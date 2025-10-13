package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/backend"
	"github.com/rajsinghtech/tsdnsproxy/internal/cache"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tsnet"
)

type LocalClient interface {
	WhoIs(ctx context.Context, addr string) (*apitype.WhoIsResponse, error)
	Status(ctx context.Context) (*ipnstate.Status, error)
}

type BackendManager interface {
	Query(ctx context.Context, backends []backend.Backend, query []byte) ([]byte, error)
	CreateBackends(servers []string) []backend.Backend
}

// Server implements the DNS proxy server
type Server struct {
	TSServer    *tsnet.Server
	LocalClient LocalClient
	WhoisCache  *cache.WhoisCache
	GrantCache  *cache.GrantCache
	GrantParser *grants.Parser
	BackendMgr  BackendManager
	Logf        func(format string, args ...any)

	// Worker pool for handling queries
	workerPool chan struct{}

	// Track active handlers for graceful shutdown
	handlerWg sync.WaitGroup

	// Server's own grants loaded at startup
	grantsMu     sync.RWMutex
	serverGrants []grants.GrantConfig
}

// Run starts both UDP and TCP DNS servers on the default Tailscale address
func (s *Server) Run(ctx context.Context) error {
	status, err := s.LocalClient.Status(ctx)
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}
	return s.RunWithAddrs(ctx, "tailscale", status)
}

// RunWithAddrs starts DNS servers on specified addresses
func (s *Server) RunWithAddrs(ctx context.Context, listenAddrsStr string, status *ipnstate.Status) error {
	s.workerPool = make(chan struct{}, 100)

	// Load server's own grants
	if err := s.loadServerGrants(ctx, status); err != nil {
		s.Logf("warning: failed to load server grants: %v", err)
		s.grantsMu.Lock()
		s.serverGrants = nil
		s.grantsMu.Unlock()
	}

	// Parse listen addresses
	listenAddrs := s.parseListenAddresses(listenAddrsStr, status)

	// Create error channel for goroutines (2 per address)
	errCh := make(chan error, len(listenAddrs)*2)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start UDP and TCP servers for each listen address
	for _, addr := range listenAddrs {
		// Start UDP server
		go func(listenAddr string) {
			if err := s.runUDP(ctx, listenAddr); err != nil {
				errCh <- fmt.Errorf("UDP server on %s: %w", listenAddr, err)
			}
		}(addr)

		// Start TCP server
		go func(listenAddr string) {
			if err := s.runTCP(ctx, listenAddr); err != nil {
				errCh <- fmt.Errorf("TCP server on %s: %w", listenAddr, err)
			}
		}(addr)
	}

	// Wait for any server to fail or context to be done
	select {
	case err := <-errCh:
		cancel()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// parseListenAddresses converts the listen addresses string into concrete addresses
func (s *Server) parseListenAddresses(listenAddrsStr string, status *ipnstate.Status) []string {
	addrs := strings.Split(listenAddrsStr, ",")
	var result []string
	
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		switch addr {
		case "tailscale":
			// Use the first tailscale IP
			if status.Self != nil && len(status.Self.TailscaleIPs) > 0 {
				result = append(result, fmt.Sprintf("%s:53", status.Self.TailscaleIPs[0]))
			} else {
				s.Logf("warning: tailscale address requested but no Tailscale IPs available, using :53")
				result = append(result, ":53")
			}
		case "0.0.0.0:53", "0.0.0.0", "all":
			result = append(result, "0.0.0.0:53")
		case "127.0.0.1:53", "127.0.0.1", "localhost":
			result = append(result, "127.0.0.1:53")
		case "[::]:53", "[::]", "ipv6":
			result = append(result, "[::]:53")
		default:
			// Custom address - validate it has a port
			if !strings.Contains(addr, ":") {
				addr += ":53"
			}
			result = append(result, addr)
		}
	}
	
	s.Logf("parsed listen addresses: %v", result)
	return result
}

// runUDP handles UDP DNS queries
func (s *Server) runUDP(ctx context.Context, listenAddr string) error {
	var pc net.PacketConn
	var err error
	
	// Determine if we should use tsnet or standard networking
	if s.shouldUseTSNet(listenAddr) {
		pc, err = s.TSServer.ListenPacket("udp", listenAddr)
	} else {
		pc, err = net.ListenPacket("udp", listenAddr)
	}
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	defer func() {
		if err := pc.Close(); err != nil {
			s.Logf("failed to close UDP listener: %v", err)
		}
	}()

	s.Logf("listening on %s (UDP)", listenAddr)

	buf := make([]byte, 65535)

	for {
		select {
		case <-ctx.Done():
			s.waitForHandlers("UDP")
			return ctx.Err()
		default:
		}

		// Set read deadline for cancellation
		if err := pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return fmt.Errorf("set read deadline: %w", err)
		}

		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.Logf("read packet: %v", err)
			continue
		}

		// Validate DNS message size (minimum 12 bytes for header)
		if n < 12 || n > 65535 {
			s.Logf("[v] invalid DNS message size %d from %s", n, addr)
			continue
		}

		// Handle DNS query in goroutine with rate limiting
		packet := make([]byte, n)
		copy(packet, buf[:n])

		// Try to acquire a worker slot
		select {
		case s.workerPool <- struct{}{}:
			// Got a worker slot, handle query
			s.handlerWg.Add(1)
			go func() {
				defer func() {
					<-s.workerPool // Release worker slot
					s.handlerWg.Done()
				}()
				s.handleQuery(ctx, pc, addr, packet)
			}()
		default:
			// Worker pool is full, drop the query
			s.Logf("dropping UDP query from %s: worker pool full", addr)
		}
	}
}

// shouldUseTSNet determines if we should use tsnet for the given address
func (s *Server) shouldUseTSNet(listenAddr string) bool {
	// Extract host from address
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		// If we can't parse, assume it's a tsnet address
		return true
	}
	
	// Use standard networking for common non-tailscale addresses
	switch host {
	case "0.0.0.0", "127.0.0.1", "localhost", "", "[::]":
		return false
	default:
		// If it looks like a tailscale IP or custom address, use tsnet
		return true
	}
}

// runTCP handles TCP DNS queries
func (s *Server) runTCP(ctx context.Context, listenAddr string) error {
	var listener net.Listener
	var err error
	
	// Determine if we should use tsnet or standard networking
	if s.shouldUseTSNet(listenAddr) {
		listener, err = s.TSServer.Listen("tcp", listenAddr)
	} else {
		listener, err = net.Listen("tcp", listenAddr)
	}
	if err != nil {
		return fmt.Errorf("listen TCP: %w", err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			s.Logf("failed to close TCP listener: %v", err)
		}
	}()

	s.Logf("listening on %s (TCP)", listenAddr)

	for {
		select {
		case <-ctx.Done():
			s.waitForHandlers("TCP")
			return ctx.Err()
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.Logf("accept: %v", err)
			continue
		}

		// Try to acquire a worker slot
		select {
		case s.workerPool <- struct{}{}:
			// Got a worker slot, handle connection
			s.handlerWg.Add(1)
			go func() {
				defer func() {
					<-s.workerPool // Release worker slot
					s.handlerWg.Done()
				}()
				s.handleTCPConnection(ctx, conn)
			}()
		default:
			// Worker pool is full, close the connection
			s.Logf("dropping TCP connection from %s: worker pool full", conn.RemoteAddr())
			if err := conn.Close(); err != nil {
				s.Logf("failed to close TCP connection: %v", err)
			}
		}
	}
}

// waitForHandlers waits for active handlers to complete
func (s *Server) waitForHandlers(protocol string) {
	s.Logf("waiting for active %s handlers to complete...", protocol)
	done := make(chan struct{})
	go func() {
		s.handlerWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.Logf("all %s handlers completed", protocol)
	case <-time.After(5 * time.Second):
		s.Logf("timeout waiting for %s handlers", protocol)
	}
}

func (s *Server) handleQuery(ctx context.Context, pc net.PacketConn, addr net.Addr, packet []byte) {
	// Create request-scoped context with timeout
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var msg dnsmessage.Message
	if err := msg.Unpack(packet); err != nil {
		s.Logf("[v] failed to parse DNS message from %s: %v", addr, err)
		return
	}

	// Only handle queries
	if msg.Response {
		return
	}

	if len(msg.Questions) > 0 {
		q := msg.Questions[0]
		s.Logf("[v] %s: %s %s", addr, q.Name, q.Type)
	}

	grants, err := s.getGrantsForSource(queryCtx, addr.String())
	if err != nil {
		s.Logf("failed to get grants for %s: %v", addr, err)
		s.sendError(pc, addr, &msg, dnsmessage.RCodeServerFailure)
		return
	}
	response, err := s.processQuery(queryCtx, &msg, grants)
	if err != nil {
		if queryCtx.Err() != nil {
			s.Logf("query timeout from %s: %v", addr, queryCtx.Err())
		} else {
			s.Logf("failed to process query from %s: %v", addr, err)
		}
		s.sendError(pc, addr, &msg, dnsmessage.RCodeServerFailure)
		return
	}

	// Send response
	if _, err := pc.WriteTo(response, addr); err != nil {
		s.Logf("failed to send response to %s: %v", addr, err)
	}
}

func (s *Server) getGrantsForSource(ctx context.Context, addr string) ([]grants.GrantConfig, error) {
	// Extract IP from address
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("parse address: %w", err)
	}

	// Get whois info atomically to prevent duplicate lookups
	whois, err := s.WhoisCache.GetOrSet(host, func() (*apitype.WhoIsResponse, error) {
		// Perform whois lookup with timeout
		whoisCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return s.LocalClient.WhoIs(whoisCtx, host)
	})
	if err != nil {
		// For non-Tailscale clients, fall back to server's own grants
		s.Logf("[v] whois failed for %s (%v), using server grants", host, err)
		s.grantsMu.RLock()
		serverGrants := s.serverGrants
		s.grantsMu.RUnlock()
		return serverGrants, nil
	}

	identity := s.getIdentity(whois)
	s.Logf("[v] client whois for %s: identity=%s", host, identity)
	s.Logf("[v] client capabilities: %+v", whois.CapMap)

	cachedGrants, cached := s.GrantCache.Get(identity)
	if cached {
		s.Logf("[v] using cached grants for %s: %d configs", identity, len(cachedGrants))
		return cachedGrants, nil
	}

	// Parse grants from capabilities
	parsedGrants, err := s.GrantParser.ParseGrants(whois.CapMap)
	if err != nil {
		return nil, fmt.Errorf("parse grants: %w", err)
	}
	s.Logf("[v] parsed %d grant configs for client %s", len(parsedGrants), identity)

	// Cache grants
	s.GrantCache.Set(identity, parsedGrants)

	return parsedGrants, nil
}

func (s *Server) getIdentity(whois *apitype.WhoIsResponse) string {
	// Use node name as primary identity
	if whois.Node != nil && whois.Node.Name != "" {
		return strings.TrimSuffix(whois.Node.Name, ".")
	}
	// Fall back to user login
	if whois.UserProfile != nil && whois.UserProfile.LoginName != "" {
		return whois.UserProfile.LoginName
	}
	return "unknown"
}

func (s *Server) loadServerGrants(ctx context.Context, status *ipnstate.Status) error {
	// Get the server's own IP for whois lookup
	if status.Self == nil || len(status.Self.TailscaleIPs) == 0 {
		return fmt.Errorf("no self IP found")
	}

	selfIP := status.Self.TailscaleIPs[0].String()

	// Do a whois on ourselves to get our capabilities
	whois, err := s.LocalClient.WhoIs(ctx, selfIP)
	if err != nil {
		return fmt.Errorf("whois self: %w", err)
	}

	s.Logf("[v] server self-whois for IP %s", selfIP)
	s.Logf("[v] server capabilities: %+v", whois.CapMap)

	// Parse grants from our own capabilities
	grants, err := s.GrantParser.ParseGrants(whois.CapMap)
	if err != nil {
		return fmt.Errorf("parse grants: %w", err)
	}

	s.grantsMu.Lock()
	s.serverGrants = grants
	s.grantsMu.Unlock()
	s.Logf("loaded %d grant configs from server capabilities", len(grants))
	for _, gc := range grants {
		for domain := range gc {
			s.Logf("  - grant for domain: %s", domain)
		}
	}

	return nil
}

func (s *Server) processQuery(ctx context.Context, query *dnsmessage.Message, grantConfigs []grants.GrantConfig) ([]byte, error) {
	if len(query.Questions) == 0 {
		return nil, fmt.Errorf("no questions in query")
	}

	question := query.Questions[0]
	originalName := question.Name
	queryName := grants.NormalizeDomain(question.Name.String())

	domain, grant, found := s.GrantParser.FindBestMatch(queryName, grantConfigs)
	if !found {
		return s.forwardQuery(ctx, query, nil, nil, dnsmessage.Name{})
	}

	// Handle 4via6 domains authoritatively (don't forward to backends)
	// 4via6 domains are identified by translateid field (0-65535)
	// translateid 0 is valid and results in passthrough mode (no 4via6 translation)
	// If DNS servers aren't specified, use the default system resolver
	if grant.TranslateID >= 0 {
		// If no DNS servers specified, the grant will use default backends from BackendManager
		if len(grant.DNS) == 0 {
			s.Logf("[v] 4via6 domain detected: %s (translateID=%d, using default DNS)", domain, grant.TranslateID)
		} else {
			s.Logf("[v] 4via6 domain detected: %s (translateID=%d)", domain, grant.TranslateID)
		}
		return s.handleAuthoritative4via6(query, &grant, domain)
	}

	var rewrittenQuery *dnsmessage.Message
	if grant.Rewrite != "" {
		rewrittenQuery = s.rewriteQuery(query, domain, grant.Rewrite)
	} else {
		rewrittenQuery = query
	}

	// Forward to configured backends
	backends := s.BackendMgr.CreateBackends(grant.DNS)
	response, err := s.forwardQuery(ctx, rewrittenQuery, backends, &grant, originalName)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// handleAuthoritative4via6 handles 4via6 domains authoritatively without forwarding to backends
func (s *Server) handleAuthoritative4via6(query *dnsmessage.Message, grant *grants.DNSGrant, domain string) ([]byte, error) {
	if len(query.Questions) == 0 {
		return nil, fmt.Errorf("no questions in query")
	}

	question := query.Questions[0]
	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 query.ID,
			Response:           true,
			OpCode:             query.OpCode,
			Authoritative:      true,
			Truncated:          false,
			RecursionDesired:   query.RecursionDesired,
			RecursionAvailable: false,
			RCode:              dnsmessage.RCodeSuccess,
		},
		Questions: query.Questions,
	}

	// Handle queries based on translateID:
	// - translateID == 0: No 4via6 translation, return backend A/AAAA records directly
	// - translateID > 0: 4via6 translation enabled, return 4via6 AAAA records, NODATA for A queries
	if grant.TranslateID == 0 {
		// No translation mode: serve A and AAAA records directly from backend
		switch question.Type {
		case dnsmessage.TypeA:
			// Resolve backend and return IPv4 directly
			ipv4, err := s.resolveBackendIPv4(question.Name.String(), domain, grant)
			if err != nil {
				s.Logf("failed to resolve IPv4 for %s: %v", question.Name.String(), err)
				response.RCode = dnsmessage.RCodeServerFailure
			} else {
				// Add A record to response
				response.Answers = []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  question.Name,
							Type:  dnsmessage.TypeA,
							Class: question.Class,
							TTL:   300, // Default TTL
						},
						Body: &dnsmessage.AResource{
							A: ipv4.As4(),
						},
					},
				}
				s.Logf("[v] authoritative A response for %s: %s", question.Name.String(), ipv4.String())
			}
		case dnsmessage.TypeAAAA:
			// Resolve backend and return IPv6 directly (no 4via6 translation)
			ipv6, err := s.resolveBackendIPv6(question.Name.String(), domain, grant)
			if err != nil {
				s.Logf("failed to resolve IPv6 for %s: %v", question.Name.String(), err)
				response.RCode = dnsmessage.RCodeServerFailure
			} else {
				// Add AAAA record to response
				response.Answers = []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  question.Name,
							Type:  dnsmessage.TypeAAAA,
							Class: question.Class,
							TTL:   300, // Default TTL
						},
						Body: &dnsmessage.AAAAResource{
							AAAA: ipv6.As16(),
						},
					},
				}
				s.Logf("[v] authoritative AAAA response for %s: %s", question.Name.String(), ipv6.String())
			}
		default:
			// For other query types, return NODATA (empty answer section)
		}
	} else {
		// 4via6 translation mode: serve AAAA records with 4via6 addresses
		if question.Type == dnsmessage.TypeAAAA {
			// Create synthetic 4via6 address
			via6Addr, err := s.createSynthetic4via6Address(question.Name.String(), domain, grant)
			if err != nil {
				s.Logf("failed to create synthetic 4via6 address for %s: %v", question.Name.String(), err)
				response.RCode = dnsmessage.RCodeServerFailure
			} else {
				// Add AAAA record to response
				response.Answers = []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  question.Name,
							Type:  dnsmessage.TypeAAAA,
							Class: question.Class,
							TTL:   300, // Default TTL
						},
						Body: &dnsmessage.AAAAResource{
							AAAA: via6Addr.As16(),
						},
					},
				}
				s.Logf("[v] 4via6 authoritative response for %s: %s", question.Name.String(), via6Addr.String())
			}
		}
		// For A or other query types, return NODATA (empty answer section)
	}

	return response.Pack()
}

// resolveBackendIPv4 resolves a query domain to its backend IPv4 address
func (s *Server) resolveBackendIPv4(queryDomain, grantDomain string, grant *grants.DNSGrant) (netip.Addr, error) {
	// Determine what to resolve - use rewrite if available, otherwise resolve directly via backends
	var targetDomain string
	if grant.Rewrite != "" {
		targetDomain = s.GrantParser.RewriteDomain(queryDomain, grantDomain, grant.Rewrite)
		s.Logf("[v] domain rewrite: %s -> %s", queryDomain, targetDomain)
	} else {
		targetDomain = queryDomain
		s.Logf("[v] no rewrite, using original domain: %s", targetDomain)
	}

	// Ensure target domain has trailing dot for DNS resolution
	if !strings.HasSuffix(targetDomain, ".") {
		targetDomain += "."
	}
	s.Logf("[v] resolving backend domain: %s via DNS servers: %v", targetDomain, grant.DNS)

	// Resolve the target domain to get IPv4 address
	ipv4, err := s.resolveToIPv4(targetDomain, grant.DNS)
	if err != nil {
		s.Logf("failed to resolve %s via %v: %v", targetDomain, grant.DNS, err)
		return netip.Addr{}, fmt.Errorf("failed to resolve %s: %w", targetDomain, err)
	}
	s.Logf("[v] resolved %s to IPv4: %s", targetDomain, ipv4)

	return ipv4, nil
}

// createSynthetic4via6Address creates a synthetic 4via6 IPv6 address by resolving the backend service
func (s *Server) createSynthetic4via6Address(queryDomain, grantDomain string, grant *grants.DNSGrant) (netip.Addr, error) {
	// Resolve backend IPv4 address
	ipv4, err := s.resolveBackendIPv4(queryDomain, grantDomain, grant)
	if err != nil {
		return netip.Addr{}, err
	}

	// Create 4via6 address using tsaddr.MapVia
	prefix := netip.PrefixFrom(ipv4, 32)
	via6Prefix, err := tsaddr.MapVia(uint32(grant.TranslateID), prefix)
	if err != nil {
		s.Logf("failed to map 4via6 for %s (site %d): %v", ipv4, grant.TranslateID, err)
		return netip.Addr{}, fmt.Errorf("failed to map 4via6 for %s (site %d): %w", ipv4, grant.TranslateID, err)
	}
	s.Logf("[v] created 4via6 address: %s -> %s", ipv4, via6Prefix.Addr())

	return via6Prefix.Addr(), nil
}

// resolveBackendIPv6 resolves a query domain to its backend IPv6 address
func (s *Server) resolveBackendIPv6(queryDomain, grantDomain string, grant *grants.DNSGrant) (netip.Addr, error) {
	// Determine what to resolve - use rewrite if available, otherwise resolve directly via backends
	var targetDomain string
	if grant.Rewrite != "" {
		targetDomain = s.GrantParser.RewriteDomain(queryDomain, grantDomain, grant.Rewrite)
		s.Logf("[v] domain rewrite: %s -> %s", queryDomain, targetDomain)
	} else {
		targetDomain = queryDomain
		s.Logf("[v] no rewrite, using original domain: %s", targetDomain)
	}

	// Ensure target domain has trailing dot for DNS resolution
	if !strings.HasSuffix(targetDomain, ".") {
		targetDomain += "."
	}
	s.Logf("[v] resolving backend domain: %s via DNS servers: %v", targetDomain, grant.DNS)

	// Resolve the target domain to get IPv6 address
	ipv6, err := s.resolveToIPv6(targetDomain, grant.DNS)
	if err != nil {
		s.Logf("failed to resolve %s via %v: %v", targetDomain, grant.DNS, err)
		return netip.Addr{}, fmt.Errorf("failed to resolve %s: %w", targetDomain, err)
	}
	s.Logf("[v] resolved %s to IPv6: %s", targetDomain, ipv6)

	return ipv6, nil
}

// resolveToIPv4 resolves a domain to an IPv4 address using the specified DNS servers
func (s *Server) resolveToIPv4(domain string, dnsServers []string) (netip.Addr, error) {
	s.Logf("[v] resolveToIPv4: creating A query for %s", domain)

	// Create a basic A query
	query := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               1, // Simple ID
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(domain),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	queryBytes, err := query.Pack()
	if err != nil {
		s.Logf("failed to pack A query for %s: %v", domain, err)
		return netip.Addr{}, fmt.Errorf("failed to pack query: %w", err)
	}

	// If no DNS servers specified, use nil to get default backends from BackendManager
	if len(dnsServers) == 0 {
		s.Logf("[v] packed A query for %s, using default DNS servers", domain)
	} else {
		s.Logf("[v] packed A query for %s, querying backends: %v", domain, dnsServers)
	}

	// Try each DNS server until we get a response
	backends := s.BackendMgr.CreateBackends(dnsServers)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	responseBytes, err := s.BackendMgr.Query(ctx, backends, queryBytes)
	if err != nil {
		s.Logf("backend query failed for %s: %v", domain, err)
		return netip.Addr{}, fmt.Errorf("DNS resolution failed: %w", err)
	}
	s.Logf("[v] got response for %s (%d bytes)", domain, len(responseBytes))

	// Parse response
	var response dnsmessage.Message
	if err := response.Unpack(responseBytes); err != nil {
		s.Logf("failed to unpack response for %s: %v", domain, err)
		return netip.Addr{}, fmt.Errorf("failed to unpack response: %w", err)
	}
	s.Logf("[v] unpacked response for %s: %d answers, RCode=%v", domain, len(response.Answers), response.RCode)

	// Extract IPv4 address from A records
	for i, answer := range response.Answers {
		s.Logf("[v] answer[%d]: Type=%v", i, answer.Header.Type)
		if a, ok := answer.Body.(*dnsmessage.AResource); ok {
			ipv4 := netip.AddrFrom4(a.A)
			s.Logf("[v] found A record: %s", ipv4)
			if ipv4.IsValid() {
				return ipv4, nil
			}
		}
	}

	s.Logf("no valid IPv4 address found in response for %s", domain)
	return netip.Addr{}, fmt.Errorf("no IPv4 address found in response for %s", domain)
}

// resolveToIPv6 resolves a domain to an IPv6 address using the specified DNS servers
func (s *Server) resolveToIPv6(domain string, dnsServers []string) (netip.Addr, error) {
	s.Logf("[v] resolveToIPv6: creating AAAA query for %s", domain)

	// Create a basic AAAA query
	query := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               1, // Simple ID
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(domain),
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	queryBytes, err := query.Pack()
	if err != nil {
		s.Logf("failed to pack AAAA query for %s: %v", domain, err)
		return netip.Addr{}, fmt.Errorf("failed to pack query: %w", err)
	}

	// If no DNS servers specified, use nil to get default backends from BackendManager
	if len(dnsServers) == 0 {
		s.Logf("[v] packed AAAA query for %s, using default DNS servers", domain)
	} else {
		s.Logf("[v] packed AAAA query for %s, querying backends: %v", domain, dnsServers)
	}

	// Try each DNS server until we get a response
	backends := s.BackendMgr.CreateBackends(dnsServers)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	responseBytes, err := s.BackendMgr.Query(ctx, backends, queryBytes)
	if err != nil {
		s.Logf("backend query failed for %s: %v", domain, err)
		return netip.Addr{}, fmt.Errorf("DNS resolution failed: %w", err)
	}
	s.Logf("[v] got response for %s (%d bytes)", domain, len(responseBytes))

	// Parse response
	var response dnsmessage.Message
	if err := response.Unpack(responseBytes); err != nil {
		s.Logf("failed to unpack response for %s: %v", domain, err)
		return netip.Addr{}, fmt.Errorf("failed to unpack response: %w", err)
	}
	s.Logf("[v] unpacked response for %s: %d answers, RCode=%v", domain, len(response.Answers), response.RCode)

	// Extract IPv6 address from AAAA records
	for i, answer := range response.Answers {
		s.Logf("[v] answer[%d]: Type=%v", i, answer.Header.Type)
		if aaaa, ok := answer.Body.(*dnsmessage.AAAAResource); ok {
			ipv6 := netip.AddrFrom16(aaaa.AAAA)
			s.Logf("[v] found AAAA record: %s", ipv6)
			if ipv6.IsValid() {
				return ipv6, nil
			}
		}
	}

	s.Logf("no valid IPv6 address found in response for %s", domain)
	return netip.Addr{}, fmt.Errorf("no IPv6 address found in response for %s", domain)
}

func (s *Server) rewriteQuery(query *dnsmessage.Message, targetDomain, rewriteDomain string) *dnsmessage.Message {
	rewritten := *query
	rewritten.Questions = make([]dnsmessage.Question, len(query.Questions))

	for i, q := range query.Questions {
		rewritten.Questions[i] = q
		// Apply rewrite to the question name
		rewrittenName := s.GrantParser.RewriteDomain(q.Name.String(), targetDomain, rewriteDomain)
		// DNS names must end with a dot
		if !strings.HasSuffix(rewrittenName, ".") {
			rewrittenName += "."
		}
		// Use NewName instead of MustNewName to avoid panic
		name, err := dnsmessage.NewName(rewrittenName)
		if err != nil {
			s.Logf("failed to create rewritten name %q: %v", rewrittenName, err)
			// Keep original name on error
			rewritten.Questions[i].Name = q.Name
		} else {
			rewritten.Questions[i].Name = name
		}
	}

	return &rewritten
}

func (s *Server) forwardQuery(ctx context.Context, query *dnsmessage.Message, backends []backend.Backend, grant *grants.DNSGrant, originalName dnsmessage.Name) ([]byte, error) {
	// Pack query for forwarding
	queryBytes, err := query.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack query: %w", err)
	}

	// Forward to backends
	responseBytes, err := s.BackendMgr.Query(ctx, backends, queryBytes)
	if err != nil {
		return nil, fmt.Errorf("backend query: %w", err)
	}

	var response dnsmessage.Message
	if err := response.Unpack(responseBytes); err != nil {
		return nil, fmt.Errorf("unpack response: %w", err)
	}

	if grant != nil && grant.TranslateID > 0 {
		s.translate4via6(&response, uint32(grant.TranslateID), query)
	}

	if grant != nil && grant.Rewrite != "" && originalName.String() != "" {
		s.unrewriteResponse(&response, originalName)
	}

	// Pack final response
	return response.Pack()
}

func (s *Server) translate4via6(response *dnsmessage.Message, siteID uint32, originalQuery *dnsmessage.Message) {
	// Determine what the client originally requested
	var queryTypes = make(map[dnsmessage.Type]bool)
	for _, q := range originalQuery.Questions {
		queryTypes[q.Type] = true
	}

	var translatedAnswers []dnsmessage.Resource

	for _, ans := range response.Answers {
		if a, ok := ans.Body.(*dnsmessage.AResource); ok && ans.Header.Type == dnsmessage.TypeA {
			ip4 := netip.AddrFrom4(a.A)
			via, err := tsaddr.MapVia(siteID, netip.PrefixFrom(ip4, 32))
			if err != nil {
				s.Logf("failed to map 4via6 for %v: %v", ip4, err)
				translatedAnswers = append(translatedAnswers, ans)
				continue
			}

			// Handle different query types appropriately
			if queryTypes[dnsmessage.TypeA] {
				// Client requested A records, keep original A record
				translatedAnswers = append(translatedAnswers, ans)
			}
			
			if queryTypes[dnsmessage.TypeAAAA] {
				// Client requested AAAA records, provide 4via6 translation
				aaaa := dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  ans.Header.Name,
						Type:  dnsmessage.TypeAAAA,
						Class: ans.Header.Class,
						TTL:   ans.Header.TTL,
					},
					Body: &dnsmessage.AAAAResource{
						AAAA: via.Addr().As16(),
					},
				}
				translatedAnswers = append(translatedAnswers, aaaa)
			}

			// If client requested neither A nor AAAA specifically (shouldn't happen in practice),
			// default to keeping the original A record for compatibility
			if !queryTypes[dnsmessage.TypeA] && !queryTypes[dnsmessage.TypeAAAA] {
				translatedAnswers = append(translatedAnswers, ans)
			}
		} else {
			// Pass through non-A records unchanged
			translatedAnswers = append(translatedAnswers, ans)
		}
	}

	response.Answers = translatedAnswers
}

func (s *Server) unrewriteResponse(response *dnsmessage.Message, originalName dnsmessage.Name) {
	if len(response.Questions) > 0 {
		response.Questions[0].Name = originalName
	}

	// Rewrite answer names back to the original query domain
	// This is required for DNS protocol compliance - answers must match the queried domain
	for i := range response.Answers {
		response.Answers[i].Header.Name = originalName
	}
}

func (s *Server) sendError(pc net.PacketConn, addr net.Addr, query *dnsmessage.Message, rcode dnsmessage.RCode) {
	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 query.ID,
			Response:           true,
			OpCode:             query.OpCode,
			RecursionDesired:   query.RecursionDesired,
			RecursionAvailable: true,
			RCode:              rcode,
		},
		Questions: query.Questions,
	}

	responseBytes, err := response.Pack()
	if err != nil {
		s.Logf("failed to pack error response: %v", err)
		return
	}

	if _, err := pc.WriteTo(responseBytes, addr); err != nil {
		s.Logf("failed to send error response: %v", err)
	}
}

// handleTCPConnection handles a single TCP connection
func (s *Server) handleTCPConnection(ctx context.Context, conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			s.Logf("failed to close TCP connection: %v", err)
		}
	}()

	// Set connection deadline
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		s.Logf("failed to set connection deadline for %s: %v", conn.RemoteAddr(), err)
		return
	}

	for {
		// Read DNS message length (2 bytes)
		var length uint16
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			if err != io.EOF {
				s.Logf("failed to read message length from %s: %v", conn.RemoteAddr(), err)
			}
			return
		}

		// Sanity check length
		if length == 0 {
			s.Logf("invalid message length %d from %s", length, conn.RemoteAddr())
			return
		}

		// Read DNS message
		packet := make([]byte, length)
		if _, err := io.ReadFull(conn, packet); err != nil {
			s.Logf("failed to read message from %s: %v", conn.RemoteAddr(), err)
			return
		}

		// Process the query
		tcpWriter := &tcpResponseWriter{conn: conn}
		s.handleQuery(ctx, tcpWriter, conn.RemoteAddr(), packet)

		// Reset deadline for next query
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			s.Logf("failed to reset deadline for %s: %v", conn.RemoteAddr(), err)
			return
		}
	}
}

// tcpResponseWriter wraps a TCP connection to implement the minimal net.PacketConn interface needed for DNS responses
type tcpResponseWriter struct {
	conn net.Conn
}

func (w *tcpResponseWriter) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// TCP DNS messages are prefixed with a 2-byte length field
	length := uint16(len(p))
	if err := binary.Write(w.conn, binary.BigEndian, length); err != nil {
		return 0, err
	}
	return w.conn.Write(p)
}

// The following methods are required by net.PacketConn but not used for TCP DNS responses
func (w *tcpResponseWriter) ReadFrom(p []byte) (int, net.Addr, error) { return 0, nil, nil }
func (w *tcpResponseWriter) Close() error                             { return nil }
func (w *tcpResponseWriter) LocalAddr() net.Addr                      { return nil }
func (w *tcpResponseWriter) SetDeadline(t time.Time) error            { return nil }
func (w *tcpResponseWriter) SetReadDeadline(t time.Time) error        { return nil }
func (w *tcpResponseWriter) SetWriteDeadline(t time.Time) error       { return nil }
