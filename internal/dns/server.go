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

// Run starts both UDP and TCP DNS servers
func (s *Server) Run(ctx context.Context) error {
	s.workerPool = make(chan struct{}, 100)

	status, err := s.LocalClient.Status(ctx)
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}

	// Load server's own grants
	if err := s.loadServerGrants(ctx, status); err != nil {
		s.Logf("warning: failed to load server grants: %v", err)
		s.grantsMu.Lock()
		s.serverGrants = nil
		s.grantsMu.Unlock()
	}

	var listenAddr string
	if status.Self != nil && len(status.Self.TailscaleIPs) > 0 {
		// Use the first tailscale IP
		listenAddr = fmt.Sprintf("%s:53", status.Self.TailscaleIPs[0])
	} else {
		listenAddr = ":53"
	}

	// Create error channel for goroutines
	errCh := make(chan error, 2)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start UDP server
	go func() {
		if err := s.runUDP(ctx, listenAddr); err != nil {
			errCh <- fmt.Errorf("UDP server: %w", err)
		}
	}()

	// Start TCP server
	go func() {
		if err := s.runTCP(ctx, listenAddr); err != nil {
			errCh <- fmt.Errorf("TCP server: %w", err)
		}
	}()

	// Wait for either server to fail or context to be done
	select {
	case err := <-errCh:
		cancel()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runUDP handles UDP DNS queries
func (s *Server) runUDP(ctx context.Context, listenAddr string) error {
	pc, err := s.TSServer.ListenPacket("udp", listenAddr)
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

// runTCP handles TCP DNS queries
func (s *Server) runTCP(ctx context.Context, listenAddr string) error {
	listener, err := s.TSServer.Listen("tcp", listenAddr)
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

	s.grantsMu.RLock()
	grants := s.serverGrants
	s.grantsMu.RUnlock()
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
		return nil, fmt.Errorf("whois lookup: %w", err)
	}

	identity := s.getIdentity(whois)

	cachedGrants, cached := s.GrantCache.Get(identity)
	if cached {
		return cachedGrants, nil
	}

	// Parse grants from capabilities
	parsedGrants, err := s.GrantParser.ParseGrants(whois.CapMap)
	if err != nil {
		return nil, fmt.Errorf("parse grants: %w", err)
	}

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
		s.translate4via6(&response, uint32(grant.TranslateID))
	}

	if grant != nil && grant.Rewrite != "" && originalName.String() != "" {
		s.unrewriteResponse(&response, originalName)
	}

	// Pack final response
	return response.Pack()
}

func (s *Server) translate4via6(response *dnsmessage.Message, siteID uint32) {
	var translatedAnswers []dnsmessage.Resource

	for _, ans := range response.Answers {
		if a, ok := ans.Body.(*dnsmessage.AResource); ok && ans.Header.Type == dnsmessage.TypeA {
			// Convert A record to AAAA with 4via6
			ip4 := netip.AddrFrom4(a.A)
			via, err := tsaddr.MapVia(siteID, netip.PrefixFrom(ip4, 32))
			if err != nil {
				s.Logf("failed to map 4via6 for %v: %v", ip4, err)
				translatedAnswers = append(translatedAnswers, ans)
				continue
			}

			// Create AAAA record
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
		} else {
			// Pass through non-A records
			translatedAnswers = append(translatedAnswers, ans)
		}
	}

	response.Answers = translatedAnswers
}

func (s *Server) unrewriteResponse(response *dnsmessage.Message, originalName dnsmessage.Name) {
	if len(response.Questions) > 0 {
		response.Questions[0].Name = originalName
	}

	// We don't need to unrewrite answer names because they should remain
	// as returned by the upstream DNS server. The query was rewritten
	// (cluster1.local -> cluster.local) so the answers are for cluster.local,
	// which is what we want to return.
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
