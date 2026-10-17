// Package backend provides DNS backend implementations for query forwarding
package backend

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type DNSDialer interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

type netDialer struct {
	net.Dialer
}

func (d netDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return d.DialContext(ctx, network, address)
}

// Backend represents a DNS backend that can handle queries
type Backend interface {
	// Query sends a DNS query and returns the response
	Query(ctx context.Context, query []byte) ([]byte, error)

	// String returns a human-readable representation
	String() string
}

// backendHealth tracks backend health with exponential backoff
type backendHealth struct {
	unhealthyUntil time.Time
	failureCount   int
}

// Manager manages multiple DNS backends with failover
type Manager struct {
	defaultBackends []Backend
	mu              sync.RWMutex
	unhealthy       map[string]*backendHealth
	done            chan struct{}
	closeOnce       sync.Once
	direct          DNSDialer
	tailnet         DNSDialer
	tailnetRoutes   DNSDialer
	defaultMode     DialMode
	logf            func(format string, args ...any)
	recorder        Recorder
}

// Recorder receives upstream failure counts. It may be nil.
type Recorder interface {
	UpstreamError(upstream string)
}

// NewManager creates a new backend manager.
// A bare address in defaultServers uses dialers.Default. An invalid address is an error.
func NewManager(defaultServers []string, dialers Dialers, logf func(format string, args ...any)) (*Manager, error) {
	if logf == nil {
		logf = func(format string, args ...any) {}
	}
	if dialers.Default == "" {
		dialers.Default = DialDirect
	}
	m := &Manager{
		unhealthy:     make(map[string]*backendHealth),
		done:          make(chan struct{}),
		direct:        dialers.Direct,
		tailnet:       dialers.Tailnet,
		tailnetRoutes: dialers.TailnetRoutes,
		defaultMode:   dialers.Default,
		logf:          logf,
	}
	for _, server := range defaultServers {
		if strings.TrimSpace(server) == "" {
			continue
		}
		backend, err := m.newBackend(server)
		if err != nil {
			return nil, err
		}
		m.defaultBackends = append(m.defaultBackends, backend)
	}

	// Start cleanup goroutine for unhealthy backends
	go m.cleanupUnhealthy()

	return m, nil
}

// Query attempts to query backends in order until one succeeds
func (m *Manager) Query(ctx context.Context, backends []Backend, query []byte) ([]byte, error) {
	if len(backends) == 0 {
		backends = m.defaultBackends
		m.logf("[v] using default backends: %d available", len(backends))
	}

	var lastErr error
	for _, backend := range backends {
		// Check if backend is in unhealthy state
		if m.isUnhealthy(backend.String()) {
			m.logf("[v] skipping unhealthy backend: %s", backend.String())
			continue
		}

		m.logf("[v] trying backend: %s", backend.String())
		resp, err := backend.Query(ctx, query)
		if err == nil {
			// Mark backend as healthy on success
			m.markHealthy(backend.String())
			m.logf("[v] backend %s succeeded", backend.String())
			return resp, nil
		}

		m.logf("[v] backend %s failed: %v", backend.String(), err)
		lastErr = err
		if m.recorder != nil {
			m.recorder.UpstreamError(backend.String())
		}
		m.markUnhealthy(backend.String())
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all backends failed, last error: %w", lastErr)
	}
	return nil, fmt.Errorf("no backends available")
}

// CreateBackends creates backend instances from server addresses.
// An empty entry is skipped. A bad address returns an error.
func (m *Manager) CreateBackends(servers []string) ([]Backend, error) {
	var backends []Backend
	for _, server := range servers {
		if strings.TrimSpace(server) == "" {
			continue
		}
		backend, err := m.newBackend(server)
		if err != nil {
			return nil, err
		}
		backends = append(backends, backend)
	}
	return backends, nil
}

func (m *Manager) newBackend(raw string) (Backend, error) {
	ep, err := ParseEndpoint(raw, m.defaultMode)
	if err != nil {
		return nil, err
	}
	var dialer DNSDialer
	if ep.Mode == DialTailnet {
		dialer = m.tailnet
		// Only an explicit tailnet:// address accepts subnet routes.
		// A bare address keeps the default tailnet dial without that.
		if ep.Explicit && m.tailnetRoutes != nil {
			dialer = m.tailnetRoutes
		}
		if dialer == nil {
			return nil, fmt.Errorf("tailnet dialer is not configured")
		}
	} else {
		dialer = m.direct
	}
	backend := NewUDPBackend(ep.Addr, dialer, m.logf)
	if ep.Explicit && ep.Mode == DialTailnet {
		backend.label = "tailnet://" + ep.Addr
	}
	return backend, nil
}

func (m *Manager) isUnhealthy(backend string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	health, exists := m.unhealthy[backend]
	if !exists {
		return false
	}

	now := time.Now()
	return now.Before(health.unhealthyUntil)
}

func (m *Manager) markUnhealthy(backend string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	health, exists := m.unhealthy[backend]
	if !exists {
		health = &backendHealth{}
		m.unhealthy[backend] = health
	}

	// Exponential backoff: 2^(n-1) seconds, capped at 5 minutes.
	// The shift is capped so a long outage cannot overflow the shift.
	health.failureCount++
	shift := health.failureCount - 1
	if shift > 9 {
		shift = 9
	}
	backoffSeconds := 1 << shift
	if backoffSeconds > 300 {
		backoffSeconds = 300
	}

	health.unhealthyUntil = time.Now().Add(time.Duration(backoffSeconds) * time.Second)
}

// markHealthy resets the failure count for a backend
func (m *Manager) markHealthy(backend string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.unhealthy, backend)
}

// cleanupUnhealthy periodically removes expired unhealthy entries
func (m *Manager) cleanupUnhealthy() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now()
			for backend, health := range m.unhealthy {
				if now.After(health.unhealthyUntil) {
					// Reset failure count after successful recovery period
					delete(m.unhealthy, backend)
				}
			}
			m.mu.Unlock()
		case <-m.done:
			return
		}
	}
}

// SetRecorder installs an optional upstream error recorder.
func (m *Manager) SetRecorder(r Recorder) {
	if m != nil {
		m.recorder = r
	}
}

// Close stops the cleanup goroutine. It is safe to call more than once.
func (m *Manager) Close() {
	m.closeOnce.Do(func() { close(m.done) })
}

// upstreamUDPSize is the EDNS buffer advertised to an upstream server.
const upstreamUDPSize = 1232

// UDPBackend queries one DNS server over UDP and falls back to TCP.
type UDPBackend struct {
	server    string
	label     string
	timeout   time.Duration
	dnsDialer DNSDialer
	logf      func(format string, args ...any)
}

// NewUDPBackend creates a new DNS backend
func NewUDPBackend(server string, dnsDialer DNSDialer, logf func(format string, args ...any)) *UDPBackend {
	// Ensure server has port
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}

	if logf == nil {
		logf = func(format string, args ...any) {}
	}

	return &UDPBackend{
		server:    server,
		label:     server,
		timeout:   10 * time.Second,
		dnsDialer: dnsDialer,
		logf:      logf,
	}
}

func (b *UDPBackend) Query(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, fmt.Errorf("query is %d bytes", len(query))
	}
	timeout := b.timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := b.dialer()
	udpBudget := timeout / 3
	if udpBudget < 250*time.Millisecond {
		udpBudget = 250 * time.Millisecond
	}
	if remain, ok := ctx.Deadline(); ok {
		if left := time.Until(remain); left < udpBudget {
			udpBudget = left
		}
	}
	if udpBudget < 0 {
		udpBudget = 0
	}

	udpQuery := withUpstreamEDNS(query, upstreamUDPSize)
	udpCtx, udpCancel := context.WithTimeout(ctx, udpBudget)
	resp, err := b.queryUDP(udpCtx, d, udpQuery)
	udpCancel()
	if err == nil && !udpTruncated(resp) {
		return resp, nil
	}
	if err != nil {
		b.logf("[v] UDP query %s failed: %v, trying TCP", b.server, err)
	} else {
		b.logf("[v] UDP response from %s is truncated, trying TCP", b.server)
	}
	tcpResp, tcpErr := b.queryTCP(ctx, d, query)
	if tcpErr != nil {
		if err == nil && udpTruncated(resp) {
			return resp, nil
		}
		if err != nil {
			return nil, fmt.Errorf("udp: %w", err)
		}
		return nil, tcpErr
	}
	return tcpResp, nil
}

func (b *UDPBackend) dialer() DNSDialer {
	if b.dnsDialer != nil {
		return b.dnsDialer
	}
	return netDialer{}
}

func (b *UDPBackend) queryTCP(ctx context.Context, d DNSDialer, query []byte) ([]byte, error) {
	if len(query) > 65535 {
		return nil, fmt.Errorf("tcp query is %d bytes", len(query))
	}
	conn, err := dialContext(ctx, d, "tcp", b.server)
	if err != nil {
		return nil, err
	}
	b.logf("[v] TCP dial succeeded, conn_type=%T local=%s remote=%s", conn, conn.LocalAddr(), conn.RemoteAddr())
	defer func() {
		_ = conn.Close()
	}()
	if err := applyDeadline(ctx, conn); err != nil {
		return nil, err
	}

	tcpQuery := make([]byte, 2+len(query))
	// len(query) is capped at 65535 above, so it fits in two bytes.
	tcpQuery[0] = byte(uint16(len(query)) >> 8) //nolint:gosec // bounded above
	tcpQuery[1] = byte(uint16(len(query)))      //nolint:gosec // bounded above
	copy(tcpQuery[2:], query)
	if _, err := conn.Write(tcpQuery); err != nil {
		return nil, fmt.Errorf("write query: %w", err)
	}

	lenBuf := make([]byte, 2)
	if _, err := readFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if respLen < 12 || respLen > 65535 {
		return nil, fmt.Errorf("tcp response length %d", respLen)
	}
	resp := make([]byte, respLen)
	if _, err := readFull(conn, resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if !validDNSResponse(query, resp) {
		return nil, fmt.Errorf("tcp response from %s does not match the query", b.server)
	}
	return resp, nil
}

func (b *UDPBackend) queryUDP(ctx context.Context, d DNSDialer, query []byte) ([]byte, error) {
	b.logf("[v] dialing %s with UDP (dialer=%T)", b.server, d)
	conn, err := dialContext(ctx, d, "udp", b.server)
	if err != nil {
		return nil, err
	}
	b.logf("[v] UDP dial succeeded, conn_type=%T local=%s remote=%s", conn, conn.LocalAddr(), conn.RemoteAddr())
	defer func() {
		_ = conn.Close()
	}()
	if err := applyDeadline(ctx, conn); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("write query: %w", err)
	}
	bufp := udpBufPool.Get().(*[]byte)
	buf := *bufp
	defer udpBufPool.Put(bufp)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if n < 12 {
		return nil, fmt.Errorf("udp response is %d bytes", n)
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	if !validDNSResponse(query, out) {
		return nil, fmt.Errorf("udp response from %s does not match the query", b.server)
	}
	return out, nil
}

var udpBufPool = sync.Pool{New: func() any {
	buf := make([]byte, 65535)
	return &buf
}}

// dialContext dials with ctx. A dialer that ignores cancellation is abandoned
// when ctx ends, and the connection is closed if it appears later.
func dialContext(ctx context.Context, d DNSDialer, network, address string) (net.Conn, error) {
	if d == nil {
		d = netDialer{}
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dial %s %s: %w", network, address, err)
	}
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := d.Dial(ctx, network, address)
		ch <- result{conn, err}
	}()
	select {
	case <-ctx.Done():
		go func() {
			res := <-ch
			if res.conn != nil {
				_ = res.conn.Close()
			}
		}()
		return nil, fmt.Errorf("dial %s %s: %w", network, address, ctx.Err())
	case res := <-ch:
		if res.err != nil {
			return nil, fmt.Errorf("dial %s %s: %w", network, address, res.err)
		}
		if res.conn == nil {
			return nil, fmt.Errorf("dial %s %s: nil connection", network, address)
		}
		return res.conn, nil
	}
}

func applyDeadline(ctx context.Context, conn net.Conn) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	return nil
}

func udpTruncated(raw []byte) bool {
	return len(raw) >= 12 && raw[2]&0x02 != 0
}

func validDNSResponse(query, resp []byte) bool {
	if len(query) < 12 || len(resp) < 12 {
		return false
	}
	if query[0] != resp[0] || query[1] != resp[1] {
		return false
	}
	// QR must be set on a response.
	return resp[2]&0x80 != 0
}

// withUpstreamEDNS returns query with an OPT record advertising udpSize.
// The original bytes are returned when the message cannot be rebuilt.
func withUpstreamEDNS(query []byte, udpSize int) []byte {
	if udpSize < 512 {
		udpSize = 512
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(query); err != nil {
		return query
	}
	updated := false
	for i, extra := range msg.Additionals {
		if extra.Header.Type != dnsmessage.TypeOPT {
			continue
		}
		if int(extra.Header.Class) < udpSize {
			msg.Additionals[i].Header.Class = dnsmessage.Class(udpSize)
		}
		updated = true
	}
	if !updated {
		msg.Additionals = append(msg.Additionals, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.TypeOPT,
				Class: dnsmessage.Class(udpSize),
			},
			Body: &dnsmessage.OPTResource{},
		})
	}
	packed, err := msg.Pack()
	if err != nil {
		return query
	}
	return packed
}

// readFull reads exactly len(buf) bytes from conn
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func (b *UDPBackend) String() string {
	if b.label != "" {
		return b.label
	}
	return b.server
}
