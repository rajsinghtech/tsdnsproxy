// Package backend provides DNS backend implementations for query forwarding
package backend

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
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
	dnsDialer       DNSDialer
	logf            func(format string, args ...any)
}

// NewManager creates a new backend manager
func NewManager(defaultServers []string, dnsDialer DNSDialer, logf func(format string, args ...any)) *Manager {
	if logf == nil {
		logf = func(format string, args ...any) {}
	}
	m := &Manager{
		unhealthy: make(map[string]*backendHealth),
		done:      make(chan struct{}),
		dnsDialer: dnsDialer,
		logf:      logf,
	}

	for _, server := range defaultServers {
		if server != "" {
			m.defaultBackends = append(m.defaultBackends, NewUDPBackend(server, dnsDialer, logf))
		}
	}

	// Start cleanup goroutine for unhealthy backends
	go m.cleanupUnhealthy()

	return m
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

		m.logf("[v] trying backend: %s (dialer=%T)", backend.String(), m.dnsDialer)
		resp, err := backend.Query(ctx, query)
		if err == nil {
			// Mark backend as healthy on success
			m.markHealthy(backend.String())
			m.logf("[v] backend %s succeeded", backend.String())
			return resp, nil
		}

		m.logf("[v] backend %s failed: %v", backend.String(), err)
		lastErr = err
		m.markUnhealthy(backend.String())
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all backends failed, last error: %w", lastErr)
	}
	return nil, fmt.Errorf("no backends available")
}

// CreateBackends creates backend instances from server addresses
func (m *Manager) CreateBackends(servers []string) []Backend {
	var backends []Backend
	for _, server := range servers {
		if server != "" {
			backends = append(backends, NewUDPBackend(server, m.dnsDialer, m.logf))
		}
	}
	return backends
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

	// Exponential backoff: 2^failureCount seconds, max 5 minutes
	health.failureCount++
	backoffSeconds := 1 << uint(health.failureCount-1)
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

// Close stops the cleanup goroutine
func (m *Manager) Close() {
	close(m.done)
}

// UDPBackend implements a DNS backend that tries TCP first, then UDP
type UDPBackend struct {
	server    string
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
		timeout:   10 * time.Second,
		dnsDialer: dnsDialer,
		logf:      logf,
	}
}

func (b *UDPBackend) Query(ctx context.Context, query []byte) ([]byte, error) {
	deadline := time.Now().Add(b.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	var dnsDialer DNSDialer = netDialer{net.Dialer{}}
	if b.dnsDialer != nil {
		dnsDialer = b.dnsDialer
	}

	// Try TCP first - it properly waits for connection establishment with tsnet/netstack
	// UDP dial returns immediately even if WireGuard tunnel isn't ready
	b.logf("[v] dialing %s with TCP (dialer=%T)", b.server, dnsDialer)
	resp, err := b.queryTCP(ctx, dnsDialer, query, deadline)
	if err == nil {
		return resp, nil
	}
	b.logf("[v] TCP query failed: %v, falling back to UDP", err)

	// Fallback to UDP
	return b.queryUDP(ctx, dnsDialer, query, deadline)
}

func (b *UDPBackend) queryTCP(ctx context.Context, d DNSDialer, query []byte, deadline time.Time) ([]byte, error) {
	conn, err := d.Dial(ctx, "tcp", b.server)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", b.server, err)
	}
	b.logf("[v] TCP dial succeeded, conn_type=%T local=%s remote=%s", conn, conn.LocalAddr(), conn.RemoteAddr())
	defer func() {
		_ = conn.Close()
	}()

	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	// DNS over TCP requires 2-byte length prefix
	tcpQuery := make([]byte, 2+len(query))
	tcpQuery[0] = byte(len(query) >> 8)
	tcpQuery[1] = byte(len(query))
	copy(tcpQuery[2:], query)

	if _, err := conn.Write(tcpQuery); err != nil {
		return nil, fmt.Errorf("write query: %w", err)
	}

	// Read length prefix
	lenBuf := make([]byte, 2)
	if _, err := readFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	// Read response
	resp := make([]byte, respLen)
	if _, err := readFull(conn, resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return resp, nil
}

func (b *UDPBackend) queryUDP(ctx context.Context, d DNSDialer, query []byte, deadline time.Time) ([]byte, error) {
	b.logf("[v] dialing %s with UDP (dialer=%T)", b.server, d)
	conn, err := d.Dial(ctx, "udp", b.server)
	if err != nil {
		return nil, fmt.Errorf("udp dial %s: %w", b.server, err)
	}
	b.logf("[v] UDP dial succeeded, conn_type=%T local=%s remote=%s", conn, conn.LocalAddr(), conn.RemoteAddr())
	defer func() {
		_ = conn.Close()
	}()

	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("write query: %w", err)
	}

	// Use larger buffer to support EDNS0 (up to 4096 bytes typical, 65KB max)
	resp := make([]byte, 65535)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return resp[:n], nil
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
	return b.server
}
