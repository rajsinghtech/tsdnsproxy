// Package backend provides DNS backend implementations for query forwarding
package backend

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

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
}

// NewManager creates a new backend manager
func NewManager(defaultServers []string) *Manager {
	m := &Manager{
		unhealthy: make(map[string]*backendHealth),
		done:      make(chan struct{}),
	}

	for _, server := range defaultServers {
		if server != "" {
			m.defaultBackends = append(m.defaultBackends, NewUDPBackend(server))
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
	}

	var lastErr error
	for _, backend := range backends {
		// Check if backend is in unhealthy state
		if m.isUnhealthy(backend.String()) {
			continue
		}

		resp, err := backend.Query(ctx, query)
		if err == nil {
			// Mark backend as healthy on success
			m.markHealthy(backend.String())
			return resp, nil
		}

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
			backends = append(backends, NewUDPBackend(server))
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

// UDPBackend implements a UDP DNS backend
type UDPBackend struct {
	server  string
	timeout time.Duration
}

// NewUDPBackend creates a new UDP DNS backend
func NewUDPBackend(server string) *UDPBackend {
	// Ensure server has port
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}

	return &UDPBackend{
		server:  server,
		timeout: 2 * time.Second,
	}
}

func (b *UDPBackend) Query(ctx context.Context, query []byte) ([]byte, error) {
	deadline := time.Now().Add(b.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	conn, err := net.Dial("udp", b.server)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", b.server, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
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

func (b *UDPBackend) String() string {
	return b.server
}
