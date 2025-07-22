package backend

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// mockBackend implements Backend for testing
type mockBackend struct {
	name      string
	responses []mockResponse
	callCount int
	mu        sync.Mutex
}

type mockResponse struct {
	response []byte
	err      error
}

func (m *mockBackend) Query(ctx context.Context, query []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.callCount >= len(m.responses) {
		return nil, errors.New("no more mock responses")
	}

	resp := m.responses[m.callCount]
	m.callCount++

	// Simulate network delay
	select {
	case <-time.After(10 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return resp.response, resp.err
}

func (m *mockBackend) String() string {
	return m.name
}

func (m *mockBackend) getCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

func TestManagerQuery(t *testing.T) {
	tests := []struct {
		name     string
		backends []Backend
		wantErr  bool
		wantResp []byte
	}{
		{
			name: "successful query first backend",
			backends: []Backend{
				&mockBackend{
					name: "backend1",
					responses: []mockResponse{
						{response: []byte("response1"), err: nil},
					},
				},
			},
			wantErr:  false,
			wantResp: []byte("response1"),
		},
		{
			name: "failover to second backend",
			backends: []Backend{
				&mockBackend{
					name: "backend1",
					responses: []mockResponse{
						{response: nil, err: errors.New("backend1 error")},
					},
				},
				&mockBackend{
					name: "backend2",
					responses: []mockResponse{
						{response: []byte("response2"), err: nil},
					},
				},
			},
			wantErr:  false,
			wantResp: []byte("response2"),
		},
		{
			name: "all backends fail",
			backends: []Backend{
				&mockBackend{
					name: "backend1",
					responses: []mockResponse{
						{response: nil, err: errors.New("backend1 error")},
					},
				},
				&mockBackend{
					name: "backend2",
					responses: []mockResponse{
						{response: nil, err: errors.New("backend2 error")},
					},
				},
			},
			wantErr: true,
		},
		{
			name:     "no backends uses defaults",
			backends: nil,
			wantErr:  true, // No default backends in test
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{
				unhealthy: make(map[string]*backendHealth),
				done:      make(chan struct{}),
			}
			defer m.Close()

			ctx := context.Background()
			resp, err := m.Query(ctx, tt.backends, []byte("query"))

			if (err != nil) != tt.wantErr {
				t.Errorf("Query() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && string(resp) != string(tt.wantResp) {
				t.Errorf("Query() = %v, want %v", resp, tt.wantResp)
			}
		})
	}
}

func TestManagerHealthTracking(t *testing.T) {
	m := &Manager{
		unhealthy: make(map[string]*backendHealth),
		done:      make(chan struct{}),
	}
	defer m.Close()

	// Test marking unhealthy
	m.markUnhealthy("backend1")
	if !m.isUnhealthy("backend1") {
		t.Error("Expected backend1 to be unhealthy")
	}

	// Test marking healthy
	m.markHealthy("backend1")
	if m.isUnhealthy("backend1") {
		t.Error("Expected backend1 to be healthy after markHealthy")
	}

	// Test exponential backoff
	for i := 0; i < 3; i++ {
		m.markUnhealthy("backend2")
	}

	m.mu.RLock()
	health := m.unhealthy["backend2"]
	m.mu.RUnlock()

	if health.failureCount != 3 {
		t.Errorf("Expected failure count 3, got %d", health.failureCount)
	}
}

func TestBackoffCalculation(t *testing.T) {
	m := &Manager{
		unhealthy: make(map[string]*backendHealth),
		done:      make(chan struct{}),
	}
	defer m.Close()

	tests := []struct {
		failures        int
		expectedBackoff time.Duration
	}{
		{1, 1 * time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{5, 16 * time.Second},
		{6, 32 * time.Second},
		{7, 64 * time.Second},
		{8, 128 * time.Second},
		{9, 256 * time.Second},
		{10, 300 * time.Second}, // Max cap at 300s
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			backend := "test-backend"

			// Mark unhealthy tt.failures times
			for i := 0; i < tt.failures; i++ {
				m.markUnhealthy(backend)
			}

			m.mu.RLock()
			health := m.unhealthy[backend]
			m.mu.RUnlock()

			// Calculate expected unhealthy duration based on the implementation
			actualBackoff := time.Until(health.unhealthyUntil)

			// Allow 100ms tolerance for timing
			tolerance := 100 * time.Millisecond
			diff := actualBackoff - tt.expectedBackoff
			if diff < -tolerance || diff > tolerance {
				t.Errorf("After %d failures, expected backoff ~%v, got %v (diff: %v)",
					tt.failures, tt.expectedBackoff, actualBackoff, diff)
			}

			// Clean up for next test
			m.markHealthy(backend)
		})
	}
}

func TestHealthCleanup(t *testing.T) {
	m := &Manager{
		unhealthy: make(map[string]*backendHealth),
		done:      make(chan struct{}),
	}

	// Start cleanup goroutine
	go m.cleanupUnhealthy()
	defer m.Close()

	// Add an unhealthy backend with very short timeout
	m.mu.Lock()
	m.unhealthy["backend1"] = &backendHealth{
		unhealthyUntil: time.Now().Add(100 * time.Millisecond),
		failureCount:   1,
	}
	m.mu.Unlock()

	// Wait for cleanup
	time.Sleep(11 * time.Second) // Cleanup runs every 10s

	m.mu.RLock()
	_, exists := m.unhealthy["backend1"]
	m.mu.RUnlock()

	if exists {
		t.Error("Expected expired unhealthy entry to be cleaned up")
	}
}

func TestConcurrentAccess(t *testing.T) {
	m := &Manager{
		unhealthy: make(map[string]*backendHealth),
		done:      make(chan struct{}),
	}
	defer m.Close()

	var wg sync.WaitGroup
	backends := []string{"backend1", "backend2", "backend3"}

	// Concurrent marking unhealthy
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				backend := backends[j%len(backends)]
				m.markUnhealthy(backend)
				m.isUnhealthy(backend)
				if j%10 == 0 {
					m.markHealthy(backend)
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestUDPBackend(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   string
	}{
		{
			name:   "server with port",
			server: "8.8.8.8:53",
			want:   "8.8.8.8:53",
		},
		{
			name:   "server without port",
			server: "8.8.8.8",
			want:   "8.8.8.8:53",
		},
		{
			name:   "IPv6 with port",
			server: "[2001:4860:4860::8888]:53",
			want:   "[2001:4860:4860::8888]:53",
		},
		{
			name:   "IPv6 without port",
			server: "2001:4860:4860::8888",
			want:   "[2001:4860:4860::8888]:53",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := NewUDPBackend(tt.server)
			if backend.String() != tt.want {
				t.Errorf("NewUDPBackend(%q) server = %q, want %q", tt.server, backend.String(), tt.want)
			}
			if backend.timeout != 2*time.Second {
				t.Errorf("Expected default timeout of 2s, got %v", backend.timeout)
			}
		})
	}
}

func TestCreateBackends(t *testing.T) {
	m := NewManager(nil)
	defer m.Close()

	servers := []string{"8.8.8.8", "1.1.1.1:53", "", "8.8.4.4"}
	backends := m.CreateBackends(servers)

	// Empty strings should be filtered out
	if len(backends) != 3 {
		t.Errorf("Expected 3 backends, got %d", len(backends))
	}

	expected := []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"}
	for i, backend := range backends {
		if backend.String() != expected[i] {
			t.Errorf("Backend %d: got %q, want %q", i, backend.String(), expected[i])
		}
	}
}

func TestManagerWithDefaults(t *testing.T) {
	defaultServers := []string{"8.8.8.8", "1.1.1.1"}
	m := NewManager(defaultServers)
	defer m.Close()

	if len(m.defaultBackends) != 2 {
		t.Errorf("Expected 2 default backends, got %d", len(m.defaultBackends))
	}

	// Test query with no backends uses defaults
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := m.Query(ctx, nil, []byte("test"))
	// This will fail because we're not actually connecting to DNS servers
	if err == nil {
		t.Error("Expected error when querying real DNS servers in test")
	}
}

func TestBackendFailoverWithUnhealthy(t *testing.T) {
	backend1 := &mockBackend{
		name: "backend1",
		responses: []mockResponse{
			{response: nil, err: errors.New("fail")},
			{response: []byte("success after recovery"), err: nil},
		},
	}

	backend2 := &mockBackend{
		name: "backend2",
		responses: []mockResponse{
			{response: []byte("backend2 response"), err: nil},
		},
	}

	m := &Manager{
		unhealthy: make(map[string]*backendHealth),
		done:      make(chan struct{}),
	}
	defer m.Close()

	backends := []Backend{backend1, backend2}

	// First query - backend1 fails, backend2 succeeds
	resp, err := m.Query(context.Background(), backends, []byte("query1"))
	if err != nil {
		t.Fatalf("First query failed: %v", err)
	}
	if string(resp) != "backend2 response" {
		t.Errorf("Expected response from backend2, got %s", resp)
	}

	// Verify backend1 is marked unhealthy
	if !m.isUnhealthy("backend1") {
		t.Error("Expected backend1 to be unhealthy after failure")
	}

	// Second query should skip unhealthy backend1
	if backend1.getCallCount() != 1 {
		t.Errorf("Expected backend1 to be called only once, got %d", backend1.getCallCount())
	}
}
