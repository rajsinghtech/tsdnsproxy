// Package health serves process liveness, DNS readiness, and metrics.
package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

// Tailnet reports whether the node is up and the hostname to show.
type Tailnet func(ctx context.Context) (connected bool, hostname string)

// State is the readiness view shared by listeners and the HTTP server.
type State struct {
	listeners atomic.Int32
	failed    atomic.Bool
	shutting  atomic.Bool
	Tailnet   Tailnet
}

// AddListener records one bound DNS listener.
func (s *State) AddListener() {
	if s != nil {
		s.listeners.Add(1)
	}
}

// RemoveListener records one listener stopping.
func (s *State) RemoveListener() {
	if s != nil {
		s.listeners.Add(-1)
	}
}

// Fail marks the DNS server as failed. Liveness then returns 503.
func (s *State) Fail() {
	if s != nil {
		s.failed.Store(true)
	}
}

// ShuttingDown marks a graceful stop. Liveness and readiness then return 503.
func (s *State) ShuttingDown() {
	if s != nil {
		s.shutting.Store(true)
	}
}

// Listeners is the number of listeners that have bound and not yet stopped.
func (s *State) Listeners() int {
	if s == nil {
		return 0
	}
	n := int(s.listeners.Load())
	if n < 0 {
		return 0
	}
	return n
}

// Live reports whether the process should stay up.
// It is true during startup, before any listener has bound.
func (s *State) Live() bool {
	if s == nil {
		return true
	}
	return !s.failed.Load() && !s.shutting.Load()
}

// Ready reports whether DNS can be served and the tailnet is running.
func (s *State) Ready(ctx context.Context) bool {
	if s == nil || !s.Live() || s.Listeners() < 1 {
		return false
	}
	if s.Tailnet == nil {
		return false
	}
	ok, _ := s.Tailnet(ctx)
	return ok
}

// Server is the HTTP listener for /health, /ready, and /metrics.
type Server struct {
	state   *State
	metrics http.Handler
	http    *http.Server
}

// Start listens on addr until Shutdown or ctx is canceled.
func Start(ctx context.Context, addr string, state *State, metrics http.Handler) *Server {
	if state == nil {
		state = &State{}
	}
	s := &Server{state: state, metrics: metrics}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/ready", s.ready)
	if metrics != nil {
		mux.Handle("/metrics", metrics)
	}
	s.http = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server", "err", err.Error(), "addr", addr)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.http.Shutdown(shutdownCtx)
	}()
	return s
}

// Shutdown stops the listener.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.http == nil {
		return nil
	}
	return s.http.Shutdown(ctx)
}

type statusBody struct {
	Status    string    `json:"status"`
	Ready     bool      `json:"ready"`
	Listeners int       `json:"listeners"`
	Timestamp time.Time `json:"timestamp"`
	Tailscale struct {
		Connected bool   `json:"connected"`
		Hostname  string `json:"hostname"`
	} `json:"tailscale"`
}

func (s *Server) snapshot(ctx context.Context) statusBody {
	body := statusBody{
		Status:    "ok",
		Listeners: s.state.Listeners(),
		Timestamp: time.Now().UTC(),
	}
	if !s.state.Live() {
		body.Status = "down"
	}
	if s.state.Tailnet != nil {
		ok, host := s.state.Tailnet(ctx)
		body.Tailscale.Connected = ok
		body.Tailscale.Hostname = host
	}
	body.Ready = s.state.Ready(ctx)
	return body
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	body := s.snapshot(r.Context())
	w.Header().Set("Content-Type", "application/json")
	if body.Status != "ok" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("health encode", "err", err.Error())
	}
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if s.state.Ready(r.Context()) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("not ready\n"))
}
