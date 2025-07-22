package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/backend"
	"github.com/rajsinghtech/tsdnsproxy/internal/cache"
	"github.com/rajsinghtech/tsdnsproxy/internal/constants"
	"github.com/rajsinghtech/tsdnsproxy/internal/dns"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store"
	"tailscale.com/tsnet"
)

func envOr(key, defaultVal string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return defaultVal
}

func retryWithBackoff(ctx context.Context, maxRetries int, fn func() error) error {
	return retry(ctx, maxRetries, time.Second, func(i int) time.Duration {
		return time.Duration(1<<uint(i)) * time.Second
	}, fn)
}

func retryWithFixedDelay(ctx context.Context, maxRetries int, delay time.Duration, fn func() error) error {
	return retry(ctx, maxRetries, delay, nil, fn)
}

// retry executes fn with configurable backoff strategy
func retry(ctx context.Context, maxRetries int, delay time.Duration, backoffFunc func(int) time.Duration, fn func() error) error {
	var err error
	for i := 0; i < maxRetries; i++ {
		if err = fn(); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("context cancelled: %w", ctx.Err())
		}
		if i < maxRetries-1 {
			backoff := delay
			if backoffFunc != nil {
				backoff = backoffFunc(i)
			}
			log.Printf("attempt %d/%d failed, retrying in %v: %v", i+1, maxRetries, backoff, err)
			time.Sleep(backoff)
		}
	}
	return fmt.Errorf("failed after %d attempts: %w", maxRetries, err)
}

func main() {
	log.SetPrefix("tsdnsproxy: ")
	hostinfo.SetApp("tsdnsproxy")

	var (
		authKey     = flag.String("authkey", os.Getenv("TS_AUTHKEY"), "tailscale auth key")
		hostname    = flag.String("hostname", envOr("TSDNSPROXY_HOSTNAME", "tsdnsproxy"), "hostname on tailnet")
		stateDir    = flag.String("statedir", envOr("TSDNSPROXY_STATE_DIR", "/var/lib/tsdnsproxy"), "state directory")
		state       = flag.String("state", os.Getenv("TSDNSPROXY_STATE"), "state storage (e.g., kube:<secret-name>)")
		controlURL  = flag.String("controlurl", os.Getenv("TS_CONTROLURL"), "optional alternate control server URL")
		defaultDNS  = flag.String("default-dns", envOr("TSDNSPROXY_DEFAULT_DNS", ""), "default DNS servers (comma-separated)")
		cacheExpiry = flag.Duration("cache-expiry", constants.DefaultCacheExpiry, "whois cache expiry duration")
		healthAddr  = flag.String("health-addr", envOr("TSDNSPROXY_HEALTH_ADDR", ":8080"), "health check endpoint address")
		verbose     = flag.Bool("verbose", envOr("TSDNSPROXY_VERBOSE", "false") == "true", "enable verbose logging")
	)
	flag.Parse()

	if *authKey == "" {
		log.Fatal("authkey is required (set TS_AUTHKEY or use -authkey)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down...")
		cancel()
	}()

	s := &tsnet.Server{
		Dir:      *stateDir,
		Hostname: *hostname,
		AuthKey:  *authKey,
		Logf:     logf(*verbose),
	}

	if *controlURL != "" {
		s.ControlURL = *controlURL
	}

	if *state != "" {
		stateStore, err := store.New(log.Printf, *state)
		if err != nil {
			log.Fatalf("failed to create state store: %v", err)
		}
		s.Store = stateStore
		log.Printf("using state store: %s", *state)
	}

	defer func() {
		if err := s.Close(); err != nil {
			log.Printf("tsnet server close error: %v", err)
		}
	}()

	log.Printf("starting tsnet server as %q", *hostname)

	if err := retryWithBackoff(ctx, constants.StartupMaxRetries, func() error {
		return s.Start()
	}); err != nil {
		log.Fatalf("failed to start tsnet: %v", err)
	}

	// Get LocalClient, but don't fail if it's not immediately available
	lc, err := s.LocalClient()
	if err != nil {
		log.Printf("warning: LocalClient not available: %v", err)
		// LocalClient might become available later, but we'll continue
	}

	whoisCache := cache.NewWhoisCache(*cacheExpiry)
	grantCache := cache.NewGrantCache(*cacheExpiry)

	var defaultServers []string
	if *defaultDNS != "" {
		defaultServers = strings.Split(*defaultDNS, ",")
		for i := range defaultServers {
			defaultServers[i] = strings.TrimSpace(defaultServers[i])
		}
	}
	backendMgr := backend.NewManager(defaultServers)
	defer backendMgr.Close()

	grantParser := grants.NewParser()

	log.Printf("waiting for tailnet...")

	var status *ipnstate.Status
	err = retryWithFixedDelay(ctx, constants.TailnetMaxRetries, constants.TailnetRetryDelay, func() error {
		upCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		var upErr error
		status, upErr = s.Up(upCtx)
		if upErr != nil {
			return upErr
		}
		if status == nil {
			return fmt.Errorf("status is nil")
		}
		return nil
	})
	if err != nil {
		log.Fatalf("tailnet failed to come up: %v", err)
	}

	// Try to get LocalClient again if we didn't have it before
	if lc == nil {
		lc, err = s.LocalClient()
		if err != nil {
			log.Fatalf("LocalClient still not available after Up: %v", err)
		}
	}

	dnsServer := &dns.Server{
		TSServer:    s,
		LocalClient: lc,
		WhoisCache:  whoisCache,
		GrantCache:  grantCache,
		GrantParser: grantParser,
		BackendMgr:  backendMgr,
		Logf:        logf(*verbose),
	}

	healthServer := startHealthServer(ctx, *healthAddr, s)

	// Start DNS server (handles both UDP and TCP)
	log.Printf("starting DNS server")
	if err := dnsServer.Run(ctx); err != nil {
		log.Printf("DNS server error: %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), constants.HealthShutdownTimeout)
	defer cancel2()
	if err := healthServer.Shutdown(ctx2); err != nil {
		log.Printf("health shutdown: %v", err)
	}

}

func logf(verbose bool) func(format string, args ...any) {
	return func(format string, args ...any) {
		if verbose || !strings.Contains(format, "[v]") {
			log.Printf(format, args...)
		}
	}
}

type healthServer struct {
	ts     *tsnet.Server
	server *http.Server
}

func startHealthServer(ctx context.Context, addr string, ts *tsnet.Server) *healthServer {
	h := &healthServer{ts: ts}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.handleHealth)
	mux.HandleFunc("/ready", h.handleReady)

	h.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		if err := h.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("health server error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		if err := h.server.Close(); err != nil {
			log.Printf("health server close error: %v", err)
		}
	}()

	return h
}

func (h *healthServer) Shutdown(ctx context.Context) error {
	if h.server != nil {
		return h.server.Shutdown(ctx)
	}
	return nil
}

func (h *healthServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := struct {
		Status    string    `json:"status"`
		Timestamp time.Time `json:"timestamp"`
		Tailscale struct {
			Connected bool   `json:"connected"`
			Hostname  string `json:"hostname"`
		} `json:"tailscale"`
	}{
		Status:    "ok",
		Timestamp: time.Now().UTC(),
	}

	if h.ts != nil {
		lc, err := h.ts.LocalClient()
		if err == nil {
			st, err := lc.Status(r.Context())
			if err == nil && st.BackendState == "Running" {
				status.Tailscale.Connected = true
				status.Tailscale.Hostname = h.ts.Hostname
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		log.Printf("health status encoding error: %v", err)
	}
}

func (h *healthServer) handleReady(w http.ResponseWriter, r *http.Request) {
	ready := true

	if h.ts != nil {
		lc, err := h.ts.LocalClient()
		if err != nil {
			ready = false
		} else {
			st, err := lc.Status(r.Context())
			if err != nil || st.BackendState != "Running" {
				ready = false
			}
		}
	}

	if ready {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ready\n")); err != nil {
			log.Printf("write error: %v", err)
		}
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		if _, err := w.Write([]byte("not ready\n")); err != nil {
			log.Printf("write error: %v", err)
		}
	}
}
