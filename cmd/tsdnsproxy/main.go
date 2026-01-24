package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
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
	"tailscale.com/client/local"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
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

func getHostDNSServers() []string {
	var servers []string

	// Try to read from /etc/resolv.conf (Linux/Unix)
	if file, err := os.Open("/etc/resolv.conf"); err == nil {
		defer func() {
			if err := file.Close(); err != nil {
				log.Printf("failed to close /etc/resolv.conf: %v", err)
			}
		}()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "nameserver ") {
				server := strings.TrimSpace(strings.TrimPrefix(line, "nameserver"))
				// Add port if not specified
				if !strings.Contains(server, ":") {
					server += ":53"
				}
				servers = append(servers, server)
			}
		}
		if len(servers) > 0 {
			return servers
		}
	}

	// Fallback to system DNS resolution
	config, err := net.DefaultResolver.LookupNS(context.Background(), ".")
	if err == nil && len(config) > 0 {
		for _, ns := range config {
			if !strings.Contains(ns.Host, ":") {
				servers = append(servers, ns.Host+":53")
			} else {
				servers = append(servers, ns.Host)
			}
		}
		if len(servers) > 0 {
			return servers
		}
	}

	// Final fallback to common public DNS
	log.Println("warning: could not determine host DNS servers, falling back to 8.8.8.8:53")
	return []string{"8.8.8.8:53"}
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
		authKey       = flag.String("authkey", os.Getenv("TS_AUTHKEY"), "tailscale auth key")
		hostname      = flag.String("hostname", envOr("TSDNSPROXY_HOSTNAME", "tsdnsproxy"), "hostname on tailnet")
		stateDir      = flag.String("statedir", envOr("TSDNSPROXY_STATE_DIR", "/var/lib/tsdnsproxy"), "state directory")
		state         = flag.String("state", os.Getenv("TSDNSPROXY_STATE"), "state storage (e.g., kube:<secret-name>)")
		controlURL    = flag.String("controlurl", os.Getenv("TS_CONTROLURL"), "optional alternate control server URL")
		advertiseTags = flag.String("advertise-tags", os.Getenv("TSDNSPROXY_ADVERTISE_TAGS"), "ACL tags to advertise (comma-separated, default: none)")
		overrideDNS   = flag.String("override-dns", envOr("TSDNSPROXY_OVERRIDE_DNS", ""), "override DNS servers (comma-separated, defaults to host resolvers)")
		cacheExpiry   = flag.Duration("cache-expiry", constants.DefaultCacheExpiry, "whois cache expiry duration")
		healthAddr    = flag.String("health-addr", envOr("TSDNSPROXY_HEALTH_ADDR", ":8080"), "health check endpoint address")
		listenAddrs   = flag.String("listen-addrs", envOr("TSDNSPROXY_LISTEN_ADDRS", "tailscale"), "listen addresses (comma-separated: tailscale,0.0.0.0:53,127.0.0.1:5353)")
		acceptRoutes = flag.Bool("accept-routes", envOr("TSDNSPROXY_ACCEPT_ROUTES", "false") == "true", "accept subnet routes and use TS dialer")
		verbose      = flag.Bool("verbose", envOr("TSDNSPROXY_VERBOSE", "false") == "true", "enable verbose logging")
	)
	flag.Parse()

	// Log configuration for debugging
	log.Printf("configuration: accept-routes=%v (env=%q), verbose=%v, listen-addrs=%q",
		*acceptRoutes, os.Getenv("TSDNSPROXY_ACCEPT_ROUTES"),
		*verbose, *listenAddrs)

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

	if *advertiseTags != "" {
		s.AdvertiseTags = strings.Split(*advertiseTags, ",")
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

	// Enable RouteAll BEFORE calling Up() so subnet routes are accepted
	// in the initial WireGuard configuration
	if *acceptRoutes && lc != nil {
		log.Print("enabling accept-routes before tailnet up...")
		if err := enableAcceptRoutes(ctx, lc); err != nil {
			log.Printf("warning: failed to enable routes early: %v", err)
			// Continue anyway, we'll try again after Up()
		}
	}

	whoisCache := cache.NewWhoisCache(*cacheExpiry)
	grantCache := cache.NewGrantCache(*cacheExpiry)

	var defaultServers []string
	if *overrideDNS != "" {
		// Use override DNS servers if specified
		defaultServers = strings.Split(*overrideDNS, ",")
		for i := range defaultServers {
			defaultServers[i] = strings.TrimSpace(defaultServers[i])
		}
		log.Printf("using override DNS servers: %v", defaultServers)
	} else {
		// Default to host's DNS resolvers
		defaultServers = getHostDNSServers()
		log.Printf("using host DNS servers: %v", defaultServers)
	}

	// Always use tsnet dialer for DNS backends - they may be Tailscale machines
	// that require MagicDNS resolution. The accept-routes flag only controls
	// whether we can reach subnet IPs, not Tailscale machine IPs.
	log.Printf("using ts dialer to query DNS over tailnet")
	var dnsDialer backend.DNSDialer = s

	backendMgr := backend.NewManager(defaultServers, dnsDialer, logf(*verbose))
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

	if *acceptRoutes {
		log.Print("accepting subnet routes...")

		if err := enableAcceptRoutes(ctx, lc); err != nil {
			log.Fatalf("failed to enable accepting routes: %v", err)
		}

	}

	// Log peer status to help diagnose subnet route issues
	if *verbose {
		peerStatus, err := lc.Status(ctx)
		if err != nil {
			log.Printf("[DEBUG] failed to get peer status: %v", err)
		} else {
			log.Printf("[DEBUG] self: %s (%v)", peerStatus.Self.HostName, peerStatus.Self.TailscaleIPs)
			for _, peer := range peerStatus.Peer {
				if peer.PrimaryRoutes != nil && peer.PrimaryRoutes.Len() > 0 {
					log.Printf("[DEBUG] peer %s (%s): routes=%v, online=%v, relay=%s",
						peer.HostName, peer.TailscaleIPs, peer.PrimaryRoutes.AsSlice(), peer.Online, peer.Relay)
				}
			}
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
	log.Printf("starting DNS server: %v", *listenAddrs)
	if err := dnsServer.RunWithAddrs(ctx, *listenAddrs, status); err != nil {
		log.Printf("DNS server error: %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), constants.HealthShutdownTimeout)
	defer cancel2()
	if err := healthServer.Shutdown(ctx2); err != nil {
		log.Printf("health shutdown: %v", err)
	}
}

// Enable --accept-routes to be able to route DNS traffic via subnet routes in tailnet
func enableAcceptRoutes(ctx context.Context, lc *local.Client) error {
	prefs, err := lc.GetPrefs(ctx)
	if err != nil {
		return err
	}

	log.Printf("current RouteAll preference: %v", prefs.RouteAll)

	if !prefs.RouteAll {
		log.Print("setting RouteAll=true via EditPrefs...")
		newPrefs, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
			Prefs: ipn.Prefs{
				RouteAll: true,
			},
			RouteAllSet: true,
		})
		if err != nil {
			return err
		}
		log.Printf("EditPrefs succeeded, new RouteAll: %v", newPrefs.RouteAll)
	} else {
		log.Print("RouteAll already enabled, skipping EditPrefs")
	}

	return nil
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
