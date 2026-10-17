package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/backend"
	"github.com/rajsinghtech/tsdnsproxy/internal/cache"
	"github.com/rajsinghtech/tsdnsproxy/internal/config"
	"github.com/rajsinghtech/tsdnsproxy/internal/constants"
	"github.com/rajsinghtech/tsdnsproxy/internal/dns"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"tailscale.com/client/local"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store"
	_ "tailscale.com/ipn/store/kubestore" // registers the kube: state store; no build tag, so -tags netgo keeps it
	"tailscale.com/tsnet"
)

// version is set with -ldflags "-X main.version=..." at release build time.
var version = "dev"

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
				servers = appendDNSServer(servers, server)
			}
		}
		if len(servers) > 0 {
			return servers
		}
	}

	// Fallback to system DNS resolution
	lookupCtx, lookupCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer lookupCancel()
	config, err := net.DefaultResolver.LookupNS(lookupCtx, ".")
	if err == nil && len(config) > 0 {
		for _, ns := range config {
			host := strings.TrimSuffix(ns.Host, ".")
			servers = appendDNSServer(servers, host)
		}
		if len(servers) > 0 {
			return servers
		}
	}

	// Final fallback to common public DNS
	log.Println("warning: could not determine host DNS servers, falling back to 8.8.8.8:53")
	return []string{"8.8.8.8:53"}
}

func appendDNSServer(servers []string, host string) []string {
	host = strings.TrimSpace(host)
	if host == "" {
		return servers
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "53")
	}
	return append(servers, host)
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
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return fmt.Errorf("context cancelled: %w", ctx.Err())
			case <-timer.C:
			}
		}
	}
	return fmt.Errorf("failed after %d attempts: %w", maxRetries, err)
}

func main() {
	log.SetPrefix("tsdnsproxy: ")
	hostinfo.SetApp("tsdnsproxy")
	log.Printf("version %s", version)

	cfg, err := config.Parse(os.Args[1:], os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	verbose := strings.EqualFold(cfg.LogLevel, "debug")

	grantParser, err := grants.NewParserWithName(cfg.CapName)
	if err != nil {
		log.Fatalf("invalid cap-name: %v", err)
	}
	dialMode, err := backend.ParseDialMode(cfg.Dial)
	if err != nil {
		log.Fatal(err)
	}

	// Log configuration for debugging
	hostedService, err := dns.ParseHostedService(cfg.Service)
	if err != nil {
		log.Fatalf("service: %v", err)
	}
	if hostedService.Name != "" && !hasAdvertiseTag(cfg.AdvertiseTags) {
		log.Fatal("advertise-tags is required to host a Tailscale Service (set -advertise-tags or TSDNSPROXY_ADVERTISE_TAGS)")
	}

	log.Printf("configuration: accept-routes=%v (env=%q), dial=%s, verbose=%v, listen-addrs=%q, service=%q, cap-name=%q, rules-file=%q, rules-only=%v",
		cfg.AcceptRoutes, os.Getenv("TSDNSPROXY_ACCEPT_ROUTES"), dialMode,
		verbose, cfg.ListenAddrs, hostedService.Name, grantParser.CapName(), cfg.RulesFile, cfg.RulesOnly)

	if cfg.AuthKey == "" {
		log.Fatal("auth key is required (set TS_AUTHKEY or use -auth-key)")
	}
	if cfg.RulesOnly && cfg.RulesFile == "" {
		log.Fatal("-rules-only requires -rules-file")
	}

	var rules *grants.RulesFile
	if cfg.RulesFile != "" {
		loaded, err := grants.OpenRulesFile(cfg.RulesFile)
		if err != nil {
			log.Fatalf("rules file: %v", err)
		}
		rules = loaded
		logLoadedRules(rules)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				if rules == nil {
					log.Print("SIGHUP ignored, no rules file configured")
					continue
				}
				changed, err := rules.Reload()
				if err != nil {
					log.Printf("SIGHUP: rules reload failed: %v", err)
					continue
				}
				if changed {
					log.Printf("SIGHUP: reloaded rules from %s", rules.Path())
					continue
				}
				log.Print("SIGHUP: rules file unchanged")
				continue
			}
			log.Println("shutting down...")
			cancel()
			return
		}
	}()
	if rules != nil {
		go rules.Watch(ctx, grants.RulesPollInterval)
	}

	cfg.Hostname = expandEnvRefs(cfg.Hostname)
	cfg.State = expandEnvRefs(cfg.State)
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		log.Printf("state dir %s: %v", cfg.StateDir, err)
	}

	defaultServers := hostOrOverrideDNS(cfg.OverrideDNS)
	needRoutes, err := needsTailnetRoutes(cfg.AcceptRoutes, explicitDialTailnet(dialMode, cfg.DialSet), defaultServers, rules)
	if err != nil {
		log.Fatalf("backend dial: %v", err)
	}
	log.Printf("using DNS servers: %v (dial=%s, tailnet-routes=%v)", defaultServers, dialMode, needRoutes)

	s := &tsnet.Server{
		Dir:      cfg.StateDir,
		Hostname: cfg.Hostname,
		AuthKey:  cfg.AuthKey,
		Logf:     logf(verbose),
	}

	if cfg.AdvertiseTags != "" {
		s.AdvertiseTags = strings.Split(cfg.AdvertiseTags, ",")
	}

	if cfg.ControlURL != "" {
		s.ControlURL = cfg.ControlURL
	}

	if cfg.State != "" {
		log.Printf("available store: awsstore: %v kube:%v", store.HasKnownProviderPrefix("arn:"), store.HasKnownProviderPrefix("kube:"))
		if strings.HasPrefix(cfg.State, "kube:") && !store.HasKnownProviderPrefix(cfg.State) {
			log.Fatal("kube: state store provider is not registered")
		}

		stateStore, err := store.New(log.Printf, cfg.State)
		if err != nil {
			log.Fatalf("failed to create state store: %v", err)
		}
		s.Store = stateStore
		log.Printf("using state store: %s", cfg.State)
	}

	defer func() {
		if err := s.Close(); err != nil {
			log.Printf("tsnet server close error: %v", err)
		}
	}()

	log.Printf("starting tsnet server as %q", cfg.Hostname)

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

	routes := &routeGate{}
	if lc != nil {
		routes.SetClient(lc)
	}
	// Enable RouteAll BEFORE calling Up() so subnet routes are accepted
	// in the initial WireGuard configuration. A failure here is retried after Up.
	if needRoutes && lc != nil {
		log.Print("enabling accept-routes before tailnet up...")
		if err := enableAcceptRoutes(ctx, lc); err != nil {
			log.Printf("warning: failed to enable routes early: %v", err)
		}
	}

	whoisCache := cache.NewWhoisCache(cfg.CacheTTL)
	grantCache := cache.NewGrantCache(cfg.CacheTTL)
	defer whoisCache.Close()
	defer grantCache.Close()

	// Bare addresses use the default dialer. An explicit tailnet:// address
	// uses the same tsnet dialer and also accepts subnet routes.
	backendMgr, err := backend.NewManager(defaultServers, backend.Dialers{
		Direct:        backend.HostDialer(),
		Tailnet:       s,
		TailnetRoutes: backend.NewEnsuringDialer(s, routes.Ensure),
		Default:       dialMode,
	}, logf(verbose))
	if err != nil {
		log.Fatalf("backend dial: %v", err)
	}
	defer backendMgr.Close()

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
	routes.SetClient(lc)

	if needRoutes {
		log.Print("accepting subnet routes...")
		if err := routes.Ensure(ctx); err != nil {
			log.Fatalf("failed to enable accepting routes: %v", err)
		}
	}

	// Log peer status to help diagnose subnet route issues
	if verbose {
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
		TSServer:     s,
		LocalClient:  lc,
		WhoisCache:   whoisCache,
		GrantCache:   grantCache,
		GrantParser:  grantParser,
		BackendMgr:   backendMgr,
		Logf:         logf(verbose),
		Rules:        rules,
		RulesOnly:    cfg.RulesOnly,
		Service:      cfg.Service,
		QueryTimeout: cfg.QueryTimeout,
		MaxUDP:       cfg.MaxUDPBytes,
		MaxInflight:  cfg.MaxInflight,
		MaxMessage:   cfg.MaxMessageBytes,
		RatePerSec:   cfg.RateLimit,
		RateBurst:    cfg.RateBurst,
	}

	healthServer := startHealthServer(ctx, cfg.HTTPAddr, s)

	// Start DNS server (handles both UDP and TCP)
	log.Printf("starting DNS server: %v", cfg.ListenAddrs)
	if err := dnsServer.RunWithAddrs(ctx, cfg.ListenAddrs, status); err != nil {
		log.Printf("DNS server error: %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), constants.HealthShutdownTimeout)
	defer cancel2()
	if err := healthServer.Shutdown(ctx2); err != nil {
		log.Printf("health shutdown: %v", err)
	}
}

func hostOrOverrideDNS(override string) []string {
	if override == "" {
		servers := getHostDNSServers()
		log.Printf("using host DNS servers: %v", servers)
		return servers
	}
	var servers []string
	for _, server := range strings.Split(override, ",") {
		server = strings.TrimSpace(server)
		if server != "" {
			servers = append(servers, server)
		}
	}
	log.Printf("using override DNS servers: %v", servers)
	return servers
}

// explicitDialTailnet reports whether the operator set -dial or
// TSDNSPROXY_DIAL to tailnet. The built-in default does not count.
func explicitDialTailnet(mode backend.DialMode, flagSet bool) bool {
	if mode != backend.DialTailnet {
		return false
	}
	if flagSet {
		return true
	}
	_, ok := os.LookupEnv("TSDNSPROXY_DIAL")
	return ok
}

func needsTailnetRoutes(accept, explicitDial bool, defaults []string, rules *grants.RulesFile) (bool, error) {
	if accept || explicitDial {
		return true, nil
	}
	need, err := backend.ExplicitTailnet(defaults)
	if err != nil || need || rules == nil {
		return need, err
	}
	cfg, ok := rules.Current()
	if !ok {
		return false, nil
	}
	var dns []string
	for _, grant := range cfg {
		dns = append(dns, grant.DNS...)
	}
	return backend.ExplicitTailnet(dns)
}

// routeGate turns on subnet routes once, and retries when a previous attempt failed.
type routeGate struct {
	mu sync.Mutex
	lc *local.Client
	on bool
}

func (g *routeGate) SetClient(lc *local.Client) {
	g.mu.Lock()
	g.lc = lc
	g.mu.Unlock()
}

func (g *routeGate) Ensure(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.on {
		return nil
	}
	if g.lc == nil {
		return fmt.Errorf("tailnet local client is not available")
	}
	if err := enableAcceptRoutes(ctx, g.lc); err != nil {
		return err
	}
	g.on = true
	return nil
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

func logLoadedRules(rules *grants.RulesFile) {
	cfg, ok := rules.Current()
	if !ok {
		return
	}
	names := make([]string, 0, len(cfg))
	for domain := range cfg {
		names = append(names, domain)
	}
	sort.Strings(names)
	log.Printf("loaded %d rules from %s", len(names), rules.Path())
	for _, name := range names {
		log.Printf("  - rule for %s", name)
	}
}

func hasAdvertiseTag(raw string) bool {
	for _, part := range strings.Split(raw, ",") {
		if strings.TrimSpace(part) != "" {
			return true
		}
	}
	return false
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
