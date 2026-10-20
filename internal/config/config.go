// Package config loads tsdnsproxy settings from flags and environment variables.
package config

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/constants"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
)

// Config is the process configuration.
type Config struct {
	AuthKey             string
	Hostname            string
	StateDir            string
	State               string
	ControlURL          string
	AdvertiseTags       string
	OverrideDNS         string
	CacheTTL            time.Duration
	HTTPAddr            string
	ListenAddrs         string
	Service             string
	AcceptRoutes        bool
	Dial                string
	DialSet             bool
	LogLevel            string
	CapName             string
	RulesFile           string
	RulesOnly           bool
	MaxInflight         int
	MaxMessageBytes     int
	MaxUDPBytes         int
	RateLimit           float64
	RateBurst           int
	QueryTimeout        time.Duration
	DNSCache            bool
	AnswerCacheSize     int
	AnswerMinTTL        time.Duration
	AnswerMaxTTL        time.Duration
	UIAddr              string
	UIHistory           int
	UICap               string
	UIAuditCap          string
	UITrustedProxyTags  []string
	UIUserHeader        string
	UINameHeader        string
	UIGroupsHeader      string
	UIGroups            []string
	UIAuditGroups       []string
	UILocalAddr         string
	UITrustedProxyCIDRs []netip.Prefix
}

// Parse reads args as flags. Environment variables supply the defaults.
// getenv may be nil, in which case every variable is unset.
func Parse(args []string, getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	var cfg Config
	fs := flag.NewFlagSet("tsdnsproxy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&cfg.AuthKey, "auth-key", getenv("TS_AUTHKEY"), "tailscale auth key (TS_AUTHKEY)")
	fs.StringVar(&cfg.Hostname, "hostname", envOr(getenv, "TSDNSPROXY_HOSTNAME", "tsdnsproxy"), "hostname on the tailnet")
	fs.StringVar(&cfg.StateDir, "state-dir", envOr(getenv, "TSDNSPROXY_STATE_DIR", "/var/lib/tsdnsproxy"), "state directory")
	fs.StringVar(&cfg.State, "state", getenv("TSDNSPROXY_STATE"), "state store, for example kube:tsdnsproxy-state")
	fs.StringVar(&cfg.ControlURL, "control-url", getenv("TS_CONTROLURL"), "alternate control server URL")
	fs.StringVar(&cfg.AdvertiseTags, "advertise-tags", getenv("TSDNSPROXY_ADVERTISE_TAGS"), "comma-separated ACL tags")
	fs.StringVar(&cfg.OverrideDNS, "override-dns", getenv("TSDNSPROXY_OVERRIDE_DNS"), "comma-separated default DNS servers")
	fs.DurationVar(&cfg.CacheTTL, "cache-ttl", durationEnv(getenv, "TSDNSPROXY_CACHE_TTL", constants.DefaultCacheExpiry), "whois and grant cache TTL")
	fs.StringVar(&cfg.HTTPAddr, "http-addr", envOr(getenv, "TSDNSPROXY_HTTP_ADDR", ":8080"), "address for /health, /ready, and /metrics")
	fs.StringVar(&cfg.ListenAddrs, "listen-addrs", envOr(getenv, "TSDNSPROXY_LISTEN_ADDRS", "tailscale"), "comma-separated DNS listen addresses")
	fs.StringVar(&cfg.Service, "service", getenv("TSDNSPROXY_SERVICE"), "Tailscale Service to host, for example svc:dns")
	fs.BoolVar(&cfg.AcceptRoutes, "accept-routes", envBool(getenv, "TSDNSPROXY_ACCEPT_ROUTES"), "accept subnet routes")
	fs.StringVar(&cfg.Dial, "dial", envOr(getenv, "TSDNSPROXY_DIAL", "tailnet"), "default backend dial mode: tailnet or direct")
	fs.StringVar(&cfg.LogLevel, "log-level", envOr(getenv, "TSDNSPROXY_LOG_LEVEL", "info"), "log level: debug, info, warn, or error")
	fs.StringVar(&cfg.CapName, "cap-name", envOr(getenv, "TSDNSPROXY_CAP_NAME", grants.DefaultCapName), "capability name for DNS grants")
	fs.StringVar(&cfg.RulesFile, "rules-file", getenv("TSDNSPROXY_RULES_FILE"), "JSON or HuJSON rules file")
	fs.BoolVar(&cfg.RulesOnly, "rules-only", envBool(getenv, "TSDNSPROXY_RULES_ONLY"), "ignore ACL grants and use only the rules file")
	fs.IntVar(&cfg.MaxInflight, "max-inflight", intEnv(getenv, "TSDNSPROXY_MAX_INFLIGHT", constants.WorkerPoolSize), "maximum queries handled at once")
	fs.IntVar(&cfg.MaxMessageBytes, "max-message-bytes", intEnv(getenv, "TSDNSPROXY_MAX_MESSAGE_BYTES", constants.DNSMaxMessageSize), "maximum accepted DNS message size")
	fs.IntVar(&cfg.MaxUDPBytes, "max-udp-bytes", intEnv(getenv, "TSDNSPROXY_MAX_UDP_BYTES", 1232), "maximum UDP response size")
	fs.Float64Var(&cfg.RateLimit, "rate-limit", floatEnv(getenv, "TSDNSPROXY_RATE_LIMIT", 0), "queries per second per client, 0 disables")
	fs.IntVar(&cfg.RateBurst, "rate-burst", intEnv(getenv, "TSDNSPROXY_RATE_BURST", 50), "per-client rate limit burst")
	fs.DurationVar(&cfg.QueryTimeout, "query-timeout", durationEnv(getenv, "TSDNSPROXY_QUERY_TIMEOUT", constants.QueryTimeout), "timeout for one DNS query")
	fs.BoolVar(&cfg.DNSCache, "dns-cache", envBoolDefault(getenv, "TSDNSPROXY_DNS_CACHE", true), "cache DNS answers")
	fs.IntVar(&cfg.AnswerCacheSize, "cache-size", intEnv(getenv, "TSDNSPROXY_CACHE_SIZE", constants.DefaultAnswerCacheSize), "maximum cached DNS answers, 0 disables")
	fs.DurationVar(&cfg.AnswerMinTTL, "cache-min-ttl", durationEnv(getenv, "TSDNSPROXY_CACHE_MIN_TTL", constants.DefaultAnswerMinTTL), "shortest time to keep a cached DNS answer")
	fs.DurationVar(&cfg.AnswerMaxTTL, "cache-max-ttl", durationEnv(getenv, "TSDNSPROXY_CACHE_MAX_TTL", constants.DefaultAnswerMaxTTL), "longest time to keep a cached DNS answer")
	fs.StringVar(&cfg.UIAddr, "ui-addr", envOr(getenv, "TSDNSPROXY_UI_ADDR", ":80"), "tailnet address for the status UI; empty or - disables it")
	fs.IntVar(&cfg.UIHistory, "ui-history", intEnv(getenv, "TSDNSPROXY_UI_HISTORY", 1000), "recent DNS queries to keep; 0 disables the log")
	fs.StringVar(&cfg.UICap, "ui-cap", getenv("TSDNSPROXY_UI_CAP"), "capability required to open the UI; empty allows any identified tailnet peer")
	fs.StringVar(&cfg.UIAuditCap, "ui-audit-cap", getenv("TSDNSPROXY_UI_AUDIT_CAP"), "capability required to see peers, queries, and access; empty uses the UI rule")
	var proxyTags, userHeader, nameHeader, groupsHeader, viewGroups, auditGroups, proxyCIDRs string
	fs.StringVar(&cfg.UILocalAddr, "ui-local-addr", getenv("TSDNSPROXY_UI_LOCAL_ADDR"), "optional pod address for the status UI, for example 0.0.0.0:8081")
	fs.StringVar(&proxyCIDRs, "ui-trusted-proxy-cidrs", getenv("TSDNSPROXY_UI_TRUSTED_PROXY_CIDRS"), "comma-separated CIDRs whose connections may forward UI identity headers")
	fs.StringVar(&proxyTags, "ui-trusted-proxy-tags", getenv("TSDNSPROXY_UI_TRUSTED_PROXY_TAGS"), "comma-separated tags whose nodes may forward UI identity headers")
	fs.StringVar(&userHeader, "ui-user-header", envOr(getenv, "TSDNSPROXY_UI_USER_HEADER", "Tailscale-User-Login"), "header with the proxied user login")
	fs.StringVar(&nameHeader, "ui-name-header", envOr(getenv, "TSDNSPROXY_UI_NAME_HEADER", "Tailscale-User-Name"), "header with the proxied display name")
	fs.StringVar(&groupsHeader, "ui-groups-header", envOr(getenv, "TSDNSPROXY_UI_GROUPS_HEADER", "X-Tailscale-Groups"), "header with comma-separated proxied groups")
	fs.StringVar(&viewGroups, "ui-groups", getenv("TSDNSPROXY_UI_GROUPS"), "comma-separated groups allowed to open the UI")
	fs.StringVar(&auditGroups, "ui-audit-groups", getenv("TSDNSPROXY_UI_AUDIT_GROUPS"), "comma-separated groups allowed to see peers, queries, and access; empty uses ui-groups")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	cfg.UITrustedProxyTags = splitList(proxyTags)
	cfg.UIGroups = splitList(viewGroups)
	cfg.UIAuditGroups = splitList(auditGroups)
	cfg.UIUserHeader = strings.TrimSpace(userHeader)
	cfg.UINameHeader = strings.TrimSpace(nameHeader)
	cfg.UIGroupsHeader = strings.TrimSpace(groupsHeader)
	cfg.UILocalAddr = strings.TrimSpace(cfg.UILocalAddr)
	cidrs, err := parsePrefixes(proxyCIDRs)
	if err != nil {
		return Config{}, err
	}
	cfg.UITrustedProxyCIDRs = cidrs
	if cfg.UIAddr == "-" {
		cfg.UIAddr = ""
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "dial" {
			cfg.DialSet = true
		}
	})
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks the values that can be rejected before the process starts.
func (c Config) Validate() error {
	if c.CacheTTL <= 0 {
		return fmt.Errorf("cache-ttl must be positive")
	}
	if c.QueryTimeout <= 0 {
		return fmt.Errorf("query-timeout must be positive")
	}
	if c.MaxInflight < 1 {
		return fmt.Errorf("max-inflight must be at least 1")
	}
	if c.MaxMessageBytes < 12 || c.MaxMessageBytes > constants.DNSMaxMessageSize {
		return fmt.Errorf("max-message-bytes must be between 12 and %d", constants.DNSMaxMessageSize)
	}
	if c.MaxUDPBytes < 512 || c.MaxUDPBytes > constants.DNSMaxMessageSize {
		return fmt.Errorf("max-udp-bytes must be between 512 and %d", constants.DNSMaxMessageSize)
	}
	if c.RateLimit < 0 {
		return fmt.Errorf("rate-limit must be zero or positive")
	}
	if c.RateBurst < 1 {
		return fmt.Errorf("rate-burst must be at least 1")
	}
	if c.AnswerCacheSize < 0 {
		return fmt.Errorf("cache-size must be zero or positive")
	}
	if c.AnswerMinTTL < 0 {
		return fmt.Errorf("cache-min-ttl must be zero or positive")
	}
	if c.AnswerMaxTTL <= 0 {
		return fmt.Errorf("cache-max-ttl must be positive")
	}
	if c.AnswerMinTTL > c.AnswerMaxTTL {
		return fmt.Errorf("cache-min-ttl must not exceed cache-max-ttl")
	}
	if c.UIHistory < 0 {
		return fmt.Errorf("ui-history must be zero or positive")
	}
	if c.UIAddr != "" {
		if _, err := net.ResolveTCPAddr("tcp", c.UIAddr); err != nil {
			return fmt.Errorf("ui-addr: %w", err)
		}
	}
	if c.UILocalAddr != "" {
		if _, err := net.ResolveTCPAddr("tcp", c.UILocalAddr); err != nil {
			return fmt.Errorf("ui-local-addr: %w", err)
		}
		if len(c.UITrustedProxyCIDRs) == 0 {
			return fmt.Errorf("ui-local-addr requires ui-trusted-proxy-cidrs")
		}
	}
	if err := validHeaderName("ui-user-header", c.UIUserHeader); err != nil {
		return err
	}
	if err := validHeaderName("ui-name-header", c.UINameHeader); err != nil {
		return err
	}
	if err := validHeaderName("ui-groups-header", c.UIGroupsHeader); err != nil {
		return err
	}
	if err := validList("ui-trusted-proxy-tags", c.UITrustedProxyTags); err != nil {
		return err
	}
	if err := validList("ui-groups", c.UIGroups); err != nil {
		return err
	}
	if err := validList("ui-audit-groups", c.UIAuditGroups); err != nil {
		return err
	}
	if _, err := ParseLogLevel(c.LogLevel); err != nil {
		return err
	}
	if c.HTTPAddr != "" {
		if _, err := net.ResolveTCPAddr("tcp", c.HTTPAddr); err != nil {
			return fmt.Errorf("http-addr: %w", err)
		}
	}
	if c.RulesOnly && c.RulesFile == "" {
		return fmt.Errorf("rules-only requires rules-file")
	}
	return nil
}

// ParseLogLevel accepts debug, info, warn, and error.
func ParseLogLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("log level %q is not debug, info, warn, or error", raw)
	}
}

func parsePrefixes(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	seen := map[netip.Prefix]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		p, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("ui-trusted-proxy-cidrs %q: %w", item, err)
		}
		p = p.Masked()
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out, nil
}

func splitList(raw string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func validHeaderName(flagName, name string) error {
	if name == "" {
		return fmt.Errorf("%s is empty", flagName)
	}
	if len(name) > 128 || !tokenString(name) {
		return fmt.Errorf("%s %q is not a header name", flagName, name)
	}
	return nil
}

func validList(flagName string, items []string) error {
	for _, item := range items {
		if len(item) > 128 || strings.ContainsAny(item, " \t\r\n") {
			return fmt.Errorf("%s entry %q is invalid", flagName, item)
		}
	}
	return nil
}

func tokenString(name string) bool {
	for _, r := range name {
		if r <= ' ' || r >= 127 || r == ':' {
			return false
		}
	}
	return true
}

func envOr(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(getenv func(string) string, key string) bool {
	return envBoolDefault(getenv, key, false)
}

func envBoolDefault(getenv func(string) string, key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(getenv(key))) {
	case "":
		return fallback
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func durationEnv(getenv func(string) string, key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return d
}

func intEnv(getenv func(string) string, key string, fallback int) int {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return fallback
	}
	var n int
	if _, err := fmt.Sscan(raw, &n); err != nil {
		return fallback
	}
	return n
}

func floatEnv(getenv func(string) string, key string, fallback float64) float64 {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return fallback
	}
	var n float64
	if _, err := fmt.Sscan(raw, &n); err != nil {
		return fallback
	}
	return n
}
