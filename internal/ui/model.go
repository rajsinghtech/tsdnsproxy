// Package ui serves a read-only status site on the tailnet.
package ui

import "time"

// Snapshot is the public configuration and runtime view.
// It never includes auth keys, state-store contents, or raw secrets.
type Snapshot struct {
	Version        string     `json:"version"`
	Image          string     `json:"image"`
	UptimeSec      int64      `json:"uptime_sec"`
	Started        time.Time  `json:"started"`
	CapName        string     `json:"cap_name"`
	RulesOnly      bool       `json:"rules_only"`
	RulesUpdated   time.Time  `json:"rules_updated"`
	HistoryEnabled bool       `json:"history_enabled"`
	HistoryLimit   int        `json:"history_limit"`
	ViewCap        string     `json:"view_cap"`
	AuditCap       string     `json:"audit_cap"`
	Viewer         Viewer     `json:"viewer,omitempty"`
	Listeners      []Listener `json:"listeners"`
	Service        Service    `json:"service"`
	Caches         Caches     `json:"caches"`
	Rules          []Rule     `json:"rules"`
	Backends       []Backend  `json:"backends"`
}

// Listener is one bound DNS socket.
type Listener struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Service string `json:"service,omitempty"`
	State   string `json:"state"`
}

// Service is the hosted Tailscale Service, if one is configured.
type Service struct {
	Name  string `json:"name"`
	Port  int    `json:"port"`
	State string `json:"state"`
}

// Caches reports the answer, whois, and grant caches.
type Caches struct {
	Answer CacheStat `json:"answer"`
	Whois  CacheStat `json:"whois"`
	Grants CacheStat `json:"grants"`
}

// CacheStat is one cache.
type CacheStat struct {
	Enabled   bool   `json:"enabled"`
	Entries   int    `json:"entries"`
	Limit     int    `json:"limit,omitempty"`
	Hits      uint64 `json:"hits,omitempty"`
	Misses    uint64 `json:"misses,omitempty"`
	Evictions uint64 `json:"evictions,omitempty"`
	TTLSec    int64  `json:"ttl_sec,omitempty"`
}

// Rule is one domain or zone and the policy that applies to it.
type Rule struct {
	Domain      string   `json:"domain"`
	Source      string   `json:"source"`
	Rewrite     string   `json:"rewrite,omitempty"`
	Backends    []string `json:"backends,omitempty"`
	TranslateID *int     `json:"translate_id,omitempty"`
	SitePrefix  string   `json:"site_prefix,omitempty"`
	AllowIPs    []string `json:"allow_ips,omitempty"`
	DenyIPs     []string `json:"deny_ips,omitempty"`
	AllowSrc    []string `json:"allow_src,omitempty"`
	IPNames     *IPNames `json:"ipnames,omitempty"`
	Static      *Static  `json:"static,omitempty"`
}

// Static is a configured address answer for one name or single-label wildcard.
type Static struct {
	A    []string `json:"a,omitempty"`
	AAAA []string `json:"aaaa,omitempty"`
	TTL  int      `json:"ttl,omitempty"`
	Apex bool     `json:"apex,omitempty"`
}

// IPNames is the encoded-name zone on a rule.
type IPNames struct {
	SiteID     int      `json:"site_id"`
	A          string   `json:"a,omitempty"`
	AllowSrc   []string `json:"allow_src,omitempty"`
	AllowIPs   []string `json:"allow_ips,omitempty"`
	DirectSrc  []string `json:"direct_src,omitempty"`
	SitePrefix string   `json:"site_prefix,omitempty"`
}

// Backend is one default upstream.
type Backend struct {
	Address  string    `json:"address"`
	Mode     string    `json:"mode"`
	Healthy  bool      `json:"healthy"`
	Failures int       `json:"failures"`
	RetryAt  time.Time `json:"retry_at,omitempty"`
}

// Peer is one identity the proxy has learned from whois and grants.
type Peer struct {
	ID          string    `json:"id"`
	Node        string    `json:"node"`
	User        string    `json:"user"`
	Tags        []string  `json:"tags"`
	IPs         []string  `json:"ips"`
	Seen        time.Time `json:"seen"`
	CacheAgeSec int64     `json:"cache_age_sec"`
	CacheExpire time.Time `json:"cache_expire"`
	Caps        []string  `json:"caps"`
	Rules       []Rule    `json:"rules"`
}

// Query is one recent DNS question.
type Query struct {
	Time        time.Time `json:"time"`
	PeerIP      string    `json:"peer_ip"`
	Node        string    `json:"node"`
	User        string    `json:"user"`
	Tags        []string  `json:"tags"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Zone        string    `json:"zone"`
	Source      string    `json:"source"`
	Rewrite     string    `json:"rewrite,omitempty"`
	TranslateID *int      `json:"translate_id,omitempty"`
	Action      string    `json:"action"`
	Backend     string    `json:"backend"`
	RCode       string    `json:"rcode"`
	LatencyMS   int64     `json:"latency_ms"`
	Cache       string    `json:"cache"`
	Path        string    `json:"path"`
}

// Access summarizes who is asking for which names.
type Access struct {
	Total   int     `json:"total"`
	Refused int     `json:"refused"`
	Peers   []Tally `json:"peers"`
	Domains []Tally `json:"domains"`
	History bool    `json:"history"`
	Viewer  Viewer  `json:"viewer,omitempty"`
}

// Viewer is the person looking at the status site.
// ViaProxy is set when the TCP peer is a trusted proxy and the identity
// came from forwarded headers.
type Viewer struct {
	Login    string   `json:"login,omitempty"`
	Name     string   `json:"name,omitempty"`
	Node     string   `json:"node,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	ViaProxy bool     `json:"via_proxy"`
	// GrantedCap is the capability that granted this viewer access.
	// It is empty for a trusted-proxy viewer and when no capability matched.
	GrantedCap string `json:"granted_cap,omitempty"`
}

// Tally is a count of queries, including how many were refused.
type Tally struct {
	Name    string `json:"name"`
	Queries int    `json:"queries"`
	Refused int    `json:"refused"`
}

// Lookup is the dry-run result for one name, type, and peer.
type Lookup struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Peer      string   `json:"peer"`
	Identity  string   `json:"identity"`
	Matched   bool     `json:"matched"`
	Rule      *Rule    `json:"rule,omitempty"`
	Forwarded bool     `json:"forwarded"`
	RCode     string   `json:"rcode,omitempty"`
	Answers   []string `json:"answers,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// LookupRequest is a dry run. Forward asks the proxy to resolve upstream.
type LookupRequest struct {
	Name    string
	Type    string
	Peer    string
	Forward bool
}
