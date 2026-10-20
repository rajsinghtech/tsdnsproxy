package ui

import "time"

// ExampleSnapshot is generic status data for previews and tests.
func ExampleSnapshot() Snapshot {
	id := 7
	return Snapshot{
		Version:        "dev",
		Image:          "example/tsdnsproxy:dev",
		UptimeSec:      5400,
		Started:        time.Unix(1_700_000_000, 0).UTC(),
		CapName:        "example.com/cap/dns",
		RulesOnly:      false,
		RulesUpdated:   time.Unix(1_700_001_000, 0).UTC(),
		HistoryEnabled: true,
		HistoryLimit:   1000,
		Listeners: []Listener{
			{Proto: "udp", Addr: ":53", State: "listening"},
			{Proto: "tcp", Addr: ":53", State: "listening"},
			{Proto: "service", Addr: "dns.example.ts.net", Service: "svc:dns", State: "listening"},
		},
		Service: Service{Name: "svc:dns", Port: 53, State: "listening"},
		Caches: Caches{
			Answer: CacheStat{Enabled: true, Entries: 128, Limit: 4096, Hits: 840, Misses: 96, Evictions: 2},
			Whois:  CacheStat{Enabled: true, Entries: 4, TTLSec: 300},
			Grants: CacheStat{Enabled: true, Entries: 2, TTLSec: 300},
		},
		Rules: []Rule{
			{Domain: "example.internal", Source: "rules", Rewrite: "svc.example", Backends: []string{"10.0.0.53:53"}},
			{Domain: "site.example", Source: "rules", TranslateID: &id, SitePrefix: "fd7a:115c:a1e0:b1a:0:7::/96", AllowIPs: []string{"10.0.0.0/8"}, Backends: []string{"10.0.0.53:53"}},
			{Domain: "ip", Source: "rules", SitePrefix: "fd7a:115c:a1e0:b1a:0:1::/96", IPNames: &IPNames{SiteID: 1, A: "never", AllowIPs: []string{"10.0.0.0/8"}, SitePrefix: "fd7a:115c:a1e0:b1a:0:1::/96"}},
			{Domain: "*.apps.example.internal", Source: "rules", Static: &Static{A: []string{"192.0.2.20"}, TTL: 30}},
		},
		Backends: []Backend{
			{Address: "10.0.0.53:53", Mode: "tailnet", Healthy: true},
			{Address: "10.0.0.54:53", Mode: "direct", Healthy: false, Failures: 3, RetryAt: time.Unix(1_700_001_800, 0).UTC()},
		},
	}
}

// ExamplePeers is a learned grant view for previews.
func ExamplePeers() []Peer {
	lab := 1
	return []Peer{
		{
			ID: "a.example.ts.net", Node: "a.example.ts.net", User: "alice@example.com",
			Tags: []string{"tag:dns"}, IPs: []string{"100.64.0.2"},
			Seen: time.Unix(1_700_001_200, 0).UTC(), CacheAgeSec: 40, CacheExpire: time.Unix(1_700_001_500, 0).UTC(),
			Caps: []string{`{"lab.example":{"dns":["10.0.0.53:53"],"translateid":1,"allowips":["10.0.0.0/8"]}}`},
			Rules: []Rule{
				{Domain: "example.internal", Source: "rules", Rewrite: "svc.example", Backends: []string{"10.0.0.53:53"}},
				{Domain: "lab.example", Source: "grant", TranslateID: &lab, SitePrefix: "fd7a:115c:a1e0:b1a:0:1::/96", AllowIPs: []string{"10.0.0.0/8"}, Backends: []string{"10.0.0.53:53"}},
			},
		},
		{
			ID: "b.example.ts.net", Node: "b.example.ts.net", User: "bob@example.com",
			Tags: []string{"tag:dns"}, IPs: []string{"100.64.0.3"},
			Seen: time.Unix(1_700_001_100, 0).UTC(), CacheAgeSec: 90, CacheExpire: time.Unix(1_700_001_400, 0).UTC(),
			Rules: []Rule{{Domain: "example.internal", Source: "rules", Rewrite: "svc.example", Backends: []string{"10.0.0.53:53"}}},
		},
	}
}

// ExampleQueries is a short access log for previews.
func ExampleQueries() []Query {
	id := 7
	base := time.Unix(1_700_001_300, 0).UTC()
	return []Query{
		{Time: base, PeerIP: "100.64.0.2", Node: "a.example.ts.net", User: "alice@example.com", Tags: []string{"tag:dns"}, Name: "app.example.internal", Type: "AAAA", Zone: "example.internal", Source: "rules", Rewrite: "svc.example", Action: "rewrite", Backend: "10.0.0.53:53", RCode: "NOERROR", LatencyMS: 12, Cache: "miss", Path: "udp"},
		{Time: base.Add(time.Second), PeerIP: "100.64.0.2", Node: "a.example.ts.net", User: "alice@example.com", Name: "app.example.internal", Type: "AAAA", Zone: "example.internal", Source: "rules", Action: "rewrite", Backend: "10.0.0.53:53", RCode: "NOERROR", LatencyMS: 1, Cache: "hit", Path: "udp"},
		{Time: base.Add(2 * time.Second), PeerIP: "100.64.0.3", Node: "b.example.ts.net", User: "bob@example.com", Name: "db.site.example", Type: "AAAA", Zone: "site.example", Source: "rules", TranslateID: &id, Action: "4via6", Backend: "10.0.0.53:53", RCode: "NOERROR", LatencyMS: 18, Cache: "miss", Path: "tcp"},
		{Time: base.Add(3 * time.Second), PeerIP: "100.64.0.3", Node: "b.example.ts.net", User: "bob@example.com", Name: "blocked.example.internal", Type: "A", Zone: "example.internal", Source: "rules", Action: "forward", Backend: "10.0.0.53:53", RCode: "REFUSED", LatencyMS: 2, Cache: "miss", Path: "peerapi"},
		{Time: base.Add(4 * time.Second), PeerIP: "100.64.0.2", Node: "a.example.ts.net", User: "alice@example.com", Name: "10-1-2-3.ip", Type: "AAAA", Zone: "ip", Source: "rules", Action: "ipnames", RCode: "NOERROR", LatencyMS: 1, Cache: "off", Path: "service"},
	}
}
