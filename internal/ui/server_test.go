package ui

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIShapeRedactionAndGating(t *testing.T) {
	ring := NewRing(4)
	ring.Add(Query{Name: "tskey-auth-secret.example.internal", Node: "a.example.ts.net", PeerIP: "100.64.0.2", RCode: "NOERROR"})
	var forwarded bool
	srv := &Server{
		Snapshot: func() Snapshot {
			return Snapshot{
				Version:   "dev",
				CapName:   "example.com/cap/dns",
				Rules:     []Rule{{Domain: "example.internal", Source: "rules", Backends: []string{"10.0.0.53:53"}}},
				Caches:    Caches{Answer: CacheStat{Enabled: true, Entries: 1, Limit: 10, Hits: 3}},
				Service:   Service{Name: "svc:dns", Port: 53, State: "listening"},
				Listeners: []Listener{{Proto: "udp", Addr: ":53", State: "listening"}},
				Backends:  []Backend{{Address: "10.0.0.53:53", Mode: "tailnet", Healthy: true}},
			}
		},
		Peers: func() []Peer {
			return []Peer{{
				ID:    "a.example.ts.net",
				Node:  "a.example.ts.net",
				Caps:  []string{`{"token":"tskey-auth-zzzz"}`},
				Rules: []Rule{{Domain: "example.internal", Source: "grant"}},
			}}
		},
		History:  ring,
		ViewCap:  "example.com/cap/dns",
		AuditCap: "example.com/cap/dns/audit",
		WhoIs: func(_ context.Context, ip string) ([]string, error) {
			switch ip {
			case "192.0.2.1":
				return []string{"example.com/cap/dns", "example.com/cap/dns/audit"}, nil
			case "192.0.2.2":
				return []string{"example.com/cap/dns"}, nil
			default:
				return nil, errDenied
			}
		},
		Lookup: func(_ context.Context, req LookupRequest) (Lookup, error) {
			forwarded = req.Forward
			return Lookup{Name: req.Name, Type: req.Type, Peer: req.Peer, Matched: true, Forwarded: req.Forward, Rule: &Rule{Domain: "example.internal", Source: "grant"}}, nil
		},
	}
	h := srv.Handler()

	deny := call(h, "192.0.2.9:9", "/api/config")
	if deny.Code != http.StatusForbidden {
		t.Fatalf("unknown peer %d", deny.Code)
	}
	cfg := call(h, "192.0.2.1:9", "/api/config")
	if cfg.Code != 200 {
		t.Fatalf("config %d %s", cfg.Code, cfg.Body.String())
	}
	if !strings.Contains(cfg.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatal("missing security header")
	}
	var snap map[string]any
	if err := json.Unmarshal(cfg.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "cap_name", "rules", "caches", "listeners", "backends", "service", "uptime_sec", "history_enabled"} {
		if _, ok := snap[key]; !ok {
			t.Fatalf("missing %s in %s", key, cfg.Body.String())
		}
	}
	if strings.Contains(cfg.Body.String(), "auth-key") || strings.Contains(cfg.Body.String(), "TS_AUTHKEY") {
		t.Fatal("config mentioned an auth key")
	}

	limited := call(h, "192.0.2.2:9", "/api/queries")
	if limited.Code != http.StatusForbidden {
		t.Fatalf("audit %d", limited.Code)
	}
	if call(h, "192.0.2.2:9", "/api/config").Code != 200 {
		t.Fatal("view cap should see config")
	}
	queries := call(h, "192.0.2.1:9", "/api/queries")
	if queries.Code != 200 {
		t.Fatal(queries.Body.String())
	}
	if strings.Contains(queries.Body.String(), "tskey-auth-secret") {
		t.Fatalf("query leaked a key: %s", queries.Body.String())
	}
	peers := call(h, "192.0.2.1:9", "/api/peers")
	if strings.Contains(peers.Body.String(), "zzzz") || !strings.Contains(peers.Body.String(), "tskey-redacted") {
		t.Fatalf("caps %s", peers.Body.String())
	}
	post := httptest.NewRequest(http.MethodPost, "/api/config", nil)
	post.RemoteAddr = "192.0.2.1:9"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, post)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("post %d", rec.Code)
	}

	dry := call(h, "192.0.2.1:9", "/api/lookup?name=app.example.internal&type=A&peer=100.64.0.2")
	if dry.Code != 200 || forwarded {
		t.Fatalf("dry status %d forwarded %v body %s", dry.Code, forwarded, dry.Body.String())
	}
	live := call(h, "192.0.2.1:9", "/api/lookup?name=app.example.internal&type=AAAA&peer=100.64.0.2&forward=1")
	if live.Code != 200 || !forwarded {
		t.Fatalf("forward status %d forwarded %v", live.Code, forwarded)
	}
	page := call(h, "192.0.2.1:9", "/")
	body, _ := io.ReadAll(page.Result().Body)
	if !strings.Contains(string(body), "Overview") || strings.Contains(string(body), "http://") || strings.Contains(string(body), "https://") {
		t.Fatalf("page %s", body)
	}
}

var errDenied = errString("denied")

type errString string

func (e errString) Error() string { return string(e) }

func call(h http.Handler, remote, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
