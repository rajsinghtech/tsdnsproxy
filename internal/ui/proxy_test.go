package ui

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyIdentity(t *testing.T) {
	const (
		proxyIP  = "192.0.2.10"
		directIP = "192.0.2.1"
		otherIP  = "192.0.2.2"
		plainIP  = "192.0.2.3"
	)
	var logs []string
	srv := &Server{
		ViewCap:          "example.com/cap/dns",
		AuditCap:         "example.com/cap/dns/audit",
		ViewGroups:       []string{"dns-admins"},
		AuditGroups:      []string{"dns-auditors"},
		TrustedProxyTags: []string{"tag:proxy"},
		WhoIs: func(_ context.Context, ip string) (*Caller, error) {
			switch ip {
			case proxyIP:
				return &Caller{Caps: []string{"example.com/cap/dns", "example.com/cap/dns/audit"}, Tags: []string{"tag:proxy"}, Node: "proxy.example.ts.net"}, nil
			case directIP:
				return &Caller{Caps: []string{"example.com/cap/dns", "example.com/cap/dns/audit"}, Login: "alice@example.com", Node: "alice.example.ts.net"}, nil
			case otherIP:
				return &Caller{Caps: []string{"example.com/cap/dns"}, Login: "bob@example.com", Node: "bob.example.ts.net"}, nil
			case plainIP:
				return &Caller{Node: "plain.example.ts.net"}, nil
			default:
				return nil, errDenied
			}
		},
		Logf: func(format string, args ...any) {
			logs = append(logs, strings.TrimSpace(strings.ReplaceAll(fmt.Sprintf(format, args...), "\n", " ")))
		},
	}
	h := srv.Handler()

	spoof := callHeaders(h, otherIP+":9", "/api/queries", map[string]string{
		"Tailscale-User-Login": "mallory@example.com",
		"Tailscale-User-Name":  "Mallory",
		"X-Tailscale-Groups":   "dns-admins,dns-auditors",
	})
	if spoof.Code != http.StatusForbidden {
		t.Fatalf("spoofed audit status %d body %s", spoof.Code, spoof.Body.String())
	}
	if strings.Contains(spoof.Body.String(), "mallory") {
		t.Fatalf("spoofed header leaked: %s", spoof.Body.String())
	}
	spoofView := callHeaders(h, otherIP+":9", "/api/config", map[string]string{
		"Tailscale-User-Login": "mallory@example.com",
		"X-Tailscale-Groups":   "dns-admins",
	})
	if spoofView.Code != 200 || strings.Contains(spoofView.Body.String(), "mallory") {
		t.Fatalf("direct viewer followed a spoofed header: %d %s", spoofView.Code, spoofView.Body.String())
	}

	missing := callHeaders(h, proxyIP+":9", "/api/config", nil)
	if missing.Code != http.StatusForbidden {
		t.Fatalf("missing user header %d", missing.Code)
	}

	noGroup := callHeaders(h, proxyIP+":9", "/api/config", map[string]string{
		"Tailscale-User-Login": "alice@example.com",
		"Tailscale-User-Name":  "Alice",
		"X-Tailscale-Groups":   "dns-readers",
	})
	if noGroup.Code != http.StatusForbidden {
		t.Fatalf("group miss %d %s", noGroup.Code, noGroup.Body.String())
	}

	match := callHeaders(h, proxyIP+":9", "/api/config", map[string]string{
		"Tailscale-User-Login": "alice@example.com",
		"Tailscale-User-Name":  "Alice",
		"X-Tailscale-Groups":   "dns-admins",
	})
	if match.Code != 200 || !strings.Contains(match.Body.String(), `"via_proxy":true`) || !strings.Contains(match.Body.String(), "alice@example.com") {
		t.Fatalf("group match %d %s", match.Code, match.Body.String())
	}
	if strings.Contains(match.Body.String(), "mallory") {
		t.Fatal(match.Body.String())
	}

	auditMiss := callHeaders(h, proxyIP+":9", "/api/queries", map[string]string{
		"Tailscale-User-Login": "alice@example.com",
		"X-Tailscale-Groups":   "dns-admins",
	})
	if auditMiss.Code != http.StatusForbidden {
		t.Fatalf("audit group miss %d", auditMiss.Code)
	}
	auditHit := callHeaders(h, proxyIP+":9", "/api/access", map[string]string{
		"Tailscale-User-Login": "auditor@example.com",
		"Tailscale-User-Name":  "Auditor",
		"X-Tailscale-Groups":   "dns-auditors",
	})
	if auditHit.Code != 200 || !strings.Contains(auditHit.Body.String(), `"via_proxy":true`) || !strings.Contains(auditHit.Body.String(), "auditor@example.com") {
		t.Fatalf("audit group hit %d %s", auditHit.Code, auditHit.Body.String())
	}
	auditorConfig := callHeaders(h, proxyIP+":9", "/api/config", map[string]string{
		"Tailscale-User-Login": "auditor@example.com",
		"X-Tailscale-Groups":   "dns-auditors",
	})
	if auditorConfig.Code != http.StatusForbidden {
		t.Fatalf("audit group opened the site %d", auditorConfig.Code)
	}

	directCap := call(h, directIP+":9", "/api/config")
	if directCap.Code != 200 {
		t.Fatalf("direct cap %d", directCap.Code)
	}
	directAudit := call(h, directIP+":9", "/api/queries")
	if directAudit.Code != 200 || strings.Contains(directAudit.Body.String(), `"via_proxy":true`) {
		t.Fatalf("direct audit cap %d %s", directAudit.Code, directAudit.Body.String())
	}
	if strings.Contains(directCap.Body.String(), `"via_proxy":true`) {
		t.Fatalf("direct viewer marked via proxy: %s", directCap.Body.String())
	}
	directNoCap := call(h, plainIP+":9", "/api/config")
	if directNoCap.Code != http.StatusForbidden {
		t.Fatalf("direct without cap %d", directNoCap.Code)
	}

	logged := strings.Join(logs, "\n")
	if !strings.Contains(logged, "login=alice@example.com") || !strings.Contains(logged, "via proxy allowed") {
		t.Fatalf("log %q", logged)
	}
	if strings.Contains(logged, "mallory") {
		t.Fatalf("log recorded a spoofed user: %s", logged)
	}
}

func TestTrustedProxyRequiresUserHeader(t *testing.T) {
	const proxyIP = "192.0.2.10"
	srv := &Server{
		TrustedProxyTags: []string{"tag:proxy"},
		UserHeader:       "X-User",
		NameHeader:       "X-Name",
		GroupsHeader:     "X-Groups",
		WhoIs: func(_ context.Context, ip string) (*Caller, error) {
			switch ip {
			case proxyIP:
				return &Caller{Tags: []string{"tag:proxy"}, Node: "proxy"}, nil
			case "192.0.2.1":
				return &Caller{Login: "alice@example.com", Node: "alice"}, nil
			default:
				return nil, errDenied
			}
		},
	}
	h := srv.Handler()
	if call(h, proxyIP+":9", "/api/config").Code != http.StatusForbidden {
		t.Fatal("proxy without a user header was allowed")
	}
	ok := callHeaders(h, proxyIP+":9", "/api/peers", map[string]string{
		"X-User":               "alice@example.com",
		"X-Name":               "Alice",
		"X-Groups":             "dns-admins",
		"Tailscale-User-Login": "mallory@example.com",
	})
	if ok.Code != 200 || !strings.Contains(ok.Body.String(), `"via_proxy":true`) || !strings.Contains(ok.Body.String(), "alice@example.com") || strings.Contains(ok.Body.String(), "mallory") {
		t.Fatalf("custom headers %d %s", ok.Code, ok.Body.String())
	}
	direct := callHeaders(h, "192.0.2.1:9", "/api/config", map[string]string{
		"X-User": "mallory@example.com",
	})
	if direct.Code != 200 || strings.Contains(direct.Body.String(), "mallory") || !strings.Contains(direct.Body.String(), "alice@example.com") {
		t.Fatalf("direct %d %s", direct.Code, direct.Body.String())
	}
}

func TestGroupsWithoutProxyDenyDirectViewers(t *testing.T) {
	srv := &Server{
		ViewGroups: []string{"dns-admins"},
		WhoIs: func(_ context.Context, ip string) (*Caller, error) {
			if ip == "192.0.2.3" {
				return &Caller{Node: "plain.example.ts.net", Login: "plain@example.com"}, nil
			}
			return nil, errDenied
		},
	}
	if code := callHeaders(srv.Handler(), "192.0.2.3:9", "/api/config", map[string]string{
		"Tailscale-User-Login": "alice@example.com",
		"X-Tailscale-Groups":   "dns-admins",
	}).Code; code != http.StatusForbidden {
		t.Fatalf("direct group check %d", code)
	}
}

func TestUnsetProxyFlagsKeepCapChecks(t *testing.T) {
	srv := &Server{
		ViewCap:  "example.com/cap/dns",
		AuditCap: "example.com/cap/dns/audit",
		WhoIs: func(_ context.Context, ip string) (*Caller, error) {
			switch ip {
			case "192.0.2.1":
				return &Caller{Caps: []string{"example.com/cap/dns", "example.com/cap/dns/audit"}, Tags: []string{"tag:proxy"}}, nil
			case "192.0.2.2":
				return &Caller{Caps: []string{"example.com/cap/dns"}}, nil
			default:
				return nil, errDenied
			}
		},
	}
	h := srv.Handler()
	headers := map[string]string{
		"Tailscale-User-Login": "mallory@example.com",
		"X-Tailscale-Groups":   "dns-admins,dns-auditors",
	}
	if callHeaders(h, "192.0.2.2:9", "/api/queries", headers).Code != http.StatusForbidden {
		t.Fatal("audit cap changed")
	}
	cfg := callHeaders(h, "192.0.2.2:9", "/api/config", headers)
	if cfg.Code != 200 || strings.Contains(cfg.Body.String(), "mallory") {
		t.Fatalf("view cap %d %s", cfg.Code, cfg.Body.String())
	}
	peers := callHeaders(h, "192.0.2.1:9", "/api/peers", headers)
	if peers.Code != 200 || strings.Contains(peers.Body.String(), `"via_proxy":true`) || strings.Contains(peers.Body.String(), "mallory") {
		t.Fatalf("tags ignored until configured: %d %s", peers.Code, peers.Body.String())
	}
}

func callHeaders(h http.Handler, remote, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remote
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
