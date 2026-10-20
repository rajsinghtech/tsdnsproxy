package ui

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

func TestTrustedCIDRProxy(t *testing.T) {
	var whoisCalls atomic.Int32
	srv := &Server{
		ViewGroups:        []string{"dns-admins"},
		AuditGroups:       []string{"dns-auditors"},
		TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("10.0.0.0/8")},
		WhoIs: func(context.Context, string) (*Caller, error) {
			whoisCalls.Add(1)
			return &Caller{Caps: []string{"example.com/cap/dns"}, Login: "alice@example.com", Node: "alice"}, nil
		},
	}
	h := srv.Handler()
	headers := map[string]string{
		"Tailscale-User-Login": "alice@example.com",
		"Tailscale-User-Name":  "Alice",
		"X-Tailscale-Groups":   "dns-admins",
	}

	outside := callLocal(h, "198.51.100.10:9", "/api/config", headers)
	if outside.Code != http.StatusForbidden {
		t.Fatalf("untrusted local status %d body %s", outside.Code, outside.Body.String())
	}
	if strings.Contains(outside.Body.String(), "alice@example.com") {
		t.Fatalf("untrusted local leaked a header: %s", outside.Body.String())
	}
	if whoisCalls.Load() != 0 {
		t.Fatalf("untrusted local called whois %d times", whoisCalls.Load())
	}

	missing := callLocal(h, "192.0.2.10:9", "/api/config", nil)
	if missing.Code != http.StatusForbidden || whoisCalls.Load() != 0 {
		t.Fatalf("missing header %d whois %d", missing.Code, whoisCalls.Load())
	}

	match := callLocal(h, "192.0.2.10:9", "/api/config", headers)
	if match.Code != 200 || !strings.Contains(match.Body.String(), `"via_proxy":true`) || !strings.Contains(match.Body.String(), "alice@example.com") {
		t.Fatalf("group match %d %s", match.Code, match.Body.String())
	}
	if whoisCalls.Load() != 0 {
		t.Fatalf("trusted cidr called whois %d times", whoisCalls.Load())
	}

	miss := callLocal(h, "10.1.2.3:9", "/api/config", map[string]string{
		"Tailscale-User-Login": "alice@example.com",
		"X-Tailscale-Groups":   "dns-readers",
	})
	if miss.Code != http.StatusForbidden {
		t.Fatalf("group miss %d %s", miss.Code, miss.Body.String())
	}

	auditMiss := callLocal(h, "192.0.2.10:9", "/api/queries", headers)
	if auditMiss.Code != http.StatusForbidden {
		t.Fatalf("audit group miss %d", auditMiss.Code)
	}
	auditHit := callLocal(h, "192.0.2.10:9", "/api/access", map[string]string{
		"Tailscale-User-Login": "auditor@example.com",
		"X-Tailscale-Groups":   "dns-auditors",
	})
	if auditHit.Code != 200 || !strings.Contains(auditHit.Body.String(), "auditor@example.com") || !strings.Contains(auditHit.Body.String(), `"via_proxy":true`) {
		t.Fatalf("audit hit %d %s", auditHit.Code, auditHit.Body.String())
	}
}

func TestTailnetPathIgnoresHeadersWhenOutsideCIDR(t *testing.T) {
	var whoisCalls atomic.Int32
	srv := &Server{
		ViewCap:           "example.com/cap/dns",
		TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		WhoIs: func(_ context.Context, ip string) (*Caller, error) {
			whoisCalls.Add(1)
			if ip != "198.51.100.20" {
				t.Errorf("whois ip %s", ip)
			}
			return &Caller{Caps: []string{"example.com/cap/dns"}, Login: "alice@example.com", Node: "alice"}, nil
		},
	}
	h := srv.Handler()
	got := callHeaders(h, "198.51.100.20:9", "/api/config", map[string]string{
		"Tailscale-User-Login": "mallory@example.com",
		"X-Tailscale-Groups":   "dns-admins",
	})
	if got.Code != 200 || strings.Contains(got.Body.String(), "mallory") || !strings.Contains(got.Body.String(), "alice@example.com") || strings.Contains(got.Body.String(), `"via_proxy":true`) {
		t.Fatalf("tailnet %d %s", got.Code, got.Body.String())
	}
	if whoisCalls.Load() != 1 {
		t.Fatalf("whois calls %d", whoisCalls.Load())
	}

	localSpoof := callLocal(h, "198.51.100.20:9", "/api/config", map[string]string{
		"Tailscale-User-Login": "alice@example.com",
	})
	if localSpoof.Code != http.StatusForbidden || whoisCalls.Load() != 1 {
		t.Fatalf("local outside cidr %d whois %d", localSpoof.Code, whoisCalls.Load())
	}
}

func TestEmptyGroupsAllowTrustedCIDR(t *testing.T) {
	srv := &Server{
		TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		WhoIs: func(context.Context, string) (*Caller, error) {
			t.Fatal("whois should not run")
			return nil, nil
		},
	}
	got := callLocal(srv.Handler(), "192.0.2.8:9", "/api/config", map[string]string{
		"Tailscale-User-Login": "alice@example.com",
	})
	if got.Code != 200 || !strings.Contains(got.Body.String(), "alice@example.com") {
		t.Fatalf("empty groups %d %s", got.Code, got.Body.String())
	}
}

func TestHealthzIsOpen(t *testing.T) {
	var whoisCalls atomic.Int32
	srv := &Server{
		ViewCap:           "example.com/cap/dns",
		TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		WhoIs: func(context.Context, string) (*Caller, error) {
			whoisCalls.Add(1)
			return nil, errDenied
		},
	}
	h := srv.Handler()
	for _, remote := range []string{"198.51.100.10:9", "10.0.0.4:9"} {
		res := callLocal(h, remote, "/healthz", map[string]string{"Tailscale-User-Login": "alice@example.com"})
		if res.Code != 200 || res.Body.Len() != 0 {
			t.Fatalf("healthz %s %d %q", remote, res.Code, res.Body.String())
		}
	}
	if whoisCalls.Load() != 0 {
		t.Fatalf("healthz called whois %d times", whoisCalls.Load())
	}
	head := httptest.NewRequest(http.MethodHead, "/healthz", nil)
	head.RemoteAddr = "198.51.100.10:9"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, head)
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("head %d %q", rec.Code, rec.Body.String())
	}
}

func TestServeLocalRejectsUntrustedAddress(t *testing.T) {
	srv := &Server{
		TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		WhoIs: func(context.Context, string) (*Caller, error) {
			t.Fatal("whois should not run")
			return nil, nil
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- srv.ServeLocal(ctx, func() (net.Listener, error) { return ln, nil })
	}()
	base := "http://" + ln.Addr().String()
	health, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(health.Body)
	health.Body.Close()
	if health.StatusCode != 200 || len(body) != 0 {
		t.Fatalf("healthz %d %q", health.StatusCode, body)
	}
	req, err := http.NewRequest(http.MethodGet, base+"/api/config", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Tailscale-User-Login", "alice@example.com")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("config %d", res.StatusCode)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func callLocal(h http.Handler, remote, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remote
	req = req.WithContext(markLocal(req.Context()))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
