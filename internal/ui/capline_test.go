package ui

import (
	"context"
	"io/fs"
	"net/netip"
	"strings"
	"testing"
)

func TestGrantedCapOnlyWhenItMatched(t *testing.T) {
	const (
		viewCap  = "example.com/cap/dns/ui"
		auditCap = "example.com/cap/dns/audit"
		dnsCap   = "example.com/cap/dns"
	)
	srv := &Server{
		Snapshot: func() Snapshot {
			return Snapshot{CapName: dnsCap, Version: "dev"}
		},
		ViewCap:           viewCap,
		AuditCap:          auditCap,
		ViewGroups:        []string{"dns-admins"},
		TrustedProxyTags:  []string{"tag:proxy"},
		TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		WhoIs: func(_ context.Context, ip string) (*Caller, error) {
			switch ip {
			case "198.51.100.10":
				return &Caller{Caps: []string{viewCap, auditCap}, Login: "alice@example.com"}, nil
			case "198.51.100.11":
				return &Caller{Login: "bob@example.com"}, nil
			case "198.51.100.12":
				return &Caller{Caps: []string{viewCap, auditCap}, Tags: []string{"tag:proxy"}, Node: "proxy"}, nil
			default:
				return nil, errDenied
			}
		},
	}
	h := srv.Handler()

	matched := call(h, "198.51.100.10:9", "/api/config")
	if matched.Code != 200 || !strings.Contains(matched.Body.String(), `"granted_cap":"`+viewCap+`"`) {
		t.Fatalf("site cap %d %s", matched.Code, matched.Body.String())
	}
	if !strings.Contains(matched.Body.String(), `"cap_name":"`+dnsCap+`"`) {
		t.Fatalf("cap name changed: %s", matched.Body.String())
	}
	audit := call(h, "198.51.100.10:9", "/api/queries")
	if audit.Code != 200 || !strings.Contains(audit.Body.String(), `"granted_cap":"`+auditCap+`"`) {
		t.Fatalf("audit cap %d %s", audit.Code, audit.Body.String())
	}

	open := &Server{
		Snapshot: func() Snapshot { return Snapshot{CapName: dnsCap} },
		WhoIs: func(context.Context, string) (*Caller, error) {
			return &Caller{Login: "alice@example.com"}, nil
		},
	}
	plain := call(open.Handler(), "198.51.100.10:9", "/api/config")
	if plain.Code != 200 || strings.Contains(plain.Body.String(), "granted_cap") {
		t.Fatalf("no cap configured %d %s", plain.Code, plain.Body.String())
	}
	if !strings.Contains(plain.Body.String(), `"cap_name":"`+dnsCap+`"`) {
		t.Fatalf("default cap name missing: %s", plain.Body.String())
	}

	tag := callHeaders(h, "198.51.100.12:9", "/api/config", map[string]string{
		"Tailscale-User-Login": "alice@example.com",
		"X-Tailscale-Groups":   "dns-admins",
	})
	if tag.Code != 200 || strings.Contains(tag.Body.String(), "granted_cap") || !strings.Contains(tag.Body.String(), `"via_proxy":true`) {
		t.Fatalf("tag proxy %d %s", tag.Code, tag.Body.String())
	}

	cidr := callHeaders(h, "192.0.2.10:9", "/api/config", map[string]string{
		"Tailscale-User-Login": "alice@example.com",
		"X-Tailscale-Groups":   "dns-admins",
	})
	if cidr.Code != 200 || strings.Contains(cidr.Body.String(), "granted_cap") || !strings.Contains(cidr.Body.String(), `"via_proxy":true`) {
		t.Fatalf("cidr proxy %d %s", cidr.Code, cidr.Body.String())
	}
}

func TestOverviewCapabilityLineUsesGrantedCap(t *testing.T) {
	data, err := fs.ReadFile(web, "web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(data)
	if strings.Contains(src, `["Capability", c.cap_name`) {
		t.Fatal("overview still always shows the configured capability")
	}
	if !strings.Contains(src, "c.viewer && c.viewer.granted_cap") || !strings.Contains(src, `["Capability", c.viewer.granted_cap]`) {
		t.Fatal("overview does not gate the Capability line on granted_cap")
	}
}
