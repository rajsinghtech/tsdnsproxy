package grants

import (
	"strings"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
)

func TestParseRulesService(t *testing.T) {
	cfg, err := ParseRules([]byte(`{
		"app.example.com": {"service": "svc:app", "addrs": ["192.0.2.10", "2001:db8::10"], "ttl": 60},
		"db.example.com": {"service": "svc:db"},
	}`))
	if err != nil {
		t.Fatal(err)
	}
	app := cfg["app.example.com"]
	if app.Service != "svc:app" || app.ServiceTTL() != 60 {
		t.Fatalf("app = %+v ttl %d", app, app.ServiceTTL())
	}
	if got := app.ServiceAddrs(); len(got) != 2 || got[0].String() != "192.0.2.10" || got[1].String() != "2001:db8::10" {
		t.Fatalf("addrs = %v", got)
	}
	if got := cfg["db.example.com"].ServiceTTL(); got != DefaultServiceTTL {
		t.Fatalf("default ttl = %d", got)
	}
}

func TestServiceRejected(t *testing.T) {
	cases := map[string]struct{ doc, want string }{
		"no prefix":    {`{"app.example.com": {"service": "app"}}`, "must look like svc:<name>"},
		"empty name":   {`{"app.example.com": {"service": "svc:"}}`, "must look like svc:<name>"},
		"bad label":    {`{"app.example.com": {"service": "svc:bad_name"}}`, "must look like svc:<name>"},
		"rewrite":      {`{"app.example.com": {"service": "svc:app", "rewrite": "app.example.net"}}`, "combined with rewrite"},
		"static":       {`{"app.example.com": {"service": "svc:app", "static": {"a": ["192.0.2.1"]}}}`, "combined with static"},
		"ipnames":      {`{"app.example.com": {"service": "svc:app", "ipnames": {"siteid": 1}}}`, "combined with ipnames"},
		"zone":         {`{"app.example.com": {"service": "svc:app", "dns": ["192.0.2.53"], "translateid": 1, "zone": {}}}`, "combined with zone"},
		"dns":          {`{"app.example.com": {"service": "svc:app", "dns": ["192.0.2.53"]}}`, "combined with dns"},
		"translateid":  {`{"app.example.com": {"service": "svc:app", "translateid": 0}}`, "combined with translateid"},
		"allowips":     {`{"app.example.com": {"service": "svc:app", "allowips": ["100.64.0.0/10"]}}`, "combined with allowips"},
		"cidr key":     {`{"100.64.0.0/10": {"service": "svc:app"}}`, "CIDR key"},
		"wildcard key": {`{"*.example.com": {"service": "svc:app"}}`, "wildcard key"},
		"bad addr":     {`{"app.example.com": {"service": "svc:app", "addrs": ["app"]}}`, "not an IP"},
		"dup addr":     {`{"app.example.com": {"service": "svc:app", "addrs": ["192.0.2.1", "192.0.2.1"]}}`, "duplicate"},
		"zero addr":    {`{"app.example.com": {"service": "svc:app", "addrs": ["0.0.0.0"]}}`, "not usable"},
		"ttl low":      {`{"app.example.com": {"service": "svc:app", "ttl": 0}}`, "ttl 0"},
		"ttl high":     {`{"app.example.com": {"service": "svc:app", "ttl": 100000}}`, "ttl 100000"},
		"addrs alone":  {`{"app.example.com": {"dns": ["192.0.2.53"], "addrs": ["192.0.2.1"]}}`, "addrs requires service"},
		"ttl alone":    {`{"app.example.com": {"dns": ["192.0.2.53"], "ttl": 30}}`, "ttl requires service"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseRules([]byte(tc.doc))
			if err == nil {
				t.Fatal("rule was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestServiceMatchesExactName(t *testing.T) {
	cfg, err := ParseRules([]byte(`{
		"app.example.com": {"service": "svc:app"},
		"example.com": {"dns": ["192.0.2.53"]},
	}`))
	if err != nil {
		t.Fatal(err)
	}
	p := NewParser()
	domain, got, ok := p.FindBestMatch("app.example.com.", []GrantConfig{cfg})
	if !ok || domain != "app.example.com" || got.Service != "svc:app" {
		t.Fatalf("exact match = %q %+v", domain, got)
	}
	domain, got, ok = p.FindBestMatch("x.app.example.com", []GrantConfig{cfg})
	if !ok || domain != "example.com" || got.Service != "" {
		t.Fatalf("subdomain matched %q %+v", domain, got)
	}
}

func TestServiceGrantFromCap(t *testing.T) {
	p := NewParser()
	capMap := tailcfg.PeerCapMap{
		peercap.Cap(DefaultCapName): {
			tailcfg.RawMessage(`{"app.example.com": {"service": "svc:app"}}`),
			tailcfg.RawMessage(`{"bad.example.com": {"service": "app"}}`),
		},
	}
	cfgs, err := p.ParseGrants(capMap)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 1 || cfgs[0]["app.example.com"].Service != "svc:app" {
		t.Fatalf("grants = %+v", cfgs)
	}
}

func TestRulesCloneService(t *testing.T) {
	ttl := 45
	in := GrantConfig{"app.example.com": {Service: "svc:app", Addrs: []string{"192.0.2.1"}, TTL: &ttl}}
	out := cloneGrantConfig(in)
	out["app.example.com"].Addrs[0] = "192.0.2.2"
	*out["app.example.com"].TTL = 90
	if in["app.example.com"].Addrs[0] != "192.0.2.1" || *in["app.example.com"].TTL != 45 {
		t.Fatal("clone shares service fields")
	}
}
