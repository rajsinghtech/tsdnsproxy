package grants

import (
	"strings"
	"testing"
	"time"
)

func TestParseRulesZone(t *testing.T) {
	cfg, err := ParseRules([]byte(`{
		// homelab zone
		"example.com": {
			"dns": ["tailnet://10.0.0.53"],
			"translateid": 7,
			"allowips": ["10.0.0.0/8"],
			"zone": {"fallback": ["direct://192.0.2.53"], "timeout": "750ms"},
		},
	}`))
	if err != nil {
		t.Fatal(err)
	}
	g := cfg["example.com"]
	if g.Zone == nil || len(g.Zone.Fallback) != 1 {
		t.Fatalf("zone = %+v", g.Zone)
	}
	if got := g.Zone.TimeoutValue(); got != 750*time.Millisecond {
		t.Fatalf("timeout = %v", got)
	}
}

func TestZoneDefaults(t *testing.T) {
	cfg, err := ParseRules([]byte(`{"example.com": {"dns": ["10.0.0.53"], "translateid": 1, "zone": {}}}`))
	if err != nil {
		t.Fatal(err)
	}
	g := cfg["example.com"]
	if got := g.Zone.TimeoutValue(); got != DefaultZoneTimeout {
		t.Fatalf("timeout = %v", got)
	}
	eff := g.ZoneGrant()
	if strings.Join(eff.AllowIPs, ",") != strings.Join(DefaultZonePrivate, ",") {
		t.Fatalf("allowips = %v", eff.AllowIPs)
	}
	if len(g.AllowIPs) != 0 {
		t.Fatal("ZoneGrant changed the rule")
	}
}

func TestZoneRejected(t *testing.T) {
	cases := map[string]string{
		"no dns":        `{"example.com": {"translateid": 1, "zone": {}}}`,
		"no translate":  `{"example.com": {"dns": ["10.0.0.53"], "zone": {}}}`,
		"translate 0":   `{"example.com": {"dns": ["10.0.0.53"], "translateid": 0, "zone": {}}}`,
		"rewrite":       `{"example.com": {"dns": ["10.0.0.53"], "translateid": 1, "rewrite": "example.internal", "zone": {}}}`,
		"cidr key":      `{"10.0.0.0/8": {"dns": ["10.0.0.53"], "translateid": 1, "zone": {}}}`,
		"bad timeout":   `{"example.com": {"dns": ["10.0.0.53"], "translateid": 1, "zone": {"timeout": "soon"}}}`,
		"long timeout":  `{"example.com": {"dns": ["10.0.0.53"], "translateid": 1, "zone": {"timeout": "30s"}}}`,
		"bad fallback":  `{"example.com": {"dns": ["10.0.0.53"], "translateid": 1, "zone": {"fallback": ["udp://192.0.2.53"]}}}`,
		"empty fallbck": `{"example.com": {"dns": ["10.0.0.53"], "translateid": 1, "zone": {"fallback": [""]}}}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRules([]byte(doc)); err == nil {
				t.Fatal("rule was accepted")
			}
		})
	}
}

func TestZoneGrantFromCap(t *testing.T) {
	siteThree := 3
	p := NewParser()
	g := GrantConfig{"example.com": {DNS: []string{"10.0.0.53"}, TranslateID: &siteThree, Zone: &ZoneConfig{}}}
	if err := p.validateGrant(g); err != nil {
		t.Fatal(err)
	}
	_, got, ok := p.FindBestMatch("deep.app.example.com", []GrantConfig{g})
	if !ok || got.Zone == nil {
		t.Fatal("zone rule did not match a subdomain")
	}
}
