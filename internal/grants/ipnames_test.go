package grants

import (
	"encoding/json"
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"
)

func TestIPNamesValidation(t *testing.T) {
	p := NewParser()
	valid := []string{
		`{"site-a.example":{"ipnames":{"siteid":1}}}`,
		`{"site-a.example":{"ipnames":{"siteid":0,"a":"never","ttl":300,"negttl":60}}}`,
		`{"site-b.example":{"ipnames":{"siteid":2,"a":"always","allowips":["10.0.0.0/8"]}}}`,
		`{"site-a.example":{"ipnames":{"siteid":3,"a":"direct","directsrc":["192.168.10.0/24"],"allowsrc":["192.0.2.0/24"]}}}`,
		`{"site-a.example":{"dns":["10.1.0.10:53"],"ipnames":{"siteid":1}}}`,
	}
	for _, raw := range valid {
		cfgs, err := parseOne(t, p, raw)
		if err != nil || len(cfgs) != 1 {
			t.Fatalf("%s: %v %#v", raw, err, cfgs)
		}
	}

	invalid := []string{
		`{"site-a.example":{"ipnames":{}}}`,
		`{"site-a.example":{"ipnames":{"siteid":65536}}}`,
		`{"site-a.example":{"ipnames":{"siteid":-1}}}`,
		`{"example":{"ipnames":{"siteid":1}}}`,
		`{".":{"ipnames":{"siteid":1}}}`,
		`{"site-a.example":{"rewrite":"other.example","ipnames":{"siteid":1}}}`,
		`{"site-a.example":{"translateid":1,"ipnames":{"siteid":1}}}`,
		`{"site-a.example":{"ipnames":{"siteid":1,"a":"sometimes"}}}`,
		`{"site-a.example":{"ipnames":{"siteid":1,"ttl":0}}}`,
		`{"site-a.example":{"ipnames":{"siteid":1,"ttl":86401}}}`,
		`{"site-a.example":{"ipnames":{"siteid":1,"negttl":0}}}`,
		`{"site-a.example":{"ipnames":{"siteid":1,"a":"direct"}}}`,
		`{"site-a.example":{"ipnames":{"siteid":1,"allowips":["bad"]}}}`,
		`{"10.0.0.0/8":{"ipnames":{"siteid":1}}}`,
	}
	for _, raw := range invalid {
		cfgs, err := parseOne(t, p, raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(cfgs) != 0 {
			t.Fatalf("expected drop for %s, got %#v", raw, cfgs)
		}
	}
}

func TestIPNamesDefaultsAndAccessors(t *testing.T) {
	p := NewParser()
	cfgs, err := parseOne(t, p, `{"site-a.example":{"ipnames":{"siteid":4,"a":"direct","directsrc":["192.0.2.0/24"],"allowsrc":["198.51.100.0/24"],"allowips":["10.0.0.0/8"]}}}`)
	if err != nil || len(cfgs) != 1 {
		t.Fatal(err, cfgs)
	}
	cfg := cfgs[0]["site-a.example"].IPNames
	id, err := cfg.SiteIDValue()
	if err != nil || id != 4 {
		t.Fatalf("site %d %v", id, err)
	}
	if cfg.AMode() != "direct" || cfg.AnswerTTL() != 300 || cfg.NegativeTTL() != 60 {
		t.Fatalf("defaults mode=%s ttl=%d neg=%d", cfg.AMode(), cfg.AnswerTTL(), cfg.NegativeTTL())
	}
	if cfg.SourceAllowed(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("source outside allowsrc")
	}
	if !cfg.SourceAllowed(netip.MustParseAddr("198.51.100.9")) {
		t.Fatal("source inside allowsrc")
	}
	if !cfg.AAllowed(netip.MustParseAddr("192.0.2.10")) || cfg.AAllowed(netip.MustParseAddr("198.51.100.9")) {
		t.Fatal("directsrc match")
	}
	if !cfg.EncodedAllowed(netip.MustParseAddr("10.1.2.3")) || cfg.EncodedAllowed(netip.MustParseAddr("11.0.0.1")) {
		t.Fatal("allowips")
	}
	if cfg.EncodedAllowed(netip.MustParseAddr("100.64.1.1")) {
		t.Fatal("built-in block should apply")
	}

	omitted, err := parseOne(t, p, `{"site-b.example":{"ipnames":{"siteid":1}}}`)
	if err != nil {
		t.Fatal(err)
	}
	bare := omitted[0]["site-b.example"].IPNames
	if bare.AMode() != "never" || bare.AAllowed(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("default a mode is never")
	}
	if !bare.SourceAllowed(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("empty allowsrc allows the source")
	}
	if !bare.EncodedAllowed(netip.MustParseAddr("192.0.2.1")) || bare.EncodedAllowed(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("default encoded policy")
	}
}

func TestIPNamesConflicts(t *testing.T) {
	p := NewParser()
	capMap := tailcfg.PeerCapMap{
		"rajsingh.info/cap/tsdnsproxy": []tailcfg.RawMessage{
			`{"zone-a.example":{"ipnames":{"siteid":1}},"other.example":{"dns":["10.0.0.1:53"]}}`,
			`{"zone-a.example":{"ipnames":{"siteid":2}}}`,
			`{"site-b.example":{"ipnames":{"siteid":3,"allowips":["10.0.0.0/8","192.168.0.0/16"]}}}`,
			`{"site-b.example":{"ipnames":{"siteid":3,"allowips":["192.168.0.0/16","10.0.0.0/8"]}}}`,
			`{"child.nest.example":{"ipnames":{"siteid":9}}}`,
			`{"nest.example":{"ipnames":{"siteid":8}}}`,
			`{"nested.example":{"ipnames":{"siteid":1}},"app.nested.example":{"dns":["10.2.0.1:53"],"translateid":-1}}`,
		},
	}
	cfgs, err := p.ParseGrants(capMap)
	if err != nil {
		t.Fatal(err)
	}
	zones := map[string]IPNamesConfig{}
	for _, cfg := range cfgs {
		for domain, grant := range cfg {
			if grant.IPNames != nil {
				zones[domain] = *grant.IPNames
			}
			if domain == "other.example" && len(grant.DNS) != 1 {
				t.Fatal("unrelated rule was dropped")
			}
			if domain == "app.nested.example" && grant.IPNames != nil {
				t.Fatal("normal rule should not be treated as ipnames")
			}
		}
	}
	if _, ok := zones["zone-a.example"]; ok {
		t.Fatal("conflicting zone-a.example should be dropped")
	}
	if _, ok := zones["child.nest.example"]; ok || func() bool { _, ok := zones["nest.example"]; return ok }() {
		t.Fatal("nested ipnames zones should be dropped")
	}
	if _, ok := zones["site-b.example"]; !ok {
		t.Fatal("identical site-b.example settings should be kept")
	}
	if _, ok := zones["nested.example"]; !ok {
		t.Fatal("ipnames nested only with a normal rule should be kept")
	}
}

func TestIPNamesDuplicateKeyKeepsLast(t *testing.T) {
	var cfg GrantConfig
	raw := `{"site-a.example":{"ipnames":{"siteid":1}},"site-a.example":{"ipnames":{"siteid":2}}}`
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	id, err := cfg["site-a.example"].IPNames.SiteIDValue()
	if err != nil || id != 2 {
		t.Fatalf("duplicate key kept %d %v", id, err)
	}
}

func parseOne(t *testing.T, p *Parser, raw string) ([]GrantConfig, error) {
	t.Helper()
	capMap := tailcfg.PeerCapMap{
		"rajsingh.info/cap/tsdnsproxy": []tailcfg.RawMessage{tailcfg.RawMessage(raw)},
	}
	return p.ParseGrants(capMap)
}
