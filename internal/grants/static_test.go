package grants

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rajsinghtech/tsdnsproxy/internal/cidr"
)

func TestStaticMatch(t *testing.T) {
	p := NewParser()
	apex := true
	noApex := false
	base := GrantConfig{
		"app.example.internal":        {Static: &StaticConfig{A: []string{"192.0.2.10"}}},
		"*.apps.example.internal":     {Static: &StaticConfig{A: []string{"192.0.2.20"}, Apex: &noApex}},
		"*.svc.apps.example.internal": {Static: &StaticConfig{A: []string{"192.0.2.30"}}},
		"example.internal":            {DNS: []string{"10.0.0.53:53"}},
	}
	withApex := GrantConfig{
		"*.apps.example.internal": {Static: &StaticConfig{A: []string{"192.0.2.20"}, Apex: &apex}},
		"apps.example.internal":   {Static: &StaticConfig{A: []string{"192.0.2.21"}}},
	}

	tests := []struct {
		name   string
		query  string
		grants []GrantConfig
		want   string
		found  bool
	}{
		{name: "exact", query: "app.example.internal", grants: []GrantConfig{base}, want: "app.example.internal", found: true},
		{name: "exact case and dot", query: "App.Example.Internal.", grants: []GrantConfig{base}, want: "app.example.internal", found: true},
		{name: "exact does not match child", query: "foo.app.example.internal", grants: []GrantConfig{base}, want: "example.internal", found: true},
		{name: "wildcard one label", query: "foo.apps.example.internal", grants: []GrantConfig{base}, want: "*.apps.example.internal", found: true},
		{name: "wildcard case and dot", query: "Foo.Apps.Example.Internal.", grants: []GrantConfig{base}, want: "*.apps.example.internal", found: true},
		{name: "wildcard misses apex", query: "apps.example.internal", grants: []GrantConfig{base}, want: "example.internal", found: true},
		{name: "wildcard misses two labels", query: "a.b.apps.example.internal", grants: []GrantConfig{base}, want: "example.internal", found: true},
		{name: "longer wildcard wins", query: "db.svc.apps.example.internal", grants: []GrantConfig{base}, want: "*.svc.apps.example.internal", found: true},
		{name: "exact beats wildcard", query: "foo.apps.example.internal", grants: []GrantConfig{base, {"foo.apps.example.internal": {Static: &StaticConfig{A: []string{"192.0.2.40"}}}}}, want: "foo.apps.example.internal", found: true},
		{name: "apex option", query: "apps.example.internal", grants: []GrantConfig{withApex}, want: "apps.example.internal", found: true},
		{name: "apex option loses to exact", query: "Apps.Example.Internal.", grants: []GrantConfig{withApex}, want: "apps.example.internal", found: true},
		{name: "apex option still matches one label", query: "foo.apps.example.internal", grants: []GrantConfig{withApex}, want: "*.apps.example.internal", found: true},
		{name: "no rule", query: "other.example", grants: []GrantConfig{base}, found: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _, found := p.FindBestMatch(tc.query, tc.grants)
			if found != tc.found || got != tc.want {
				t.Fatalf("FindBestMatch(%q) = %q, %v; want %q, %v", tc.query, got, found, tc.want, tc.found)
			}
		})
	}
}

func TestStaticConfigValidation(t *testing.T) {
	ok := []string{
		`{"app.example.internal.":{"static":{"a":["192.0.2.10"],"aaaa":["2001:db8::10"],"ttl":60}}}`,
		`{"*.Apps.Example.Internal":{"static":{"a":["10.1.2.3"],"ttl":1,"apex":true,"allowsrc":["192.0.2.0/24"]}}}`,
		`{"app.example.internal":{"static":{"aaaa":["2001:db8::10"]}}}`,
	}
	for _, body := range ok {
		cfg, err := ParseRules([]byte(body))
		if err != nil {
			t.Fatalf("ParseRules(%s): %v", body, err)
		}
		if len(cfg) != 1 {
			t.Fatalf("rules = %d", len(cfg))
		}
	}

	bad := []struct {
		name string
		body string
		want string
	}{
		{name: "bad a", body: `{"app.example.internal":{"static":{"a":["nope"]}}}`, want: "not an IP"},
		{name: "a is v6", body: `{"app.example.internal":{"static":{"a":["2001:db8::1"]}}}`, want: "not IPv4"},
		{name: "aaaa is v4", body: `{"app.example.internal":{"static":{"aaaa":["192.0.2.1"]}}}`, want: "not IPv6"},
		{name: "mapped", body: `{"app.example.internal":{"static":{"aaaa":["::ffff:192.0.2.1"]}}}`, want: "not IPv6"},
		{name: "unspecified", body: `{"app.example.internal":{"static":{"a":["0.0.0.0"]}}}`, want: "not usable"},
		{name: "multicast", body: `{"app.example.internal":{"static":{"aaaa":["ff02::1"]}}}`, want: "not usable"},
		{name: "duplicate", body: `{"app.example.internal":{"static":{"a":["192.0.2.10","192.0.2.10"]}}}`, want: "duplicate"},
		{name: "empty addr", body: `{"app.example.internal":{"static":{"a":[""]}}}`, want: "empty"},
		{name: "no addr", body: `{"app.example.internal":{"static":{}}}`, want: "needs an a or aaaa"},
		{name: "ttl low", body: `{"app.example.internal":{"static":{"a":["192.0.2.10"],"ttl":0}}}`, want: "outside 1-86400"},
		{name: "ttl high", body: `{"app.example.internal":{"static":{"a":["192.0.2.10"],"ttl":86401}}}`, want: "outside 1-86400"},
		{name: "bad allowsrc", body: `{"app.example.internal":{"static":{"a":["192.0.2.10"],"allowsrc":["nope"]}}}`, want: "allowsrc"},
		{name: "star", body: `{"*":{"static":{"a":["192.0.2.10"]}}}`, want: "invalid"},
		{name: "double star", body: `{"*.*.example.internal":{"static":{"a":["192.0.2.10"]}}}`, want: "invalid wildcard"},
		{name: "mid star", body: `{"foo.*.example.internal":{"static":{"a":["192.0.2.10"]}}}`, want: "invalid"},
		{name: "glued star", body: `{"*apps.example.internal":{"static":{"a":["192.0.2.10"]}}}`, want: "invalid"},
		{name: "apex on exact", body: `{"app.example.internal":{"static":{"a":["192.0.2.10"],"apex":true}}}`, want: "apex is only valid"},
		{name: "with dns", body: `{"app.example.internal":{"dns":["10.0.0.53:53"],"static":{"a":["192.0.2.10"]}}}`, want: "combined with dns"},
		{name: "with rewrite", body: `{"app.example.internal":{"rewrite":"svc.example","static":{"a":["192.0.2.10"]}}}`, want: "combined with rewrite"},
		{name: "with translate", body: `{"app.example.internal":{"translateid":1,"static":{"a":["192.0.2.10"]}}}`, want: "combined with translateid"},
		{name: "with ipnames", body: `{"app.example.internal":{"ipnames":{"siteid":1},"static":{"a":["192.0.2.10"]}}}`, want: "combined with ipnames"},
		{name: "wildcard without static", body: `{"*.apps.example.internal":{"dns":["10.0.0.53:53"]}}`, want: "requires static"},
		{name: "cidr", body: `{"10.0.0.0/8":{"static":{"a":["192.0.2.10"]}}}`, want: "CIDR"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRules([]byte(tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestStaticPreparedValues(t *testing.T) {
	cfg, err := ParseRules([]byte(`{
		"App.Example.Internal.": {"static": {"a": ["192.0.2.10", "192.0.2.11"], "aaaa": ["2001:db8::10"], "ttl": 60, "allowsrc": ["192.0.2.0/24"]}},
		"*.apps.example.internal": {"static": {"aaaa": ["2001:db8::20"], "apex": true}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	exact := cfg["app.example.internal"].Static
	policy := cidr.Policy{ApplyDefaults: true}
	if exact == nil || exact.AnswerTTL() != 60 || len(exact.ARecords(policy)) != 2 {
		t.Fatalf("exact = %+v", exact)
	}
	if got := exact.AAAARecords(nil); len(got) != 1 || got[0] != netip.MustParseAddr("2001:db8::10") {
		t.Fatalf("aaaa = %v", got)
	}
	if !exact.SourceAllowed(netip.MustParseAddr("192.0.2.10")) || exact.SourceAllowed(netip.MustParseAddr("198.51.100.10")) {
		t.Fatal("allowsrc")
	}
	wild := cfg["*.apps.example.internal"].Static
	if wild == nil || !wild.ApexEnabled() || wild.AnswerTTL() != defaultStaticTTL {
		t.Fatalf("wildcard ttl/apex = %d %v", wild.AnswerTTL(), wild.ApexEnabled())
	}
	blocked := cidr.Policy{ApplyDefaults: true}
	loop, err := ParseRules([]byte(`{"app.example.internal":{"static":{"a":["127.0.0.1"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(loop["app.example.internal"].Static.ARecords(blocked)) != 0 {
		t.Fatal("loopback A was not filtered")
	}
	covered := cidr.Policy{Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, ApplyDefaults: true}
	if len(loop["app.example.internal"].Static.ARecords(covered)) != 1 {
		t.Fatal("allowips did not cover loopback")
	}
}
