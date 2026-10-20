package dns

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/cache"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"github.com/rajsinghtech/tsdnsproxy/internal/ui"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

func TestStaticAnswers(t *testing.T) {
	src := netip.MustParseAddr("192.0.2.10")
	other := netip.MustParseAddr("198.51.100.10")
	rules := `{
		"app.example.internal": {
			"static": {"a": ["192.0.2.10", "192.0.2.11"], "aaaa": ["2001:db8::10"], "ttl": 60}
		},
		"v6.example.internal": {"static": {"aaaa": ["2001:db8::20"], "ttl": 30}},
		"*.apps.example.internal": {"static": {"a": ["192.0.2.20"], "ttl": 15, "allowsrc": ["192.0.2.0/24"]}},
		"*.apex.example.internal": {"static": {"a": ["192.0.2.30"], "ttl": 15, "apex": true}},
		"kept.example.internal": {
			"static": {"a": ["192.0.2.40", "192.0.2.41"], "ttl": 60},
			"denyips": ["192.0.2.41/32"]
		},
		"loop.example.internal": {"static": {"a": ["127.0.0.1"], "ttl": 60}},
		"open.example.internal": {
			"static": {"a": ["127.0.0.1"], "ttl": 60},
			"allowips": ["127.0.0.1/32"]
		},
		"example.internal": {"dns": ["10.0.0.53:53"], "translateid": -1}
	}`
	cfgs := mustStaticRules(t, rules)

	tests := []struct {
		name    string
		qname   string
		qtype   dnsmessage.Type
		src     netip.Addr
		rcode   dnsmessage.RCode
		answers []string
		nodata  bool
		soa     string
		calls   int32
	}{
		{name: "exact a", qname: "App.Example.Internal.", qtype: dnsmessage.TypeA, src: src, rcode: dnsmessage.RCodeSuccess, answers: []string{"192.0.2.10", "192.0.2.11"}},
		{name: "exact aaaa", qname: "app.example.internal.", qtype: dnsmessage.TypeAAAA, src: src, rcode: dnsmessage.RCodeSuccess, answers: []string{"2001:db8::10"}},
		{name: "mx nodata", qname: "app.example.internal.", qtype: dnsmessage.TypeMX, src: src, rcode: dnsmessage.RCodeSuccess, nodata: true, soa: "app.example.internal."},
		{name: "txt nodata", qname: "app.example.internal.", qtype: dnsmessage.TypeTXT, src: src, rcode: dnsmessage.RCodeSuccess, nodata: true, soa: "app.example.internal."},
		{name: "a when only aaaa", qname: "v6.example.internal.", qtype: dnsmessage.TypeA, src: src, rcode: dnsmessage.RCodeSuccess, nodata: true, soa: "v6.example.internal."},
		{name: "wildcard", qname: "foo.apps.example.internal.", qtype: dnsmessage.TypeA, src: src, rcode: dnsmessage.RCodeSuccess, answers: []string{"192.0.2.20"}},
		{name: "wildcard nodata aaaa", qname: "foo.apps.example.internal.", qtype: dnsmessage.TypeAAAA, src: src, rcode: dnsmessage.RCodeSuccess, nodata: true, soa: "apps.example.internal."},
		{name: "wildcard apex miss", qname: "apps.example.internal.", qtype: dnsmessage.TypeA, src: src, rcode: dnsmessage.RCodeSuccess, answers: []string{"10.0.0.1"}, calls: 1},
		{name: "multi label miss", qname: "a.b.apps.example.internal.", qtype: dnsmessage.TypeA, src: src, rcode: dnsmessage.RCodeSuccess, answers: []string{"10.0.0.1"}, calls: 1},
		{name: "apex option", qname: "apex.example.internal.", qtype: dnsmessage.TypeA, src: src, rcode: dnsmessage.RCodeSuccess, answers: []string{"192.0.2.30"}},
		{name: "allowsrc miss", qname: "foo.apps.example.internal.", qtype: dnsmessage.TypeA, src: other, rcode: dnsmessage.RCodeRefused},
		{name: "denyips", qname: "kept.example.internal.", qtype: dnsmessage.TypeA, src: src, rcode: dnsmessage.RCodeSuccess, answers: []string{"192.0.2.40"}},
		{name: "blocked a", qname: "loop.example.internal.", qtype: dnsmessage.TypeA, src: src, rcode: dnsmessage.RCodeSuccess, nodata: true, soa: "loop.example.internal."},
		{name: "allowips covers blocked", qname: "open.example.internal.", qtype: dnsmessage.TypeA, src: src, rcode: dnsmessage.RCodeSuccess, answers: []string{"127.0.0.1"}},
		{name: "child of exact falls through", qname: "extra.app.example.internal.", qtype: dnsmessage.TypeA, src: src, rcode: dnsmessage.RCodeSuccess, answers: []string{"10.0.0.1"}, calls: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := staticServer(t, &calls)
			msg := staticQuery(tc.qname, tc.qtype)
			raw, err := server.processQuery(context.Background(), msg, cfgs, tc.src)
			if err != nil {
				t.Fatal(err)
			}
			got := unpackStatic(t, raw)
			if got.RCode != tc.rcode {
				t.Fatalf("rcode %v, want %v", got.RCode, tc.rcode)
			}
			if tc.calls == 0 && !got.Authoritative {
				t.Fatal("static answer was not authoritative")
			}
			if tc.nodata {
				if len(got.Answers) != 0 || len(got.Authorities) != 1 {
					t.Fatalf("answers %d auth %d", len(got.Answers), len(got.Authorities))
				}
				soa, ok := got.Authorities[0].Body.(*dnsmessage.SOAResource)
				if !ok || got.Authorities[0].Header.Name.String() != tc.soa || soa.MinTTL == 0 {
					t.Fatalf("soa name %s min %d", got.Authorities[0].Header.Name, soaMin(soa))
				}
			}
			if tc.answers != nil && !sameAnswers(t, got, tc.answers) {
				t.Fatalf("answers %v", answerText(t, got))
			}
			if calls.Load() != tc.calls {
				t.Fatalf("upstream calls %d, want %d", calls.Load(), tc.calls)
			}
		})
	}
}

func TestStaticExactBeatsZone(t *testing.T) {
	var calls atomic.Int32
	server := staticServer(t, &calls)
	cfgs := mustStaticRules(t, `{
		"example.internal": {"dns": ["10.0.0.53:53"], "translateid": -1},
		"app.example.internal": {"static": {"a": ["192.0.2.10"], "ttl": 60}}
	}`)
	raw, err := server.processQuery(context.Background(), staticQuery("app.example.internal.", dnsmessage.TypeA), cfgs, netip.MustParseAddr("192.0.2.8"))
	if err != nil {
		t.Fatal(err)
	}
	got := unpackStatic(t, raw)
	if !sameAnswers(t, got, []string{"192.0.2.10"}) || calls.Load() != 0 {
		t.Fatalf("answers %v calls %d", answerText(t, got), calls.Load())
	}
	zone, action, _, backend, _, _ := describeMatch(server.GrantParser, cfgs, "app.example.internal.")
	if zone != "app.example.internal" || action != "static" || backend != "" {
		t.Fatalf("describe %s %s %q", zone, action, backend)
	}
	rule := ruleFrom(zone, cfgs[0]["app.example.internal"], "rules")
	if rule.Static == nil || rule.Static.TTL != 60 || len(rule.Static.A) != 1 {
		t.Fatalf("rule %+v", rule.Static)
	}
}

func TestStaticAnswerCache(t *testing.T) {
	var calls atomic.Int32
	server := staticServer(t, &calls)
	clk := newTestClock(time.Unix(1_700_000_000, 0))
	server.answers = newAnswerCache(16, time.Second, time.Hour, nil)
	server.answers.now = clk.now
	cfgs := mustStaticRules(t, `{
		"app.example.internal": {"static": {"a": ["192.0.2.10"], "ttl": 60, "allowsrc": ["192.0.2.0/24"]}},
		"v6.example.internal": {"static": {"aaaa": ["2001:db8::20"], "ttl": 30}}
	}`)
	src := netip.MustParseAddr("192.0.2.10")
	other := netip.MustParseAddr("198.51.100.10")

	first, hit, err := server.resolveCached(context.Background(), staticQuery("app.example.internal.", dnsmessage.TypeA), cfgs, src)
	if err != nil || hit {
		t.Fatalf("first hit %v err %v", hit, err)
	}
	if !sameAnswers(t, unpackStatic(t, first), []string{"192.0.2.10"}) {
		t.Fatal(answerText(t, unpackStatic(t, first)))
	}
	refused, _, err := server.resolveCached(context.Background(), staticQuery("app.example.internal.", dnsmessage.TypeA), cfgs, other)
	if err != nil {
		t.Fatal(err)
	}
	if unpackStatic(t, refused).RCode != dnsmessage.RCodeRefused {
		t.Fatal("denied client reused the allowed answer")
	}
	clk.add(10 * time.Second)
	again, hit, err := server.resolveCached(context.Background(), staticQuery("app.example.internal.", dnsmessage.TypeA), cfgs, src)
	if err != nil || !hit {
		t.Fatalf("second hit %v err %v", hit, err)
	}
	msg := unpackStatic(t, again)
	if msg.Answers[0].Header.TTL != 50 || calls.Load() != 0 {
		t.Fatalf("ttl %d calls %d", msg.Answers[0].Header.TTL, calls.Load())
	}

	_, _, err = server.resolveCached(context.Background(), staticQuery("v6.example.internal.", dnsmessage.TypeA), cfgs, src)
	if err != nil {
		t.Fatal(err)
	}
	_, hit, err = server.resolveCached(context.Background(), staticQuery("v6.example.internal.", dnsmessage.TypeA), cfgs, src)
	if err != nil || !hit {
		t.Fatalf("nodata hit %v err %v", hit, err)
	}
	nodata := unpackStatic(t, mustRaw(t, server, cfgs, "v6.example.internal.", dnsmessage.TypeA, src))
	if len(nodata.Answers) != 0 || len(nodata.Authorities) != 1 {
		t.Fatalf("cached nodata answers %d auth %d", len(nodata.Answers), len(nodata.Authorities))
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream calls %d", calls.Load())
	}
}

func TestStaticLookupDryRun(t *testing.T) {
	var calls atomic.Int32
	server := staticServer(t, &calls)
	server.LocalClient = &mockLocalClient{whoisFunc: func(context.Context, string) (*apitype.WhoIsResponse, error) {
		return &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "a.example.ts.net"},
			CapMap: tailcfg.PeerCapMap{
				grants.DefaultCapName: {tailcfg.RawMessage(`{"app.example.internal":{"static":{"a":["192.0.2.10"],"ttl":60}}}`)},
			},
		}, nil
	}}
	server.WhoisCache = cache.NewWhoisCache(time.Minute)
	server.GrantCache = cache.NewGrantCache(time.Minute)
	t.Cleanup(func() {
		server.WhoisCache.Close()
		server.GrantCache.Close()
	})
	got, err := server.Explain(context.Background(), ui.LookupRequest{
		Name: "app.example.internal", Type: "A", Peer: "192.0.2.10",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Matched || got.Forwarded || got.Rule == nil || got.Rule.Static == nil || got.Rule.Static.A[0] != "192.0.2.10" {
		t.Fatalf("%+v", got)
	}
	if calls.Load() != 0 {
		t.Fatalf("dry run calls %d", calls.Load())
	}
	got, err = server.Explain(context.Background(), ui.LookupRequest{
		Name: "app.example.internal", Type: "MX", Peer: "192.0.2.10", Forward: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Forwarded || got.RCode != "NOERROR" || len(got.Answers) != 0 || calls.Load() != 0 {
		t.Fatalf("%+v calls %d", got, calls.Load())
	}
}

func staticServer(t *testing.T, calls *atomic.Int32) *Server {
	t.Helper()
	return &Server{
		GrantParser: grants.NewParser(),
		BackendMgr: &mockBackendManager{backend: &mockBackend{queryFunc: func(context.Context, []byte) ([]byte, error) {
			calls.Add(1)
			return packedA(1, "unused.example.internal.", 30, [4]byte{10, 0, 0, 1}), nil
		}}},
		Logf: t.Logf,
	}
}

func mustStaticRules(t *testing.T, body string) []grants.GrantConfig {
	t.Helper()
	cfg, err := grants.ParseRules([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return []grants.GrantConfig{cfg}
}

func staticQuery(name string, qtype dnsmessage.Type) *dnsmessage.Message {
	return &dnsmessage.Message{
		Header: dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name: dnsmessage.MustNewName(name), Type: qtype, Class: dnsmessage.ClassINET,
		}},
	}
}

func unpackStatic(t *testing.T, raw []byte) *dnsmessage.Message {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		t.Fatal(err)
	}
	return &msg
}

func sameAnswers(t *testing.T, msg *dnsmessage.Message, want []string) bool {
	t.Helper()
	got := answerText(t, msg)
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func answerText(t *testing.T, msg *dnsmessage.Message) []string {
	t.Helper()
	_, lines := answerLines(mustPack(t, msg))
	return lines
}

func soaMin(soa *dnsmessage.SOAResource) uint32 {
	if soa == nil {
		return 0
	}
	return soa.MinTTL
}

func mustRaw(t *testing.T, server *Server, cfgs []grants.GrantConfig, name string, qtype dnsmessage.Type, src netip.Addr) []byte {
	t.Helper()
	raw, _, err := server.resolveCached(context.Background(), staticQuery(name, qtype), cfgs, src)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
