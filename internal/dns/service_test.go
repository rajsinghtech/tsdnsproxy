package dns

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/cache"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"github.com/rajsinghtech/tsdnsproxy/internal/ui"
	"github.com/rajsinghtech/tsdnsproxy/internal/vip"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

const upstreamIP = "192.0.2.99"

// serviceServer answers upstream queries with upstreamIP and counts them.
func serviceServer(t *testing.T, vips *vip.Table, calls *atomic.Int32) *Server {
	t.Helper()
	server := &Server{
		GrantParser: grants.NewParser(),
		BackendMgr: &mockBackendManager{backend: &mockBackend{queryFunc: func(_ context.Context, raw []byte) ([]byte, error) {
			calls.Add(1)
			var q dnsmessage.Message
			if err := q.Unpack(raw); err != nil {
				return nil, err
			}
			resp := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: q.ID, Response: true},
				Questions: q.Questions,
			}
			if q.Questions[0].Type == dnsmessage.TypeA {
				resp.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
					Body:   &dnsmessage.AResource{A: netip.MustParseAddr(upstreamIP).As4()},
				}}
			}
			return resp.Pack()
		}}},
		Logf: t.Logf,
	}
	if vips != nil {
		server.ServiceVIPs = vips
	}
	return server
}

func vipTable(entries map[string][]string) *vip.Table {
	t := &vip.Table{}
	setVIPs(t, entries)
	return t
}

func setVIPs(t *vip.Table, entries map[string][]string) {
	m := map[tailcfg.ServiceName][]netip.Addr{}
	for name, addrs := range entries {
		for _, a := range addrs {
			m[tailcfg.ServiceName(name)] = append(m[tailcfg.ServiceName(name)], netip.MustParseAddr(a))
		}
	}
	t.Set(m)
}

func serviceAnswer(t *testing.T, server *Server, cfgs []grants.GrantConfig, name string, qtype dnsmessage.Type) (*dnsmessage.Message, bool) {
	t.Helper()
	raw, hit, err := server.resolveCached(context.Background(), staticQuery(name, qtype), cfgs, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	return unpackStatic(t, raw), hit
}

func TestServiceAnswersFromNetmap(t *testing.T) {
	var calls atomic.Int32
	vips := vipTable(map[string][]string{"svc:app": {"100.64.0.10", "2001:db8::a"}})
	server := serviceServer(t, vips, &calls)
	cfgs := mustStaticRules(t, `{"app.example.com": {"service": "svc:app", "addrs": ["192.0.2.10"]}}`)

	a, _ := serviceAnswer(t, server, cfgs, "app.example.com.", dnsmessage.TypeA)
	if !sameAnswers(t, a, []string{"100.64.0.10"}) || a.Answers[0].Header.TTL != grants.DefaultServiceTTL || !a.Authoritative {
		t.Fatalf("A = %v ttl %d", answerText(t, a), a.Answers[0].Header.TTL)
	}
	aaaa, _ := serviceAnswer(t, server, cfgs, "app.example.com.", dnsmessage.TypeAAAA)
	if !sameAnswers(t, aaaa, []string{"2001:db8::a"}) {
		t.Fatalf("AAAA = %v", answerText(t, aaaa))
	}
	mx, _ := serviceAnswer(t, server, cfgs, "app.example.com.", dnsmessage.TypeMX)
	if mx.RCode != dnsmessage.RCodeSuccess || len(mx.Answers) != 0 || len(mx.Authorities) != 1 {
		t.Fatalf("MX rcode %v answers %d auth %d", mx.RCode, len(mx.Answers), len(mx.Authorities))
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream calls %d", calls.Load())
	}
}

func TestServiceNetmapFamilyMissing(t *testing.T) {
	var calls atomic.Int32
	vips := vipTable(map[string][]string{"svc:app": {"100.64.0.10"}})
	server := serviceServer(t, vips, &calls)
	cfgs := mustStaticRules(t, `{"app.example.com": {"service": "svc:app", "addrs": ["2001:db8::10"], "ttl": 45}}`)
	aaaa, _ := serviceAnswer(t, server, cfgs, "app.example.com.", dnsmessage.TypeAAAA)
	if len(aaaa.Answers) != 0 || len(aaaa.Authorities) != 1 || calls.Load() != 0 {
		t.Fatalf("AAAA answers %v auth %d calls %d", answerText(t, aaaa), len(aaaa.Authorities), calls.Load())
	}
	if soa := aaaa.Authorities[0].Body.(*dnsmessage.SOAResource); soa.MinTTL != 45 {
		t.Fatalf("soa min %d", soa.MinTTL)
	}
}

func TestServiceAddrsFallback(t *testing.T) {
	var calls atomic.Int32
	vips := vipTable(map[string][]string{"svc:other": {"100.64.0.20"}})
	server := serviceServer(t, vips, &calls)
	cfgs := mustStaticRules(t, `{"app.example.com": {"service": "svc:app", "addrs": ["192.0.2.10", "2001:db8::10"], "ttl": 60}}`)

	a, _ := serviceAnswer(t, server, cfgs, "app.example.com.", dnsmessage.TypeA)
	if !sameAnswers(t, a, []string{"192.0.2.10"}) || a.Answers[0].Header.TTL != 60 {
		t.Fatalf("A = %v", answerText(t, a))
	}
	aaaa, _ := serviceAnswer(t, server, cfgs, "app.example.com.", dnsmessage.TypeAAAA)
	if !sameAnswers(t, aaaa, []string{"2001:db8::10"}) {
		t.Fatalf("AAAA = %v", answerText(t, aaaa))
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream calls %d", calls.Load())
	}

	noSource := serviceServer(t, nil, &calls)
	a, _ = serviceAnswer(t, noSource, cfgs, "app.example.com.", dnsmessage.TypeA)
	if !sameAnswers(t, a, []string{"192.0.2.10"}) {
		t.Fatalf("A without a netmap source = %v", answerText(t, a))
	}
}

func TestServiceUpstreamFallback(t *testing.T) {
	var calls atomic.Int32
	server := serviceServer(t, vipTable(nil), &calls)
	cfgs := mustStaticRules(t, `{"app.example.com": {"service": "svc:app"}}`)
	a, _ := serviceAnswer(t, server, cfgs, "app.example.com.", dnsmessage.TypeA)
	if !sameAnswers(t, a, []string{upstreamIP}) || calls.Load() != 1 {
		t.Fatalf("A = %v calls %d", answerText(t, a), calls.Load())
	}
}

func TestServiceCallerWithoutGrant(t *testing.T) {
	var calls atomic.Int32
	vips := vipTable(map[string][]string{"svc:app": {"100.64.0.10"}})
	server := serviceServer(t, vips, &calls)
	server.LocalClient = &mockLocalClient{whoisFunc: func(_ context.Context, addr string) (*apitype.WhoIsResponse, error) {
		resp := &apitype.WhoIsResponse{Node: &tailcfg.Node{Name: addr + ".example.ts.net"}}
		if addr == "100.64.0.2" {
			resp.CapMap = tailcfg.PeerCapMap{
				grants.DefaultCapName: {tailcfg.RawMessage(`{"app.example.com": {"service": "svc:app"}}`)},
			}
		}
		return resp, nil
	}}
	server.WhoisCache = cache.NewWhoisCache(time.Minute)
	server.GrantCache = cache.NewGrantCache(time.Minute)
	server.answers = newAnswerCache(16, time.Second, time.Hour, nil)
	t.Cleanup(func() {
		server.WhoisCache.Close()
		server.GrantCache.Close()
	})

	ask := func(peer string) *dnsmessage.Message {
		t.Helper()
		cfgs, err := server.getGrantsForSource(context.Background(), peer+":53000")
		if err != nil {
			t.Fatal(err)
		}
		msg, _ := serviceAnswer(t, server, cfgs, "app.example.com.", dnsmessage.TypeA)
		return msg
	}
	if got := ask("100.64.0.2"); !sameAnswers(t, got, []string{"100.64.0.10"}) {
		t.Fatalf("granted peer got %v", answerText(t, got))
	}
	if got := ask("100.64.0.3"); !sameAnswers(t, got, []string{upstreamIP}) {
		t.Fatalf("peer without the grant got %v", answerText(t, got))
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls %d", calls.Load())
	}
}

func TestServiceVIPChangeAfterNetmapUpdate(t *testing.T) {
	var calls atomic.Int32
	vips := vipTable(map[string][]string{"svc:app": {"100.64.0.10"}})
	server := serviceServer(t, vips, &calls)
	clk := newTestClock(time.Unix(1_700_000_000, 0))
	server.answers = newAnswerCache(16, time.Second, time.Hour, nil)
	server.answers.now = clk.now
	cfgs := mustStaticRules(t, `{"app.example.com": {"service": "svc:app"}}`)

	first, hit := serviceAnswer(t, server, cfgs, "app.example.com.", dnsmessage.TypeA)
	if hit || !sameAnswers(t, first, []string{"100.64.0.10"}) {
		t.Fatalf("first %v hit %v", answerText(t, first), hit)
	}
	clk.add(5 * time.Second)
	cached, hit := serviceAnswer(t, server, cfgs, "app.example.com.", dnsmessage.TypeA)
	if !hit || !sameAnswers(t, cached, []string{"100.64.0.10"}) {
		t.Fatalf("cached %v hit %v", answerText(t, cached), hit)
	}

	setVIPs(vips, map[string][]string{"svc:app": {"100.64.0.11"}})
	moved, hit := serviceAnswer(t, server, cfgs, "app.example.com.", dnsmessage.TypeA)
	if hit || !sameAnswers(t, moved, []string{"100.64.0.11"}) {
		t.Fatalf("after netmap update %v hit %v", answerText(t, moved), hit)
	}

	setVIPs(vips, nil)
	gone, hit := serviceAnswer(t, server, cfgs, "app.example.com.", dnsmessage.TypeA)
	if hit || !sameAnswers(t, gone, []string{upstreamIP}) {
		t.Fatalf("after removal %v hit %v", answerText(t, gone), hit)
	}
}

func TestServiceCacheKeepsRuleTTL(t *testing.T) {
	var calls atomic.Int32
	vips := vipTable(map[string][]string{"svc:app": {"100.64.0.10"}})
	server := serviceServer(t, vips, &calls)
	clk := newTestClock(time.Unix(1_700_000_000, 0))
	server.answers = newAnswerCache(16, 5*time.Minute, time.Hour, nil)
	server.answers.now = clk.now
	cfgs := mustStaticRules(t, `{"app.example.com": {"service": "svc:app", "ttl": 10}}`)

	if _, hit := serviceAnswer(t, server, cfgs, "app.example.com.", dnsmessage.TypeA); hit {
		t.Fatal("first query hit")
	}
	clk.add(9 * time.Second)
	if _, hit := serviceAnswer(t, server, cfgs, "app.example.com.", dnsmessage.TypeA); !hit {
		t.Fatal("second query missed")
	}
	clk.add(2 * time.Second)
	if _, hit := serviceAnswer(t, server, cfgs, "app.example.com.", dnsmessage.TypeA); hit {
		t.Fatal("answer served past its ttl")
	}
}

func TestServiceLookupAndSnapshot(t *testing.T) {
	var calls atomic.Int32
	vips := vipTable(map[string][]string{"svc:app": {"100.64.0.10", "2001:db8::a"}})
	server := serviceServer(t, vips, &calls)
	withRules(t, server, `{
		"app.example.com": {"service": "svc:app"},
		"db.example.com": {"service": "svc:db", "addrs": ["192.0.2.20"]},
		"web.example.com": {"service": "svc:web"},
	}`)
	server.LocalClient = &mockLocalClient{whoisFunc: func(context.Context, string) (*apitype.WhoIsResponse, error) {
		return nil, errors.New("no whois")
	}}
	server.WhoisCache = cache.NewWhoisCache(time.Minute)
	server.GrantCache = cache.NewGrantCache(time.Minute)
	t.Cleanup(func() {
		server.WhoisCache.Close()
		server.GrantCache.Close()
	})

	got, err := server.Explain(context.Background(), ui.LookupRequest{Name: "app.example.com", Type: "A", Peer: "100.64.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	svc := got.Rule.ServiceVIP
	if svc == nil || svc.From != "netmap" || len(svc.Resolved) != 2 || svc.Resolved[0] != "100.64.0.10" || got.Forwarded {
		t.Fatalf("lookup %+v", svc)
	}

	snap := server.UISnapshot()
	if len(snap.ServiceVIPs) != 3 {
		t.Fatalf("service vips %+v", snap.ServiceVIPs)
	}
	want := map[string]string{"app.example.com": "netmap", "db.example.com": "addrs", "web.example.com": "upstream"}
	for _, v := range snap.ServiceVIPs {
		if want[v.Domain] != v.From || v.Source != "rules" || v.TTL != grants.DefaultServiceTTL {
			t.Fatalf("view %+v", v)
		}
	}
	for _, r := range snap.Rules {
		if r.ServiceVIP == nil || r.ServiceVIP.From == "" {
			t.Fatalf("rule %s not described: %+v", r.Domain, r.ServiceVIP)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream calls %d", calls.Load())
	}
}
