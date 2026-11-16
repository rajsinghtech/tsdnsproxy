package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/backend"
	"github.com/rajsinghtech/tsdnsproxy/internal/cache"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
)

// zoneReply builds a reply to q. drop means no reply is sent.
type zoneReply func(q dnsmessage.Question) (rcode dnsmessage.RCode, answers []dnsmessage.Resource, drop bool)

type fakeDNS struct {
	addr    string
	queries atomic.Int32
}

func serveZoneDNS(t *testing.T, reply zoneReply) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	f := &fakeDNS{addr: pc.LocalAddr().String()}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if err := q.Unpack(buf[:n]); err != nil || len(q.Questions) != 1 {
				continue
			}
			f.queries.Add(1)
			rcode, answers, drop := reply(q.Questions[0])
			if drop {
				continue
			}
			msg := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true, RCode: rcode},
				Questions: q.Questions,
				Answers:   answers,
			}
			raw, err := msg.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(raw, addr)
		}
	}()
	return f
}

func zoneA(q dnsmessage.Question, ip string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
		Body:   &dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()},
	}
}

func zoneAAAA(q dnsmessage.Question, ip string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 60},
		Body:   &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(ip).As16()},
	}
}

// answerFor returns an A or AAAA answer matching the question type.
func answerFor(v4, v6 string) zoneReply {
	return func(q dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource, bool) {
		switch q.Type {
		case dnsmessage.TypeA:
			if v4 != "" {
				return dnsmessage.RCodeSuccess, []dnsmessage.Resource{zoneA(q, v4)}, false
			}
		case dnsmessage.TypeAAAA:
			if v6 != "" {
				return dnsmessage.RCodeSuccess, []dnsmessage.Resource{zoneAAAA(q, v6)}, false
			}
		}
		return dnsmessage.RCodeSuccess, nil, false
	}
}

func zoneTestServer(t *testing.T, defaults []string) *Server {
	t.Helper()
	mgr, err := backend.NewManager(defaults, backend.Dialers{
		Direct:  backend.HostDialer(),
		Default: backend.DialDirect,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Close)
	server := &Server{
		LocalClient: &mockLocalClient{whoisFunc: func(context.Context, string) (*apitype.WhoIsResponse, error) {
			return nil, fmt.Errorf("no whois")
		}},
		WhoisCache:   cache.NewWhoisCache(time.Minute),
		GrantCache:   cache.NewGrantCache(time.Minute),
		GrantParser:  grants.NewParser(),
		BackendMgr:   mgr,
		Logf:         t.Logf,
		MaxInflight:  8,
		QueryTimeout: 5 * time.Second,
	}
	t.Cleanup(func() {
		server.WhoisCache.Close()
		server.GrantCache.Close()
	})
	return server
}

func withRules(t *testing.T, server *Server, rules string) {
	t.Helper()
	path := t.TempDir() + "/rules.json"
	if err := os.WriteFile(path, []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
	rf, err := grants.OpenRulesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	server.Rules = rf
	server.RulesOnly = true
}

func zoneRule(upstream, fallback string) string {
	fb := ""
	if fallback != "" {
		fb = `"fallback": ["direct://` + fallback + `"],`
	}
	return `{"example.com": {
		"dns": ["direct://` + upstream + `"],
		"translateid": 7,
		"allowips": ["10.0.0.0/8"],
		"zone": {` + fb + ` "timeout": "200ms"}
	}}`
}

func unpackZone(t *testing.T, raw []byte) dnsmessage.Message {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		t.Fatal(err)
	}
	return msg
}

func answerAddrs(msg dnsmessage.Message) []netip.Addr {
	var out []netip.Addr
	for _, ans := range msg.Answers {
		switch body := ans.Body.(type) {
		case *dnsmessage.AResource:
			out = append(out, netip.AddrFrom4(body.A))
		case *dnsmessage.AAAAResource:
			out = append(out, netip.AddrFrom16(body.AAAA))
		}
	}
	return out
}

func wantAddrs(t *testing.T, raw []byte, want ...string) {
	t.Helper()
	msg := unpackZone(t, raw)
	if msg.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode = %v", msg.RCode)
	}
	got := answerAddrs(msg)
	if len(got) != len(want) {
		t.Fatalf("answers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != netip.MustParseAddr(want[i]) {
			t.Fatalf("answers = %v, want %v", got, want)
		}
	}
}

func mustVia6(t *testing.T, site uint32, ip string) string {
	t.Helper()
	via, err := via6For(site, netip.MustParseAddr(ip))
	if err != nil {
		t.Fatal(err)
	}
	return via.String()
}

func TestZonePrivateAnswerIsTranslated(t *testing.T) {
	upstream := serveZoneDNS(t, answerFor("10.1.2.3", ""))
	fallback := serveZoneDNS(t, answerFor("192.0.2.99", ""))
	server := zoneTestServer(t, nil)
	withRules(t, server, zoneRule(upstream.addr, fallback.addr))

	wantAddrs(t, askUDP(t, server, "nas.example.com.", dnsmessage.TypeAAAA), mustVia6(t, 7, "10.1.2.3"))
	wantAddrs(t, askUDP(t, server, "nas.example.com.", dnsmessage.TypeA))
	if n := fallback.queries.Load(); n != 0 {
		t.Fatalf("fallback queried %d times", n)
	}
}

func TestZonePublicAnswerPassesThrough(t *testing.T) {
	upstream := serveZoneDNS(t, answerFor("192.0.2.80", "2001:db8::80"))
	fallback := serveZoneDNS(t, answerFor("192.0.2.99", "2001:db8::99"))
	server := zoneTestServer(t, nil)
	withRules(t, server, zoneRule(upstream.addr, fallback.addr))

	wantAddrs(t, askUDP(t, server, "www.example.com.", dnsmessage.TypeA), "192.0.2.80")
	wantAddrs(t, askUDP(t, server, "www.example.com.", dnsmessage.TypeAAAA), "2001:db8::80")
	if n := fallback.queries.Load(); n != 0 {
		t.Fatalf("fallback queried %d times", n)
	}
}

func TestZoneEmptyUpstreamFallsBack(t *testing.T) {
	cases := []struct {
		name  string
		reply zoneReply
	}{
		{"nxdomain", func(dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource, bool) {
			return dnsmessage.RCodeNameError, nil, false
		}},
		{"nodata", func(dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource, bool) {
			return dnsmessage.RCodeSuccess, nil, false
		}},
	}
	for _, tc := range cases {
		for _, explicit := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/explicit=%v", tc.name, explicit), func(t *testing.T) {
				upstream := serveZoneDNS(t, tc.reply)
				public := serveZoneDNS(t, answerFor("192.0.2.53", ""))
				var server *Server
				if explicit {
					server = zoneTestServer(t, nil)
					withRules(t, server, zoneRule(upstream.addr, public.addr))
				} else {
					server = zoneTestServer(t, []string{"direct://" + public.addr})
					withRules(t, server, zoneRule(upstream.addr, ""))
				}
				wantAddrs(t, askUDP(t, server, "blog.example.com.", dnsmessage.TypeA), "192.0.2.53")
				if upstream.queries.Load() == 0 {
					t.Fatal("upstream was not queried")
				}
			})
		}
	}
}

func TestZoneUpstreamTimeoutFallsBack(t *testing.T) {
	upstream := serveZoneDNS(t, func(dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource, bool) {
		return 0, nil, true
	})
	fallback := serveZoneDNS(t, answerFor("192.0.2.54", ""))
	server := zoneTestServer(t, nil)
	withRules(t, server, zoneRule(upstream.addr, fallback.addr))

	start := time.Now()
	raw := askUDP(t, server, "shop.example.com.", dnsmessage.TypeA)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("answer took %v", d)
	}
	wantAddrs(t, raw, "192.0.2.54")
}

func TestZoneUpstreamTimeoutFallsBackForAAAA(t *testing.T) {
	upstream := serveZoneDNS(t, func(dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource, bool) {
		return 0, nil, true
	})
	fallback := serveZoneDNS(t, answerFor("192.0.2.54", "2001:db8::54"))
	server := zoneTestServer(t, nil)
	withRules(t, server, zoneRule(upstream.addr, fallback.addr))

	start := time.Now()
	raw := askUDP(t, server, "shop.example.com.", dnsmessage.TypeAAAA)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("answer took %v", d)
	}
	wantAddrs(t, raw, "2001:db8::54")
}

func TestZoneCallerWithoutCapGetsPublicAnswer(t *testing.T) {
	upstream := serveZoneDNS(t, answerFor("10.1.2.3", ""))
	public := serveZoneDNS(t, answerFor("192.0.2.81", ""))
	grant := `{"example.com": {
		"dns": ["direct://` + upstream.addr + `"],
		"translateid": 7,
		"zone": {"timeout": "200ms"}
	}}`

	newServer := func(withCap bool) *Server {
		server := zoneTestServer(t, []string{"direct://" + public.addr})
		server.LocalClient = &mockLocalClient{whoisFunc: func(context.Context, string) (*apitype.WhoIsResponse, error) {
			resp := &apitype.WhoIsResponse{Node: &tailcfg.Node{Name: "laptop.example.ts.net."}}
			if withCap {
				resp.CapMap = tailcfg.PeerCapMap{
					peercap.Cap(grants.DefaultCapName): []tailcfg.RawMessage{tailcfg.RawMessage(grant)},
				}
			}
			return resp, nil
		}}
		return server
	}

	without := newServer(false)
	start := time.Now()
	wantAddrs(t, askUDP(t, without, "nas.example.com.", dnsmessage.TypeA), "192.0.2.81")
	msg := unpackZone(t, askUDP(t, without, "nas.example.com.", dnsmessage.TypeAAAA))
	for _, addr := range answerAddrs(msg) {
		if addr.Is6() {
			t.Fatalf("caller without the cap got AAAA %v", addr)
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("answers took %v", d)
	}
	if n := upstream.queries.Load(); n != 0 {
		t.Fatalf("private upstream queried %d times for a caller without the cap", n)
	}

	with := newServer(true)
	wantAddrs(t, askUDP(t, with, "nas.example.com.", dnsmessage.TypeAAAA), mustVia6(t, 7, "10.1.2.3"))
}
