package dns

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/tailcfg"
)

func TestHandleIPNames(t *testing.T) {
	srcIn := netip.MustParseAddr("192.0.2.10")
	srcOut := netip.MustParseAddr("198.51.100.10")
	direct := netip.MustParseAddr("192.168.10.4")
	tests := []struct {
		name       string
		raw        string
		qname      string
		qtype      dnsmessage.Type
		class      dnsmessage.Class
		opcode     dnsmessage.OpCode
		questions  int
		src        netip.Addr
		wantRCode  dnsmessage.RCode
		wantAA     bool
		wantAns    int
		wantAuth   bool
		wantA      bool
		wantAAAA   bool
		wantSOAAns bool
	}{
		{
			name: "aaaa", raw: `{"site-a.example":{"ipnames":{"siteid":1}}}`,
			qname: "10-0-0-1.site-a.example.", qtype: dnsmessage.TypeAAAA, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeSuccess, wantAA: true, wantAns: 1, wantAAAA: true,
		},
		{
			name: "preserve case", raw: `{"site-a.example":{"ipnames":{"siteid":1}}}`,
			qname: "10-0-0-1.Site-A.Example.", qtype: dnsmessage.TypeAAAA, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeSuccess, wantAA: true, wantAns: 1, wantAAAA: true,
		},
		{
			name: "a never", raw: `{"site-a.example":{"ipnames":{"siteid":1}}}`,
			qname: "10-0-0-1.site-a.example.", qtype: dnsmessage.TypeA, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeSuccess, wantAA: true, wantAuth: true,
		},
		{
			name: "a always", raw: `{"site-a.example":{"ipnames":{"siteid":1,"a":"always"}}}`,
			qname: "10-0-0-1.site-a.example.", qtype: dnsmessage.TypeA, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeSuccess, wantAA: true, wantAns: 1, wantA: true,
		},
		{
			name: "a direct match", raw: `{"site-a.example":{"ipnames":{"siteid":1,"a":"direct","directsrc":["192.168.10.0/24"]}}}`,
			qname: "10-0-0-1.site-a.example.", qtype: dnsmessage.TypeA, class: dnsmessage.ClassINET, questions: 1, src: direct,
			wantRCode: dnsmessage.RCodeSuccess, wantAA: true, wantAns: 1, wantA: true,
		},
		{
			name: "a direct miss", raw: `{"site-a.example":{"ipnames":{"siteid":1,"a":"direct","directsrc":["192.168.10.0/24"]}}}`,
			qname: "10-0-0-1.site-a.example.", qtype: dnsmessage.TypeA, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeSuccess, wantAA: true, wantAuth: true,
		},
		{
			name: "mx nodata", raw: `{"site-a.example":{"ipnames":{"siteid":1}}}`,
			qname: "10-0-0-1.site-a.example.", qtype: dnsmessage.TypeMX, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeSuccess, wantAA: true, wantAuth: true,
		},
		{
			name: "txt nodata", raw: `{"site-a.example":{"ipnames":{"siteid":1}}}`,
			qname: "10-0-0-1.site-a.example.", qtype: dnsmessage.TypeTXT, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeSuccess, wantAA: true, wantAuth: true,
		},
		{
			name: "https nodata", raw: `{"site-a.example":{"ipnames":{"siteid":1}}}`,
			qname: "10-0-0-1.site-a.example.", qtype: dnsmessage.TypeHTTPS, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeSuccess, wantAA: true, wantAuth: true,
		},
		{
			name: "any nodata", raw: `{"site-a.example":{"ipnames":{"siteid":1}}}`,
			qname: "10-0-0-1.site-a.example.", qtype: dnsmessage.TypeALL, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeSuccess, wantAA: true, wantAuth: true,
		},
		{
			name: "apex soa", raw: `{"site-a.example":{"ipnames":{"siteid":1,"negttl":90}}}`,
			qname: "site-a.example.", qtype: dnsmessage.TypeSOA, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeSuccess, wantAA: true, wantAns: 1, wantSOAAns: true,
		},
		{
			name: "apex a", raw: `{"site-a.example":{"ipnames":{"siteid":1}}}`,
			qname: "site-a.example.", qtype: dnsmessage.TypeA, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeSuccess, wantAA: true, wantAuth: true,
		},
		{
			name: "leading zero", raw: `{"site-a.example":{"ipnames":{"siteid":1}}}`,
			qname: "010-0-0-1.site-a.example.", qtype: dnsmessage.TypeAAAA, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeNameError, wantAA: true, wantAuth: true,
		},
		{
			name: "octet overflow", raw: `{"site-a.example":{"ipnames":{"siteid":1}}}`,
			qname: "256-0-0-1.site-a.example.", qtype: dnsmessage.TypeAAAA, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeNameError, wantAA: true, wantAuth: true,
		},
		{
			name: "extra label", raw: `{"site-a.example":{"ipnames":{"siteid":1}}}`,
			qname: "10-0-0-1.extra.site-a.example.", qtype: dnsmessage.TypeAAAA, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeNameError, wantAA: true, wantAuth: true,
		},
		{
			name: "blocked range", raw: `{"site-a.example":{"ipnames":{"siteid":1}}}`,
			qname: "100-64-1-1.site-a.example.", qtype: dnsmessage.TypeAAAA, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeNameError, wantAA: true, wantAuth: true,
		},
		{
			name: "outside allowips", raw: `{"site-a.example":{"ipnames":{"siteid":1,"allowips":["192.168.0.0/16"]}}}`,
			qname: "10-1-2-3.site-a.example.", qtype: dnsmessage.TypeAAAA, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeNameError, wantAA: true, wantAuth: true,
		},
		{
			name: "allowips hit", raw: `{"site-b.example":{"ipnames":{"siteid":2,"allowips":["10.0.0.0/8"]}}}`,
			qname: "10-9-8-7.site-b.example.", qtype: dnsmessage.TypeAAAA, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeSuccess, wantAA: true, wantAns: 1, wantAAAA: true,
		},
		{
			name: "allowsrc miss", raw: `{"site-a.example":{"ipnames":{"siteid":1,"allowsrc":["198.51.100.0/24"]}}}`,
			qname: "10-0-0-1.site-a.example.", qtype: dnsmessage.TypeAAAA, class: dnsmessage.ClassINET, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeRefused, wantAA: true,
		},
		{
			name: "allowsrc hit", raw: `{"site-a.example":{"ipnames":{"siteid":1,"allowsrc":["198.51.100.0/24"]}}}`,
			qname: "10-0-0-1.site-a.example.", qtype: dnsmessage.TypeAAAA, class: dnsmessage.ClassINET, questions: 1, src: srcOut,
			wantRCode: dnsmessage.RCodeSuccess, wantAA: true, wantAns: 1, wantAAAA: true,
		},
		{
			name: "class", raw: `{"site-a.example":{"ipnames":{"siteid":1}}}`,
			qname: "10-0-0-1.site-a.example.", qtype: dnsmessage.TypeAAAA, class: dnsmessage.ClassCHAOS, questions: 1, src: srcIn,
			wantRCode: dnsmessage.RCodeRefused, wantAA: true,
		},
		{
			name: "two questions", raw: `{"site-a.example":{"ipnames":{"siteid":1}}}`,
			qname: "10-0-0-1.site-a.example.", qtype: dnsmessage.TypeAAAA, class: dnsmessage.ClassINET, questions: 2, src: srcIn,
			wantRCode: dnsmessage.RCodeFormatError, wantAA: true,
		},
		{
			name: "opcode", raw: `{"site-a.example":{"ipnames":{"siteid":1}}}`,
			qname: "10-0-0-1.site-a.example.", qtype: dnsmessage.TypeAAAA, class: dnsmessage.ClassINET, questions: 1, opcode: 5, src: srcIn,
			wantRCode: dnsmessage.RCodeNotImplemented, wantAA: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := &Server{
				GrantParser: grants.NewParser(),
				BackendMgr: &mockBackendManager{backend: &mockBackend{queryFunc: func(ctx context.Context, query []byte) ([]byte, error) {
					calls++
					return nil, fmt.Errorf("backend must not be queried")
				}}},
				Logf: t.Logf,
			}
			cfgs := mustIPNames(t, tc.raw)
			questions := make([]dnsmessage.Question, tc.questions)
			for i := range questions {
				questions[i] = dnsmessage.Question{
					Name: dnsmessage.MustNewName(tc.qname), Type: tc.qtype, Class: tc.class,
				}
			}
			query := &dnsmessage.Message{
				Header:    dnsmessage.Header{ID: 42, OpCode: tc.opcode, RecursionDesired: true},
				Questions: questions,
			}
			raw, err := server.processQuery(context.Background(), query, cfgs, tc.src)
			if err != nil {
				t.Fatalf("processQuery: %v", err)
			}
			if calls != 0 {
				t.Fatalf("backend calls = %d", calls)
			}
			var resp dnsmessage.Message
			if err := resp.Unpack(raw); err != nil {
				t.Fatal(err)
			}
			if resp.RCode != tc.wantRCode {
				t.Fatalf("rcode %v want %v", resp.RCode, tc.wantRCode)
			}
			if resp.Authoritative != tc.wantAA {
				t.Fatalf("aa %v", resp.Authoritative)
			}
			if len(resp.Answers) != tc.wantAns {
				t.Fatalf("answers %d want %d", len(resp.Answers), tc.wantAns)
			}
			if tc.wantAuth && len(resp.Authorities) == 0 {
				t.Fatal("missing authority SOA")
			}
			if tc.wantAuth {
				soa, ok := resp.Authorities[0].Body.(*dnsmessage.SOAResource)
				if !ok || soa.Serial != 1 || soa.MinTTL == 0 {
					t.Fatalf("soa %#v", resp.Authorities[0].Body)
				}
			}
			if tc.wantSOAAns {
				soa, ok := resp.Answers[0].Body.(*dnsmessage.SOAResource)
				if !ok || soa.MinTTL != 90 {
					t.Fatalf("apex soa %#v", resp.Answers[0].Body)
				}
			}
			if tc.wantA {
				a, ok := resp.Answers[0].Body.(*dnsmessage.AResource)
				if !ok || a.A != [4]byte{10, 0, 0, 1} {
					t.Fatalf("A %#v", resp.Answers[0].Body)
				}
			}
			if tc.wantAAAA {
				aaaa, ok := resp.Answers[0].Body.(*dnsmessage.AAAAResource)
				if !ok {
					t.Fatalf("AAAA %#v", resp.Answers[0].Body)
				}
				got := netip.AddrFrom16(aaaa.AAAA)
				want, err := via6For(siteFromName(tc.qname), netip.MustParseAddr(stringsReplaceDash(tc.qname)))
				if err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Fatalf("AAAA %s want %s", got, want)
				}
				if resp.Answers[0].Header.Name.String() != tc.qname {
					t.Fatalf("name %s want %s", resp.Answers[0].Header.Name, tc.qname)
				}
			}
		})
	}
}

func FuzzProcessQuery(f *testing.F) {
	seed := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 1, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name: dnsmessage.MustNewName("10-0-0-1.site-a.example."), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := seed.Pack()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(packed)
	f.Add([]byte{0, 1, 2, 3})
	server := &Server{
		GrantParser: grants.NewParser(),
		BackendMgr: &mockBackendManager{backend: &mockBackend{queryFunc: func(ctx context.Context, query []byte) ([]byte, error) {
			return seed.Pack()
		}}},
		Logf: func(string, ...any) {},
	}
	cfgs := mustIPNames(f, `{"site-a.example":{"ipnames":{"siteid":1}},"site-b.example":{"dns":["10.1.0.10:53"],"translateid":-1}}`)
	f.Fuzz(func(t *testing.T, packet []byte) {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("panic: %v", rec)
			}
		}()
		var msg dnsmessage.Message
		if err := msg.Unpack(packet); err != nil {
			return
		}
		resp, err := server.processQuery(context.Background(), &msg, cfgs, netip.MustParseAddr("192.0.2.10"))
		if err != nil || len(resp) == 0 {
			return
		}
		var out dnsmessage.Message
		if err := out.Unpack(resp); err != nil {
			t.Fatalf("response unpack: %v", err)
		}
	})
}

func mustIPNames(t testing.TB, raw string) []grants.GrantConfig {
	t.Helper()
	p := grants.NewParser()
	cfgs, err := p.ParseGrants(tailcfg.PeerCapMap{
		"rajsingh.info/cap/tsdnsproxy": {tailcfg.RawMessage(raw)},
	})
	if err != nil || len(cfgs) == 0 {
		t.Fatalf("grant: %v %#v", err, cfgs)
	}
	return cfgs
}

func siteFromName(qname string) uint32 {
	if strings.Contains(strings.ToLower(qname), "site-b.example") {
		return 2
	}
	return 1
}

func stringsReplaceDash(qname string) string {
	// first label, dashes to dots
	end := 0
	for end < len(qname) && qname[end] != '.' {
		end++
	}
	out := make([]byte, 0, end)
	for i := 0; i < end; i++ {
		c := qname[i]
		if c == '-' {
			c = '.'
		}
		out = append(out, c)
	}
	return string(out)
}
