package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/backend"
	"github.com/rajsinghtech/tsdnsproxy/internal/cache"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

const exampleRules = `{
  "example.internal": {
    "dns": ["10.0.0.53:53"],
    "translateid": 1,
    "allowips": ["10.0.0.0/8"]
  }
}
`

func TestRulesFileAppliesWithNoGrant(t *testing.T) {
	path := writeExampleRules(t, exampleRules)
	var whoisCalls int
	server, logs := newRulesServer(t, path, func(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
		whoisCalls++
		return nil, fmt.Errorf("no whois for %s", addr)
	}, false)
	server.serverGrants = []grants.GrantConfig{{
		"example.internal": {
			DNS:         []string{"10.9.9.9:53"},
			TranslateID: translateID(9),
			AllowIPs:    []string{"10.0.0.0/8"},
		},
	}}

	aaaa := queryRules(t, server, "app.example.internal.", dnsmessage.TypeAAAA)
	if got := mustAAAA(t, aaaa); got != netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:1:a00:1") {
		t.Fatalf("AAAA = %s, want fd7a:115c:a1e0:b1a:0:1:a00:1", got)
	}
	a := queryRules(t, server, "app.example.internal.", dnsmessage.TypeA)
	if a.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("A RCode = %v, want success", a.RCode)
	}
	if len(a.Answers) != 0 {
		t.Fatalf("A answers = %d, want 0", len(a.Answers))
	}
	if whoisCalls == 0 {
		t.Fatal("whois was not called")
	}
	if !strings.Contains(logs.String(), "whois failed for 100.64.0.5") {
		t.Fatalf("log %q does not name the caller", logs.String())
	}
	if !serverHasBackend(t, server, "10.0.0.53:53") {
		t.Fatalf("backends = %v, want 10.0.0.53:53", rulesBackends(server))
	}
}

func TestRulesFileIPSuffix(t *testing.T) {
	body := `{
	  "ip": {
	    "ipnames": {"siteid": 1, "a": "never", "allowips": ["10.0.0.0/8"]}
	  }
	}`
	path := writeExampleRules(t, body)
	server, _ := newRulesServer(t, path, func(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
		return &apitype.WhoIsResponse{Node: &tailcfg.Node{Name: "client.example.ts.net"}}, nil
	}, true)

	aaaa := queryRules(t, server, "10-1-2-3.ip.", dnsmessage.TypeAAAA)
	if got := mustAAAA(t, aaaa); got != netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:1:a01:203") {
		t.Fatalf("AAAA = %s", got)
	}
	a := queryRules(t, server, "10-1-2-3.ip.", dnsmessage.TypeA)
	if a.RCode != dnsmessage.RCodeSuccess || len(a.Answers) != 0 {
		t.Fatalf("A rcode=%v answers=%d, want NODATA", a.RCode, len(a.Answers))
	}
	outside := queryRules(t, server, "11-0-0-1.ip.", dnsmessage.TypeAAAA)
	if outside.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("outside allowips rcode=%v, want NXDOMAIN", outside.RCode)
	}
	if serverHasBackend(t, server, "10.0.0.53:53") || len(rulesBackends(server)) != 0 {
		t.Fatalf("encoded name used a backend: %v", rulesBackends(server))
	}

	alwaysPath := writeExampleRules(t, `{
	  "ip": {"ipnames": {"siteid": 1, "a": "always", "allowips": ["10.0.0.0/8"]}}
	}`)
	always, _ := newRulesServer(t, alwaysPath, func(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
		return &apitype.WhoIsResponse{Node: &tailcfg.Node{Name: "client.example.ts.net"}}, nil
	}, true)
	a = queryRules(t, always, "10-1-2-3.ip.", dnsmessage.TypeA)
	if a.RCode != dnsmessage.RCodeSuccess || len(a.Answers) != 1 {
		t.Fatalf("always A rcode=%v answers=%d", a.RCode, len(a.Answers))
	}
	arec, ok := a.Answers[0].Body.(*dnsmessage.AResource)
	if !ok || netip.AddrFrom4(arec.A) != netip.MustParseAddr("10.1.2.3") {
		t.Fatalf("A = %#v", a.Answers)
	}
}

func TestRulesFileAppliesWhenWhoisHasNoGrant(t *testing.T) {
	path := writeExampleRules(t, exampleRules)
	server, logs := newRulesServer(t, path, func(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
		return &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "client.example.ts.net"},
		}, nil
	}, false)

	aaaa := queryRules(t, server, "app.example.internal.", dnsmessage.TypeAAAA)
	if got := mustAAAA(t, aaaa); got != netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:1:a00:1") {
		t.Fatalf("AAAA = %s, want fd7a:115c:a1e0:b1a:0:1:a00:1", got)
	}
	if !strings.Contains(logs.String(), "identity=client.example.ts.net") {
		t.Fatalf("log %q does not name the caller", logs.String())
	}
}

func TestRulesFileGrantPrecedence(t *testing.T) {
	body := `{
	  "example.internal": {"dns": ["10.0.0.53:53"], "translateid": 1, "allowips": ["10.0.0.0/8"]},
	  "other.internal": {"dns": ["10.0.0.53:53"], "translateid": 2, "allowips": ["10.0.0.0/8"]}
	}`
	path := writeExampleRules(t, body)
	whois := func(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
		return &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "client.example.ts.net"},
			CapMap: tailcfg.PeerCapMap{
				"rajsingh.info/cap/tsdnsproxy": {
					`{"example.internal":{"dns":["10.9.9.9:53"],"translateid":9,"allowips":["10.0.0.0/8"]}}`,
				},
			},
		}, nil
	}

	server, logs := newRulesServer(t, path, whois, false)
	got := mustAAAA(t, queryRules(t, server, "app.example.internal.", dnsmessage.TypeAAAA))
	if got != netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:9:a00:1") {
		t.Fatalf("grant domain AAAA = %s, want site 9", got)
	}
	got = mustAAAA(t, queryRules(t, server, "app.other.internal.", dnsmessage.TypeAAAA))
	if got != netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:2:a00:1") {
		t.Fatalf("file domain AAAA = %s, want site 2", got)
	}
	a := queryRules(t, server, "app.example.internal.", dnsmessage.TypeA)
	if len(a.Answers) != 0 {
		t.Fatalf("grant domain A answers = %d, want 0", len(a.Answers))
	}
	if !strings.Contains(logs.String(), "identity=client.example.ts.net") {
		t.Fatalf("log %q does not name the caller", logs.String())
	}

	only, _ := newRulesServer(t, path, whois, true)
	got = mustAAAA(t, queryRules(t, only, "app.example.internal.", dnsmessage.TypeAAAA))
	if got != netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:1:a00:1") {
		t.Fatalf("rules-only AAAA = %s, want site 1", got)
	}
}

func TestRulesFileReloadAppliesOnNextQuery(t *testing.T) {
	path := writeExampleRules(t, exampleRules)
	server, _ := newRulesServer(t, path, func(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
		return nil, fmt.Errorf("no whois")
	}, false)

	got := mustAAAA(t, queryRules(t, server, "app.example.internal.", dnsmessage.TypeAAAA))
	if got != netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:1:a00:1") {
		t.Fatalf("AAAA = %s, want site 1", got)
	}

	body := `{
	  "example.internal": {"dns": ["10.0.0.53:53"], "translateid": 3, "allowips": ["10.0.0.0/8"]}
	}`
	writeRulesFile(t, path, body)
	if _, err := server.Rules.Reload(); err != nil {
		t.Fatal(err)
	}
	got = mustAAAA(t, queryRules(t, server, "app.example.internal.", dnsmessage.TypeAAAA))
	if got != netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:3:a00:1") {
		t.Fatalf("AAAA after reload = %s, want site 3", got)
	}
}

type captureBackend struct {
	mu      sync.Mutex
	servers []string
	inner   *mockBackend
}

func (m *captureBackend) Query(ctx context.Context, backends []backend.Backend, query []byte) ([]byte, error) {
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backends")
	}
	return backends[0].Query(ctx, query)
}

func (m *captureBackend) CreateBackends(servers []string) []backend.Backend {
	m.mu.Lock()
	m.servers = append(m.servers, servers...)
	m.mu.Unlock()
	return []backend.Backend{m.inner}
}

func (m *captureBackend) addrs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.servers))
	copy(out, m.servers)
	return out
}

func newRulesServer(t *testing.T, path string, whois func(context.Context, string) (*apitype.WhoIsResponse, error), rulesOnly bool) (*Server, *strings.Builder) {
	t.Helper()
	rules, err := grants.OpenRulesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	mgr := &captureBackend{inner: ipv4Backend([4]byte{10, 0, 0, 1})}
	server := &Server{
		LocalClient: &mockLocalClient{whoisFunc: whois},
		WhoisCache:  cache.NewWhoisCache(time.Minute),
		GrantCache:  cache.NewGrantCache(time.Minute),
		GrantParser: grants.NewParser(),
		BackendMgr:  mgr,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(&logs, format, args...)
			logs.WriteByte('\n')
		},
		Rules:     rules,
		RulesOnly: rulesOnly,
	}
	t.Cleanup(func() {
		server.WhoisCache.Close()
		server.GrantCache.Close()
	})
	return server, &logs
}

func ipv4Backend(ip [4]byte) *mockBackend {
	return &mockBackend{queryFunc: func(ctx context.Context, query []byte) ([]byte, error) {
		var q dnsmessage.Message
		if err := q.Unpack(query); err != nil {
			return nil, err
		}
		if len(q.Questions) == 0 {
			return nil, fmt.Errorf("no question")
		}
		resp := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: q.ID, Response: true, RCode: dnsmessage.RCodeSuccess},
			Questions: q.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Questions[0].Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: ip},
			}},
		}
		return resp.Pack()
	}}
}

func queryRules(t *testing.T, server *Server, name string, qtype dnsmessage.Type) *dnsmessage.Message {
	t.Helper()
	pc := &mockPacketConn{}
	var got []byte
	pc.writeToFunc = func(b []byte, addr net.Addr) (int, error) {
		got = append([]byte(nil), b...)
		return len(b), nil
	}
	server.handleQuery(context.Background(), pc, &net.UDPAddr{IP: net.IPv4(100, 64, 0, 5), Port: 5353}, packQuestion(t, 7, name, qtype), "udp")
	if len(got) == 0 {
		t.Fatal("no DNS response")
	}
	var resp dnsmessage.Message
	if err := resp.Unpack(got); err != nil {
		t.Fatal(err)
	}
	return &resp
}

func mustAAAA(t *testing.T, resp *dnsmessage.Message) netip.Addr {
	t.Helper()
	if resp.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("RCode = %v, want success", resp.RCode)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answers))
	}
	aaaa, ok := resp.Answers[0].Body.(*dnsmessage.AAAAResource)
	if !ok {
		t.Fatalf("answer body = %T, want AAAA", resp.Answers[0].Body)
	}
	return netip.AddrFrom16(aaaa.AAAA)
}

func writeExampleRules(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.json")
	writeRulesFile(t, path, body)
	return path
}

func writeRulesFile(t *testing.T, path, body string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func serverHasBackend(t *testing.T, server *Server, want string) bool {
	t.Helper()
	for _, serverAddr := range rulesBackends(server) {
		if serverAddr == want {
			return true
		}
	}
	return false
}

func rulesBackends(server *Server) []string {
	mgr, ok := server.BackendMgr.(*captureBackend)
	if !ok {
		return nil
	}
	return mgr.addrs()
}
