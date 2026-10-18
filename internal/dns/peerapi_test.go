package dns

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/cache"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
)

func TestPeerAPIPrefixInterceptsDNSQuery(t *testing.T) {
	handler, ok := peerAPIHandlerPrefixes[peerDNSPrefix]
	if !ok || handler == nil {
		t.Fatal("peerapi prefix /dns-query is not installed")
	}
	for _, path := range []string{"/dns-query", "/dns-query/"} {
		got := matchingPeerPrefixes(path)
		if len(got) != 1 || got[0] != peerDNSPrefix {
			t.Fatalf("path %s matched %v, want only %s", path, got, peerDNSPrefix)
		}
	}
	for _, path := range []string{"/", "/v0/drive", "/v0/ingress", "/v0/goroutines"} {
		for _, pfx := range matchingPeerPrefixes(path) {
			if pfx == peerDNSPrefix {
				t.Fatalf("path %s matched the dns prefix", path)
			}
		}
	}
}

func TestPeerAPIDOHAppliesRulesForSource(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	path := writeExampleRules(t, `{
	  "example.internal": {"dns": ["10.0.0.53:53"], "translateid": 4, "allowips": ["10.0.0.0/8"]}
	}`)
	rules, err := grants.OpenRulesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		LocalClient: &mockLocalClient{whoisFunc: func(_ context.Context, addr string) (*apitype.WhoIsResponse, error) {
			mu.Lock()
			seen = append(seen, addr)
			mu.Unlock()
			switch addr {
			case "100.64.0.2":
				return &apitype.WhoIsResponse{
					Node: &tailcfg.Node{Name: "a.example.ts.net."},
					CapMap: tailcfg.PeerCapMap{
						grants.DefaultCapName: {
							`{"example.internal":{"dns":["10.0.0.53:53"],"translateid":7,"allowips":["10.0.0.0/8"]}}`,
						},
					},
				}, nil
			case "100.64.0.3":
				return &apitype.WhoIsResponse{
					Node: &tailcfg.Node{Name: "b.example.ts.net."},
				}, nil
			default:
				return nil, fmt.Errorf("unexpected whois %s", addr)
			}
		}},
		WhoisCache:  cache.NewWhoisCache(time.Minute),
		GrantCache:  cache.NewGrantCache(time.Minute),
		GrantParser: grants.NewParser(),
		BackendMgr:  &captureBackend{inner: ipv4Backend([4]byte{10, 0, 0, 1})},
		Logf:        t.Logf,
		Rules:       rules,
	}
	t.Cleanup(func() {
		server.WhoisCache.Close()
		server.GrantCache.Close()
	})

	query := packQuestion(t, 7, "app.example.internal.", dnsmessage.TypeAAAA)
	granted := postPeerDNS(t, server, netip.MustParseAddrPort("100.64.0.2:5353"), query)
	if !bytes.Equal(granted, answerOn(t, server, "100.64.0.2:5353", query)) {
		t.Fatal("peerapi response differs from the port 53 handler for the same peer")
	}
	if got := mustAAAA(t, unpackMsg(t, granted)); got != netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:7:a00:1") {
		t.Fatalf("grant AAAA = %s, want site 7", got)
	}

	filed := getPeerDNS(t, server, netip.MustParseAddrPort("100.64.0.3:5353"), query)
	if got := mustAAAA(t, unpackMsg(t, filed)); got != netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:4:a00:1") {
		t.Fatalf("rules file AAAA = %s, want site 4", got)
	}

	mu.Lock()
	gotSeen := append([]string(nil), seen...)
	mu.Unlock()
	if !containsAll(gotSeen, "100.64.0.2", "100.64.0.3") {
		t.Fatalf("whois saw %v, want both peer addresses", gotSeen)
	}

	// The registered prefix, not a direct method call, is what ServeHTTP runs.
	prev := activePeerServer.Swap(server)
	t.Cleanup(func() { activePeerServer.Store(prev) })
	req := httptest.NewRequest(http.MethodPost, "http://100.64.0.1/dns-query", bytes.NewReader(query))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	peerAPIHandlerPrefixes[peerDNSPrefix](fakePeer{addr: netip.MustParseAddrPort("100.64.0.2:5353")}, rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("prefix handler status = %d body %s", rec.Code, rec.Body.Bytes())
	}
	if rec.Header().Get("Content-Type") != "application/dns-message" {
		t.Fatalf("content type = %q", rec.Header().Get("Content-Type"))
	}
	if !bytes.Equal(rec.Body.Bytes(), granted) {
		t.Fatal("prefix handler did not apply the peer grant")
	}
}

func TestPeerAPIDOHRejectsMalformedQuery(t *testing.T) {
	var calls int
	server := &Server{
		LocalClient: &mockLocalClient{whoisFunc: func(context.Context, string) (*apitype.WhoIsResponse, error) {
			calls++
			return nil, fmt.Errorf("whois should not run")
		}},
		WhoisCache:  cache.NewWhoisCache(time.Minute),
		GrantCache:  cache.NewGrantCache(time.Minute),
		GrantParser: grants.NewParser(),
		BackendMgr:  &captureBackend{inner: ipv4Backend([4]byte{10, 0, 0, 1})},
		Logf:        t.Logf,
	}
	t.Cleanup(func() {
		server.WhoisCache.Close()
		server.GrantCache.Close()
	})
	peer := fakePeer{addr: netip.MustParseAddrPort("100.64.0.2:5353")}
	req := httptest.NewRequest(http.MethodPost, "http://100.64.0.1/dns-query", strings.NewReader("not-dns"))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	server.ServePeerDNS(peer, rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	if calls != 0 {
		t.Fatalf("whois calls = %d", calls)
	}

	empty := httptest.NewRequest(http.MethodGet, "http://100.64.0.1/dns-query", nil)
	rec = httptest.NewRecorder()
	server.ServePeerDNS(peer, rec, empty)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("GET status = %d", rec.Code)
	}
}

func TestPeerAPINotReady(t *testing.T) {
	prev := activePeerServer.Swap(nil)
	t.Cleanup(func() { activePeerServer.Store(prev) })
	req := httptest.NewRequest(http.MethodPost, "http://100.64.0.1/dns-query", strings.NewReader("x"))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	dispatchPeerDNS(fakePeer{addr: netip.MustParseAddrPort("100.64.0.2:1")}, rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", rec.Code)
	}
}

type fakePeer struct {
	addr netip.AddrPort
}

func (f fakePeer) Peer() tailcfg.NodeView               { return tailcfg.NodeView{} }
func (f fakePeer) PeerCaps() tailcfg.PeerCapMap         { return nil }
func (f fakePeer) CanDebug() bool                       { return false }
func (f fakePeer) Self() tailcfg.NodeView               { return tailcfg.NodeView{} }
func (f fakePeer) LocalBackend() *ipnlocal.LocalBackend { return nil }
func (f fakePeer) IsSelfUntagged() bool                 { return false }
func (f fakePeer) RemoteAddr() netip.AddrPort           { return f.addr }
func (f fakePeer) Logf(string, ...any)                  {}

func postPeerDNS(t *testing.T, server *Server, peer netip.AddrPort, query []byte) []byte {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://100.64.0.1/dns-query", bytes.NewReader(query))
	req.Header.Set("Content-Type", "application/dns-message")
	return doPeerDNS(t, server, peer, req)
}

func getPeerDNS(t *testing.T, server *Server, peer netip.AddrPort, query []byte) []byte {
	t.Helper()
	q := base64.RawURLEncoding.EncodeToString(query)
	req := httptest.NewRequest(http.MethodGet, "http://100.64.0.1/dns-query?dns="+q, nil)
	return doPeerDNS(t, server, peer, req)
}

func doPeerDNS(t *testing.T, server *Server, peer netip.AddrPort, req *http.Request) []byte {
	t.Helper()
	rec := httptest.NewRecorder()
	server.ServePeerDNS(fakePeer{addr: peer}, rec, req)
	res := rec.Result()
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body %s", res.StatusCode, body)
	}
	if res.Header.Get("Content-Type") != "application/dns-message" {
		t.Fatalf("content type = %q", res.Header.Get("Content-Type"))
	}
	return body
}

func answerOn(t *testing.T, server *Server, addr string, query []byte) []byte {
	t.Helper()
	pc := &replyConn{}
	udp, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	server.handleQuery(context.Background(), pc, udp, query, "tcp")
	if len(pc.reply) == 0 {
		t.Fatal("port 53 handler wrote no response")
	}
	return pc.reply
}

func unpackMsg(t *testing.T, raw []byte) *dnsmessage.Message {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		t.Fatal(err)
	}
	return &msg
}

func matchingPeerPrefixes(path string) []string {
	var got []string
	for pfx := range peerAPIHandlerPrefixes {
		if strings.HasPrefix(path, pfx) {
			got = append(got, pfx)
		}
	}
	return got
}

func containsAll(got []string, want ...string) bool {
	have := map[string]bool{}
	for _, v := range got {
		have[v] = true
	}
	for _, v := range want {
		if !have[v] {
			return false
		}
	}
	return true
}
