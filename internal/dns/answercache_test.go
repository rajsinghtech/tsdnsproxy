package dns

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/cache"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"github.com/rajsinghtech/tsdnsproxy/internal/metrics"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

func TestAnswerCacheTTLAndID(t *testing.T) {
	clk := newTestClock(time.Unix(1_700_000_000, 0))
	c := newAnswerCache(8, 0, time.Hour, nil)
	c.now = clk.now
	q1 := qmsg(1, "app.example.internal.")
	key := newAnswerKey(q1, grantSet(4), netip.Addr{})
	var calls atomic.Int32
	load := func() ([]byte, error) {
		calls.Add(1)
		return packedA(1, "app.example.internal.", 2, [4]byte{10, 1, 2, 3}), nil
	}
	first, hit, err := c.lookup(q1, key, load)
	if err != nil || hit {
		t.Fatalf("first hit=%v err=%v", hit, err)
	}
	if idOf(t, first) != 1 {
		t.Fatalf("id %d", idOf(t, first))
	}
	clk.add(time.Second)
	q2 := qmsg(99, "APP.example.internal.")
	second, hit, err := c.lookup(q2, newAnswerKey(q2, grantSet(4), netip.Addr{}), load)
	if err != nil || !hit {
		t.Fatalf("second hit=%v err=%v", hit, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("loads %d", calls.Load())
	}
	msg := unpackMsg(t, second)
	if msg.ID != 99 {
		t.Fatalf("id %d", msg.ID)
	}
	if msg.Questions[0].Name.String() != "APP.example.internal." {
		t.Fatalf("name %s", msg.Questions[0].Name)
	}
	if msg.Answers[0].Header.TTL != 1 {
		t.Fatalf("ttl %d", msg.Answers[0].Header.TTL)
	}
	if msg.Answers[0].Header.Name.String() != "APP.example.internal." {
		t.Fatalf("answer name %s", msg.Answers[0].Header.Name)
	}
	clk.add(time.Second)
	if _, hit, err = c.lookup(qmsg(3, "app.example.internal."), key, load); err != nil || hit {
		t.Fatalf("expired hit=%v err=%v", hit, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("loads after expiry %d", calls.Load())
	}
}

func TestAnswerCacheNegativeSOA(t *testing.T) {
	clk := newTestClock(time.Unix(1_700_000_000, 0))
	c := newAnswerCache(4, 0, time.Hour, nil)
	c.now = clk.now
	q := qmsg(5, "missing.example.internal.")
	key := newAnswerKey(q, nil, netip.Addr{})
	var calls atomic.Int32
	load := func() ([]byte, error) {
		calls.Add(1)
		return packedNXDOMAIN(5, "missing.example.internal.", 100, 30), nil
	}
	if _, _, err := c.lookup(q, key, load); err != nil {
		t.Fatal(err)
	}
	clk.add(10 * time.Second)
	got, hit, err := c.lookup(qmsg(6, "missing.example.internal."), key, load)
	if err != nil || !hit {
		t.Fatalf("hit=%v err=%v", hit, err)
	}
	msg := unpackMsg(t, got)
	if msg.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("rcode %v", msg.RCode)
	}
	if msg.ID != 6 {
		t.Fatalf("id %d", msg.ID)
	}
	soa := msg.Authorities[0]
	if soa.Header.TTL != 90 {
		t.Fatalf("soa ttl %d", soa.Header.TTL)
	}
	if body, ok := soa.Body.(*dnsmessage.SOAResource); !ok || body.MinTTL != 30 {
		t.Fatalf("soa minimum %#v", soa.Body)
	}
	clk.add(20 * time.Second)
	if _, hit, err = c.lookup(q, key, load); err != nil || hit {
		t.Fatalf("after minimum hit=%v err=%v", hit, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("loads %d", calls.Load())
	}
}

func TestAnswerCachePeerIsolation(t *testing.T) {
	c := newAnswerCache(8, 0, time.Hour, nil)
	q := qmsg(1, "app.example.internal.")
	keyA := newAnswerKey(q, grantSet(1), netip.Addr{})
	keyB := newAnswerKey(q, grantSet(2), netip.Addr{})
	if keyA == keyB {
		t.Fatal("different grants hashed the same")
	}
	reordered := newAnswerKey(q, grantSetReversed(1), netip.MustParseAddr("10.1.2.3"))
	plain := newAnswerKey(q, grantSet(1), netip.MustParseAddr("10.9.9.9"))
	if reordered != plain {
		t.Fatal("equivalent rules did not share a key")
	}
	var callsA, callsB atomic.Int32
	if _, _, err := c.lookup(q, keyA, func() ([]byte, error) {
		callsA.Add(1)
		return packedA(1, "app.example.internal.", 60, [4]byte{10, 0, 0, 1}), nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.lookup(q, keyB, func() ([]byte, error) {
		callsB.Add(1)
		return packedA(1, "app.example.internal.", 60, [4]byte{10, 0, 0, 2}), nil
	}); err != nil {
		t.Fatal(err)
	}
	got, hit, err := c.lookup(qmsg(8, "app.example.internal."), keyA, func() ([]byte, error) {
		t.Fatal("peer A should hit")
		return nil, nil
	})
	if err != nil || !hit {
		t.Fatalf("hit=%v err=%v", hit, err)
	}
	ip := mustA(t, got)
	if ip != [4]byte{10, 0, 0, 1} {
		t.Fatalf("peer A got %v", ip)
	}
	got, _, err = c.lookup(qmsg(9, "app.example.internal."), keyB, func() ([]byte, error) {
		t.Fatal("peer B should hit")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if mustA(t, got) != [4]byte{10, 0, 0, 2} {
		t.Fatalf("peer B got %v", mustA(t, got))
	}
	if callsA.Load() != 1 || callsB.Load() != 1 {
		t.Fatalf("loads A=%d B=%d", callsA.Load(), callsB.Load())
	}
}

func TestAnswerCacheSourceAndFlags(t *testing.T) {
	q := qmsg(1, "10-0-0-1.ip.")
	shared := []grants.GrantConfig{{
		"ip": {IPNames: &grants.IPNamesConfig{SiteID: pint(1)}},
	}}
	a := newAnswerKey(q, shared, netip.MustParseAddr("10.0.0.1"))
	b := newAnswerKey(q, shared, netip.MustParseAddr("10.0.0.2"))
	if a != b {
		t.Fatal("source changed the key when the rules do not read it")
	}
	bound := []grants.GrantConfig{{
		"ip": {IPNames: &grants.IPNamesConfig{SiteID: pint(1), AllowSrc: []string{"10.0.0.0/8"}}},
	}}
	in := newAnswerKey(q, bound, netip.MustParseAddr("10.0.0.1"))
	out := newAnswerKey(q, bound, netip.MustParseAddr("192.0.2.1"))
	if in == out {
		t.Fatal("allowsrc rules shared a key across clients")
	}
	direct := []grants.GrantConfig{{
		"ip": {IPNames: &grants.IPNamesConfig{SiteID: pint(1), A: "direct", DirectSrc: []string{"10.0.0.0/8"}}},
	}}
	if newAnswerKey(q, direct, netip.MustParseAddr("10.0.0.1")) == newAnswerKey(q, direct, netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("direct rules shared a key across clients")
	}
	withDO := qmsg(1, "app.example.internal.")
	hdr := dnsmessage.ResourceHeader{}
	if err := hdr.SetEDNS0(1232, 0, true); err != nil {
		t.Fatal(err)
	}
	withDO.Additionals = []dnsmessage.Resource{{Header: hdr, Body: &dnsmessage.OPTResource{}}}
	plain := qmsg(1, "app.example.internal.")
	if newAnswerKey(withDO, nil, netip.Addr{}) == newAnswerKey(plain, nil, netip.Addr{}) {
		t.Fatal("DO bit was ignored")
	}
	cd := qmsg(1, "app.example.internal.")
	cd.CheckingDisabled = true
	if newAnswerKey(cd, nil, netip.Addr{}) == newAnswerKey(plain, nil, netip.Addr{}) {
		t.Fatal("CD bit was ignored")
	}
}

func TestAnswerCacheSkipsTruncatedAndClamps(t *testing.T) {
	c := newAnswerCache(4, 5*time.Second, 10*time.Second, nil)
	q := qmsg(1, "app.example.internal.")
	key := newAnswerKey(q, nil, netip.Addr{})
	var calls atomic.Int32
	tc := packedA(1, "app.example.internal.", 60, [4]byte{10, 0, 0, 1})
	var msg dnsmessage.Message
	if err := msg.Unpack(tc); err != nil {
		t.Fatal(err)
	}
	msg.Truncated = true
	truncated, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	load := func() ([]byte, error) {
		calls.Add(1)
		return truncated, nil
	}
	if _, _, err := c.lookup(q, key, load); err != nil {
		t.Fatal(err)
	}
	if _, hit, err := c.lookup(q, key, load); err != nil || hit {
		t.Fatalf("truncated was cached hit=%v err=%v", hit, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("loads %d", calls.Load())
	}

	clk := newTestClock(time.Unix(1_700_000_000, 0))
	c.now = clk.now
	long := newAnswerKey(qmsg(1, "long.example.internal."), nil, netip.Addr{})
	if _, _, err := c.lookup(qmsg(1, "long.example.internal."), long, func() ([]byte, error) {
		return packedA(1, "long.example.internal.", 86400, [4]byte{10, 0, 0, 9}), nil
	}); err != nil {
		t.Fatal(err)
	}
	clk.add(11 * time.Second)
	var again atomic.Int32
	if _, hit, err := c.lookup(qmsg(1, "long.example.internal."), long, func() ([]byte, error) {
		again.Add(1)
		return packedA(1, "long.example.internal.", 86400, [4]byte{10, 0, 0, 9}), nil
	}); err != nil || hit || again.Load() != 1 {
		t.Fatalf("max ttl hit=%v err=%v loads=%d", hit, err, again.Load())
	}
}

func TestAnswerCacheServfailIsShort(t *testing.T) {
	clk := newTestClock(time.Unix(1_700_000_000, 0))
	c := newAnswerCache(4, time.Minute, time.Hour, nil)
	c.now = clk.now
	q := qmsg(4, "app.example.internal.")
	key := newAnswerKey(q, nil, netip.Addr{})
	var calls atomic.Int32
	load := func() ([]byte, error) {
		calls.Add(1)
		return nil, fmt.Errorf("upstream down")
	}
	if _, _, err := c.lookup(q, key, load); err == nil {
		t.Fatal("expected error")
	}
	got, hit, err := c.lookup(qmsg(5, "app.example.internal."), key, load)
	if err != nil || !hit {
		t.Fatalf("cached servfail hit=%v err=%v", hit, err)
	}
	if unpackMsg(t, got).RCode != dnsmessage.RCodeServerFailure || unpackMsg(t, got).ID != 5 {
		t.Fatalf("response id=%d rcode=%v", unpackMsg(t, got).ID, unpackMsg(t, got).RCode)
	}
	clk.add(5 * time.Second)
	if _, _, err := c.lookup(q, key, load); err == nil {
		t.Fatal("expected a fresh error after the short ttl")
	}
	if calls.Load() != 2 {
		t.Fatalf("loads %d", calls.Load())
	}
}

func TestAnswerCacheEvictsLRU(t *testing.T) {
	m := metrics.New()
	c := newAnswerCache(1, 0, time.Hour, m)
	for i, name := range []string{"a.example.internal.", "b.example.internal."} {
		q := qmsg(1, name)
		if _, _, err := c.lookup(q, newAnswerKey(q, nil, netip.Addr{}), func() ([]byte, error) {
			return packedA(1, name, 30, [4]byte{10, 0, 0, byte(i + 1)}), nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if c.order.Len() != 1 {
		t.Fatalf("size %d", c.order.Len())
	}
	body := metricText(t, m)
	if !containsCount(body, "tsdnsproxy_cache_evictions_total", "1") {
		t.Fatalf("evictions\n%s", body)
	}
}

func TestAnswerCacheConcurrentMiss(t *testing.T) {
	c := newAnswerCache(8, 0, time.Hour, nil)
	q := qmsg(1, "app.example.internal.")
	key := newAnswerKey(q, grantSet(1), netip.Addr{})
	raw := packedA(1, "app.example.internal.", 30, [4]byte{10, 1, 2, 3})
	var calls atomic.Int32
	release := make(chan struct{})
	var once sync.Once
	started := make(chan struct{})
	var joined atomic.Int32
	c.joined = func() { joined.Add(1) }
	const n = 32
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		id := uint16(i + 1)
		go func() {
			defer wg.Done()
			qq := qmsg(id, "app.example.internal.")
			got, _, err := c.lookup(qq, key, func() ([]byte, error) {
				calls.Add(1)
				once.Do(func() { close(started) })
				<-release
				return raw, nil
			})
			if err != nil {
				errCh <- err
				return
			}
			gotID, idErr := messageID(got)
			if idErr != nil {
				errCh <- idErr
				return
			}
			if gotID != id {
				errCh <- fmt.Errorf("id %d want %d", gotID, id)
			}
		}()
	}
	<-started
	deadline := time.Now().Add(2 * time.Second)
	for joined.Load() < n-1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if joined.Load() != n-1 {
		t.Fatalf("joined %d", joined.Load())
	}
	close(release)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("loads %d", calls.Load())
	}
}

func TestAnswerCachePanicReleasesWaiter(t *testing.T) {
	c := newAnswerCache(4, 0, time.Hour, nil)
	q := qmsg(1, "app.example.internal.")
	key := newAnswerKey(q, nil, netip.Addr{})
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	joined := make(chan struct{})
	c.joined = func() { close(joined) }
	panicked := make(chan struct{})
	go func() {
		defer func() {
			if recover() != nil {
				close(panicked)
			}
		}()
		_, _, _ = c.lookup(q, key, func() ([]byte, error) {
			once.Do(func() { close(started) })
			<-release
			panic("boom")
		})
	}()
	<-started
	waiter := make(chan error, 1)
	go func() {
		_, _, err := c.lookup(qmsg(2, "app.example.internal."), key, func() ([]byte, error) {
			return nil, fmt.Errorf("waiter loaded")
		})
		waiter <- err
	}()
	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not join")
	}
	close(release)
	select {
	case <-panicked:
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not panic")
	}
	select {
	case err := <-waiter:
		if err == nil {
			t.Fatal("waiter succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter hung")
	}
}

func TestHandleQueryCachesPeersSeparately(t *testing.T) {
	var calls atomic.Int32
	inner := ipv4Backend([4]byte{10, 0, 0, 1})
	server := &Server{
		LocalClient: &mockLocalClient{whoisFunc: func(_ context.Context, addr string) (*apitype.WhoIsResponse, error) {
			id := 1
			name := "a.example.ts.net"
			if addr == "100.64.0.3" {
				id = 2
				name = "b.example.ts.net"
			}
			return &apitype.WhoIsResponse{
				Node: &tailcfg.Node{Name: name},
				CapMap: tailcfg.PeerCapMap{
					grants.DefaultCapName: {tailcfg.RawMessage(grantJSON(id))},
				},
			}, nil
		}},
		WhoisCache:  cache.NewWhoisCache(time.Minute),
		GrantCache:  cache.NewGrantCache(time.Minute),
		GrantParser: grants.NewParser(),
		BackendMgr: &mockBackendManager{backend: &mockBackend{queryFunc: func(ctx context.Context, query []byte) ([]byte, error) {
			calls.Add(1)
			return inner.Query(ctx, query)
		}}},
		Logf: t.Logf,
	}
	t.Cleanup(func() {
		server.WhoisCache.Close()
		server.GrantCache.Close()
	})
	clk := newTestClock(time.Unix(1_700_000_000, 0))
	server.answers = newAnswerCache(16, 0, time.Hour, nil)
	server.answers.now = clk.now

	first := askServer(t, server, net.IPv4(100, 64, 0, 2), 7, "app.example.internal.", dnsmessage.TypeAAAA)
	other := askServer(t, server, net.IPv4(100, 64, 0, 3), 8, "app.example.internal.", dnsmessage.TypeAAAA)
	if mustAAAA(t, first) == mustAAAA(t, other) {
		t.Fatal("peers with different grants received the same answer")
	}
	clk.add(10 * time.Second)
	again := askServer(t, server, net.IPv4(100, 64, 0, 2), 99, "app.example.internal.", dnsmessage.TypeAAAA)
	if again.ID != 99 {
		t.Fatalf("id %d", again.ID)
	}
	if mustAAAA(t, again) != mustAAAA(t, first) {
		t.Fatal("cached answer changed")
	}
	if again.Answers[0].Header.TTL != 290 {
		t.Fatalf("ttl %d", again.Answers[0].Header.TTL)
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream calls %d", calls.Load())
	}
}

type testClock struct{ n atomic.Int64 }

func newTestClock(t time.Time) *testClock {
	c := &testClock{}
	c.set(t)
	return c
}

func (c *testClock) set(t time.Time) { c.n.Store(t.UnixNano()) }

func (c *testClock) add(d time.Duration) { c.n.Add(int64(d)) }

func (c *testClock) now() time.Time { return time.Unix(0, c.n.Load()).UTC() }

func qmsg(id uint16, name string) *dnsmessage.Message {
	return &dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(name),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
}

func grantSet(id int) []grants.GrantConfig {
	return []grants.GrantConfig{{
		"example.internal": {DNS: []string{"10.0.0.53:53"}, TranslateID: pint(id), AllowIPs: []string{"10.0.0.0/8"}},
		"other.example":    {DNS: []string{"10.0.0.54:53"}, TranslateID: pint(-1)},
	}}
}

func grantSetReversed(id int) []grants.GrantConfig {
	return []grants.GrantConfig{{
		"other.example":    {DNS: []string{"10.0.0.54:53"}, TranslateID: pint(-1)},
		"example.internal": {AllowIPs: []string{"10.0.0.0/8"}, DNS: []string{"10.0.0.53:53"}, TranslateID: pint(id)},
	}}
}

func pint(v int) *int { return &v }

func grantJSON(id int) string {
	return fmt.Sprintf(`{"example.internal":{"dns":["10.0.0.53:53"],"translateid":%d,"allowips":["10.0.0.0/8"]}}`, id)
}

func packedA(id uint16, name string, ttl uint32, ip [4]byte) []byte {
	qname := dnsmessage.MustNewName(name)
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{{Name: qname, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: qname, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl},
			Body:   &dnsmessage.AResource{A: ip},
		}},
	}
	raw, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return raw
}

func packedNXDOMAIN(id uint16, name string, soaTTL, minimum uint32) []byte {
	qname := dnsmessage.MustNewName(name)
	ns := dnsmessage.MustNewName("ns.example.internal.")
	mbox := dnsmessage.MustNewName("hostmaster.example.internal.")
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Response: true, Authoritative: true, RCode: dnsmessage.RCodeNameError},
		Questions: []dnsmessage.Question{{Name: qname, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Authorities: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example.internal."), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: soaTTL},
			Body: &dnsmessage.SOAResource{
				NS: ns, MBox: mbox, Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, MinTTL: minimum,
			},
		}},
	}
	raw, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return raw
}

func idOf(t *testing.T, raw []byte) uint16 {
	t.Helper()
	return unpackMsg(t, raw).ID
}

func askServer(t *testing.T, server *Server, ip net.IP, id uint16, name string, qtype dnsmessage.Type) *dnsmessage.Message {
	t.Helper()
	pc := &mockPacketConn{}
	var got []byte
	pc.writeToFunc = func(b []byte, _ net.Addr) (int, error) {
		got = append([]byte(nil), b...)
		return len(b), nil
	}
	server.handleQuery(context.Background(), pc, &net.UDPAddr{IP: ip, Port: 5353}, packQuestion(t, id, name, qtype), "udp")
	if len(got) == 0 {
		t.Fatal("no response")
	}
	return unpackMsg(t, got)
}

func metricText(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rr := httptest.NewRecorder()
	m.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, err := io.ReadAll(rr.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func containsCount(body, name, want string) bool {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, name) && strings.HasSuffix(strings.TrimSpace(line), " "+want) {
			return true
		}
	}
	return false
}

func messageID(raw []byte) (uint16, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		return 0, err
	}
	return msg.ID, nil
}
