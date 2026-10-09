package dns

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

func TestServeUDPWithFakeConn(t *testing.T) {
	server := serverWithGrants(t, []grants.GrantConfig{{
		"test.local": {DNS: []string{"10.0.0.1:53"}, TranslateID: translateID(-1)},
	}}, aRecordBackend([4]byte{10, 1, 2, 3}))
	server.workerPool = make(chan struct{}, 2)

	pc := newFakePacketConn()
	pc.remote = &net.UDPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 5353}
	pc.push([]byte{0, 1, 2, 3})
	pc.push(packQuestion(t, 4, "svc.test.local.", dnsmessage.TypeA))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.serveUDP(ctx, pc) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pc.writeCount() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pc.writeCount() == 0 {
		t.Fatal("udp loop wrote no response")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("serveUDP: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveUDP did not return")
	}
}

func TestServeUDPDropsWhenPoolFull(t *testing.T) {
	server := &Server{workerPool: make(chan struct{}), Logf: t.Logf}
	pc := newFakePacketConn()
	pc.remote = &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}
	pc.push(packQuestion(t, 1, "svc.test.local.", dnsmessage.TypeA))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.serveUDP(ctx, pc) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("serveUDP: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveUDP did not return")
	}
	if pc.writeCount() != 0 {
		t.Fatalf("dropped query wrote %d responses", pc.writeCount())
	}
}

func TestServeTCPWithFakeConn(t *testing.T) {
	server := serverWithGrants(t, []grants.GrantConfig{{
		"test.local": {DNS: []string{"10.0.0.1:53"}, TranslateID: translateID(-1)},
	}}, aRecordBackend([4]byte{10, 2, 3, 4}))
	server.workerPool = make(chan struct{}, 2)

	client, serverConn := net.Pipe()
	conn := &addrConn{Conn: serverConn, remote: &net.TCPAddr{IP: net.IPv4(10, 9, 8, 7), Port: 5353}}
	ln := newFakeListener()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.serveTCP(ctx, ln) }()
	ln.conns <- conn

	writeTCPMsg(t, client, packQuestion(t, 8, "svc.test.local.", dnsmessage.TypeA))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	raw := readTCPMsg(t, client)
	var resp dnsmessage.Message
	if err := resp.Unpack(raw); err != nil {
		t.Fatal(err)
	}
	if resp.ID != 8 || resp.RCode != dnsmessage.RCodeSuccess || len(resp.Answers) != 1 {
		t.Fatalf("tcp response id=%d rcode=%v answers=%d", resp.ID, resp.RCode, len(resp.Answers))
	}
	_ = client.Close()
	cancel()
	_ = ln.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("serveTCP: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveTCP did not return")
	}
}

func TestRunUDPAndRunTCPCancel(t *testing.T) {
	server := &Server{workerPool: make(chan struct{}, 1), Logf: t.Logf}
	ctx, cancel := context.WithCancel(context.Background())
	udpDone := make(chan error, 1)
	tcpDone := make(chan error, 1)
	go func() { udpDone <- server.runUDP(ctx, "127.0.0.1:0") }()
	go func() { tcpDone <- server.runTCP(ctx, "127.0.0.1:0") }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	for _, ch := range []chan error{udpDone, tcpDone} {
		select {
		case err := <-ch:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("listener: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("listener did not return after cancel")
		}
	}
}

func TestShouldUseTSNet(t *testing.T) {
	server := &Server{}
	if server.shouldUseTSNet("127.0.0.1:53") || server.shouldUseTSNet("0.0.0.0:53") || server.shouldUseTSNet("[::]:53") {
		t.Fatal("local addresses use the host network")
	}
	if !server.shouldUseTSNet("100.64.0.1:53") || !server.shouldUseTSNet("not-an-addr") {
		t.Fatal("other addresses use the embedded listener")
	}
}

func TestLoadServerGrantsPaths(t *testing.T) {
	t.Run("no self address", func(t *testing.T) {
		server := &Server{Logf: t.Logf, GrantParser: grants.NewParser(), LocalClient: &mockLocalClient{}}
		if err := server.loadServerGrants(context.Background(), &ipnstate.Status{}); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("whois failure", func(t *testing.T) {
		server := &Server{
			Logf:        t.Logf,
			GrantParser: grants.NewParser(),
			LocalClient: &mockLocalClient{whoisFunc: func(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
				return nil, io.EOF
			}},
		}
		status := &ipnstate.Status{Self: &ipnstate.PeerStatus{TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")}}}
		if err := server.loadServerGrants(context.Background(), status); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("loads grant", func(t *testing.T) {
		server := &Server{
			Logf:        t.Logf,
			GrantParser: grants.NewParser(),
			LocalClient: &mockLocalClient{whoisFunc: func(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{
					Node: &tailcfg.Node{Name: "self.example"},
					CapMap: tailcfg.PeerCapMap{
						"rajsingh.info/cap/tsdnsproxy": {`{"site-a.example":{"dns":["10.1.0.10:53"],"translateid":1}}`},
					},
				}, nil
			}},
		}
		status := &ipnstate.Status{Self: &ipnstate.PeerStatus{TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")}}}
		if err := server.loadServerGrants(context.Background(), status); err != nil {
			t.Fatal(err)
		}
		server.grantsMu.RLock()
		defer server.grantsMu.RUnlock()
		if len(server.serverGrants) != 1 {
			t.Fatalf("grants = %d", len(server.serverGrants))
		}
	})
}

func TestTCPResponseWriterStubs(t *testing.T) {
	w := &tcpResponseWriter{}
	if _, _, err := w.ReadFrom(nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil || w.LocalAddr() != nil {
		t.Fatal(err)
	}
	if err := w.SetDeadline(time.Time{}); err != nil || w.SetReadDeadline(time.Time{}) != nil || w.SetWriteDeadline(time.Time{}) != nil {
		t.Fatal(err)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type fakePacketConn struct {
	mu       sync.Mutex
	inbound  [][]byte
	remote   net.Addr
	writes   [][]byte
	deadline time.Time
	closed   bool
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}}
}

func (f *fakePacketConn) push(packet []byte) {
	f.mu.Lock()
	f.inbound = append(f.inbound, append([]byte(nil), packet...))
	f.mu.Unlock()
}

func (f *fakePacketConn) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

func (f *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		remote := f.remote
		if len(f.inbound) > 0 {
			pkt := f.inbound[0]
			f.inbound = f.inbound[1:]
			f.mu.Unlock()
			n := copy(b, pkt)
			return n, remote, nil
		}
		deadline := f.deadline
		f.mu.Unlock()
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, nil, timeoutError{}
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (f *fakePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	f.mu.Lock()
	f.writes = append(f.writes, append([]byte(nil), p...))
	f.mu.Unlock()
	return len(p), nil
}

func (f *fakePacketConn) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

func (f *fakePacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (f *fakePacketConn) SetDeadline(t time.Time) error {
	return f.SetReadDeadline(t)
}

func (f *fakePacketConn) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.deadline = t
	f.mu.Unlock()
	return nil
}

func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

type fakeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newFakeListener() *fakeListener {
	return &fakeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (f *fakeListener) Accept() (net.Conn, error) {
	select {
	case c := <-f.conns:
		return c, nil
	case <-f.closed:
		return nil, net.ErrClosed
	}
}

func (f *fakeListener) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0} }

type addrConn struct {
	net.Conn
	remote net.Addr
}

func (a addrConn) RemoteAddr() net.Addr             { return a.remote }
func (a addrConn) SetDeadline(time.Time) error      { return nil }
func (a addrConn) SetReadDeadline(time.Time) error  { return nil }
func (a addrConn) SetWriteDeadline(time.Time) error { return nil }
