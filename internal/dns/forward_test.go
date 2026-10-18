package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/backend"
	"github.com/rajsinghtech/tsdnsproxy/internal/cache"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/tailscale/apitype"
)

func TestForwardThroughFakeUpstream(t *testing.T) {
	addr := serveFakeUpstream(t, [4]byte{10, 1, 2, 3}, false)
	server := forwardServer(t, addr)
	raw := askUDP(t, server, "app.example.internal.", dnsmessage.TypeA)
	if messageTruncated(raw) {
		t.Fatal("small answer was truncated")
	}
	ip := mustA(t, raw)
	if ip != [4]byte{10, 1, 2, 3} {
		t.Fatalf("A = %v", ip)
	}
}

func TestForwardRetriesTCPWhenUpstreamTruncates(t *testing.T) {
	addr := serveFakeUpstream(t, [4]byte{10, 4, 5, 6}, true)
	server := forwardServer(t, addr)
	raw := askUDP(t, server, "app.example.internal.", dnsmessage.TypeA)
	if messageTruncated(raw) {
		t.Fatal("client received the truncated upstream answer")
	}
	ip := mustA(t, raw)
	if ip != [4]byte{10, 4, 5, 6} {
		t.Fatalf("A = %v", ip)
	}
}

func forwardServer(t *testing.T, upstream string) *Server {
	t.Helper()
	mgr, err := backend.NewManager(nil, backend.Dialers{
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
		RulesOnly:    true,
		MaxInflight:  8,
		QueryTimeout: 2 * time.Second,
	}
	path := t.TempDir() + "/rules.json"
	if err := os.WriteFile(path, []byte(`{"example.internal":{"dns":["`+upstream+`"],"translateid":-1}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rf, err := grants.OpenRulesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	server.Rules = rf
	t.Cleanup(func() {
		server.WhoisCache.Close()
		server.GrantCache.Close()
	})
	return server
}

func askUDP(t *testing.T, server *Server, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	server.workerPool = make(chan struct{}, 4)
	pc := newFakePacketConn()
	pc.remote = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 5353}
	pc.push(packQuestion(t, 7, name, qtype))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.serveUDP(ctx, pc) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		pc.mu.Lock()
		n := len(pc.writes)
		var raw []byte
		if n > 0 {
			raw = append([]byte(nil), pc.writes[0]...)
		}
		pc.mu.Unlock()
		if n > 0 {
			cancel()
			<-done
			return raw
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	t.Fatal("no udp response")
	return nil
}

func mustA(t *testing.T, raw []byte) [4]byte {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		t.Fatal(err)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("answers = %d rcode = %v", len(msg.Answers), msg.RCode)
	}
	a, ok := msg.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("body %T", msg.Answers[0].Body)
	}
	return a.A
}

func serveFakeUpstream(t *testing.T, ip [4]byte, truncateUDP bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = pc.Close()
	})
	go func() {
		buf := make([]byte, 65535)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				if isTimeout(err) {
					continue
				}
				return
			}
			resp := fakeAnswer(buf[:n], ip)
			if truncateUDP && len(resp) >= 3 {
				resp[2] |= 0x02
			}
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				var hdr [2]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(hdr[:]))
				q := make([]byte, n)
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				resp := fakeAnswer(q, ip)
				binary.BigEndian.PutUint16(hdr[:], uint16(len(resp)))
				_, _ = c.Write(hdr[:])
				_, _ = c.Write(resp)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func fakeAnswer(query []byte, ip [4]byte) []byte {
	var q dnsmessage.Message
	if err := q.Unpack(query); err != nil || len(q.Questions) == 0 {
		resp := make([]byte, 12)
		if len(query) >= 2 {
			resp[0], resp[1] = query[0], query[1]
		}
		resp[2] = 0x80
		return resp
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true},
		Questions: q.Questions,
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30,
			},
			Body: &dnsmessage.AResource{A: ip},
		}},
	}
	raw, err := msg.Pack()
	if err != nil {
		return []byte{byte(q.ID >> 8), byte(q.ID), 0x80, 2}
	}
	return raw
}
