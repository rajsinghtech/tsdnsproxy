package backend

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestQueryUsesUDPWhenComplete(t *testing.T) {
	var udpN, tcpN atomic.Int32
	addr := serveDNS(t, func(q []byte) []byte {
		udpN.Add(1)
		return dnsAnswer(q, [4]byte{10, 1, 2, 3})
	}, func(q []byte) []byte {
		tcpN.Add(1)
		return dnsAnswer(q, [4]byte{10, 9, 9, 9})
	})
	b := NewUDPBackend(addr, HostDialer(), nil)
	b.timeout = 2 * time.Second
	got, err := b.Query(context.Background(), dnsQuestion(t))
	if err != nil {
		t.Fatal(err)
	}
	if tcpN.Load() != 0 || udpN.Load() == 0 {
		t.Fatalf("udp calls=%d tcp calls=%d", udpN.Load(), tcpN.Load())
	}
	if !bytesEqual(dnsA(t, got), [4]byte{10, 1, 2, 3}) {
		t.Fatalf("answer = %v", dnsA(t, got))
	}
}

func TestQueryFallsBackToTCPWhenTruncated(t *testing.T) {
	addr := serveDNS(t, func(q []byte) []byte {
		resp := dnsAnswer(q, [4]byte{10, 0, 0, 1})
		resp[2] |= 0x02
		return resp
	}, func(q []byte) []byte {
		return dnsAnswer(q, [4]byte{10, 8, 8, 8})
	})
	b := NewUDPBackend(addr, HostDialer(), nil)
	b.timeout = 2 * time.Second
	got, err := b.Query(context.Background(), dnsQuestion(t))
	if err != nil {
		t.Fatal(err)
	}
	if messageHasTC(got) {
		t.Fatal("tcp fallback still truncated")
	}
	if !bytesEqual(dnsA(t, got), [4]byte{10, 8, 8, 8}) {
		t.Fatalf("answer = %v", dnsA(t, got))
	}
}

func TestQueryFallsBackToTCPWhenUDPClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	pc, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = pc.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				var nbuf [2]byte
				if _, err := io.ReadFull(c, nbuf[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(nbuf[:]))
				q := make([]byte, n)
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				resp := dnsAnswer(q, [4]byte{10, 2, 2, 2})
				var hdr [2]byte
				binary.BigEndian.PutUint16(hdr[:], uint16(len(resp)))
				_, _ = c.Write(hdr[:])
				_, _ = c.Write(resp)
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	b := NewUDPBackend(ln.Addr().String(), HostDialer(), nil)
	b.timeout = 2 * time.Second
	got, err := b.Query(context.Background(), dnsQuestion(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(dnsA(t, got), [4]byte{10, 2, 2, 2}) {
		t.Fatalf("answer = %v", dnsA(t, got))
	}
	if port == 0 {
		t.Fatal("port")
	}
}

func TestQueryRejectsMismatchedUDPThenUsesTCP(t *testing.T) {
	addr := serveDNS(t, func(q []byte) []byte {
		resp := dnsAnswer(q, [4]byte{1, 1, 1, 1})
		resp[0] ^= 0xff
		return resp
	}, func(q []byte) []byte {
		return dnsAnswer(q, [4]byte{10, 3, 3, 3})
	})
	b := NewUDPBackend(addr, HostDialer(), nil)
	b.timeout = 2 * time.Second
	got, err := b.Query(context.Background(), dnsQuestion(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(dnsA(t, got), [4]byte{10, 3, 3, 3}) {
		t.Fatalf("answer = %v", dnsA(t, got))
	}
}

func TestDialContextHonorsCancel(t *testing.T) {
	release := make(chan struct{})
	d := &ignoreCtxDialer{release: release, finished: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := dialContext(ctx, d, "udp", "127.0.0.1:53")
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("err=%v elapsed=%s", err, time.Since(start))
	}
	close(release)
	select {
	case <-d.finished:
	case <-time.After(2 * time.Second):
		t.Fatal("dial goroutine did not finish")
	}
}

func TestMarkUnhealthyDoesNotPanic(t *testing.T) {
	m, err := NewManager(nil, Dialers{Default: DialDirect}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for i := 0; i < 80; i++ {
		m.markUnhealthy("10.0.0.53:53")
	}
	if !m.isUnhealthy("10.0.0.53:53") {
		t.Fatal("expected unhealthy")
	}
	m.Close()
}

func TestWithUpstreamEDNS(t *testing.T) {
	q := dnsQuestion(t)
	got := withUpstreamEDNS(q, 1232)
	var msg dnsmessage.Message
	if err := msg.Unpack(got); err != nil {
		t.Fatal(err)
	}
	var saw bool
	for _, extra := range msg.Additionals {
		if extra.Header.Type == dnsmessage.TypeOPT {
			saw = true
			if int(extra.Header.Class) != 1232 {
				t.Fatalf("opt class = %d", extra.Header.Class)
			}
		}
	}
	if !saw {
		t.Fatal("missing opt")
	}
	if withUpstreamEDNS([]byte{1, 2, 3}, 1232) == nil {
		t.Fatal("short query")
	}
}

type ignoreCtxDialer struct {
	release  chan struct{}
	finished chan struct{}
}

func (d *ignoreCtxDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	defer close(d.finished)
	<-d.release
	return nil, errors.New("released")
}

func serveDNS(t *testing.T, udpFn, tcpFn func([]byte) []byte) string {
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
				if isNetTimeout(err) {
					continue
				}
				return
			}
			resp := udpFn(append([]byte(nil), buf[:n]...))
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
				var nbuf [2]byte
				if _, err := io.ReadFull(c, nbuf[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(nbuf[:]))
				if n < 12 || n > 65535 {
					return
				}
				q := make([]byte, n)
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				resp := tcpFn(q)
				var hdr [2]byte
				binary.BigEndian.PutUint16(hdr[:], uint16(len(resp)))
				_, _ = c.Write(hdr[:])
				_, _ = c.Write(resp)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func dnsQuestion(t *testing.T) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0x1234, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName("app.example.internal."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	raw, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func dnsAnswer(query []byte, ip [4]byte) []byte {
	var q dnsmessage.Message
	if err := q.Unpack(query); err != nil || len(q.Questions) == 0 {
		resp := make([]byte, 12)
		if len(query) >= 2 {
			resp[0], resp[1] = query[0], query[1]
		}
		resp[2] = 0x80
		resp[3] = 2
		return resp
	}
	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true},
		Questions: q.Questions,
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30,
			},
			Body: &dnsmessage.AResource{A: ip},
		}},
	}
	raw, err := resp.Pack()
	if err != nil {
		resp := make([]byte, 12)
		resp[0], resp[1] = query[0], query[1]
		resp[2] = 0x80
		resp[3] = 2
		return resp
	}
	return raw
}

func dnsA(t *testing.T, raw []byte) [4]byte {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		t.Fatal(err)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("answers = %d", len(msg.Answers))
	}
	a, ok := msg.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("body %T", msg.Answers[0].Body)
	}
	return a.A
}

func isNetTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func messageHasTC(raw []byte) bool {
	return len(raw) >= 3 && raw[2]&0x02 != 0
}

func bytesEqual(a, b [4]byte) bool { return a == b }
