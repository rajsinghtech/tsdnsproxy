package dns

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/cache"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

func TestResolveRejectsOverlongName(t *testing.T) {
	server := &Server{Logf: t.Logf}
	// MustNewName panics once the string is longer than 255 bytes.
	name := strings.Repeat("a", 255) + "."
	if len(name) <= 255 {
		t.Fatalf("fixture length = %d, want > 255", len(name))
	}

	if _, err := server.resolveToIPv4(name, []string{"10.0.0.1:53"}); err == nil {
		t.Fatal("resolveToIPv4 returned nil error for an overlong name")
	}
	if _, err := server.resolveToIPv6(name, []string{"10.0.0.1:53"}); err == nil {
		t.Fatal("resolveToIPv6 returned nil error for an overlong name")
	}
}

func TestOverlongRewriteReturnsSERVFAIL(t *testing.T) {
	// A short query plus a long rewrite target exceeds the 255-byte name limit.
	rewrite := strings.Repeat("b", 300)
	cases := []struct {
		name  string
		id    string // JSON literal, or empty to omit the field
		qtype dnsmessage.Type
	}{
		{name: "explicit zero A", id: "0", qtype: dnsmessage.TypeA},
		{name: "explicit zero AAAA", id: "0", qtype: dnsmessage.TypeAAAA},
		{name: "positive AAAA", id: "4", qtype: dnsmessage.TypeAAAA},
		{name: "omitted A", id: "", qtype: dnsmessage.TypeA},
		{name: "negative MX", id: "-1", qtype: dnsmessage.TypeMX},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := `{"z":{"dns":["10.0.0.1:53"],"rewrite":"` + rewrite + `"}}`
			if tc.id != "" {
				raw = `{"z":{"dns":["10.0.0.1:53"],"rewrite":"` + rewrite + `","translateid":` + tc.id + `}}`
			}
			var calls atomic.Int32
			backend := &mockBackend{queryFunc: func(ctx context.Context, query []byte) ([]byte, error) {
				calls.Add(1)
				return nil, fmt.Errorf("backend should not be queried")
			}}
			server := serverWithGrants(t, []grants.GrantConfig{mustGrant(t, raw)}, backend)
			pc := &mockPacketConn{}
			var got []byte
			pc.writeToFunc = func(b []byte, addr net.Addr) (int, error) {
				got = append([]byte(nil), b...)
				return len(b), nil
			}

			packet := packQuestion(t, 42, "aaaa.z.", tc.qtype)
			server.handleQuery(context.Background(), pc, &net.UDPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 5353}, packet, "udp")

			if calls.Load() != 0 {
				t.Fatalf("backend calls = %d, want 0", calls.Load())
			}
			if len(got) == 0 {
				t.Fatal("no DNS response written")
			}
			var resp dnsmessage.Message
			if err := resp.Unpack(got); err != nil {
				t.Fatalf("unpack response: %v", err)
			}
			if resp.RCode != dnsmessage.RCodeServerFailure {
				t.Fatalf("RCode = %v, want SERVFAIL", resp.RCode)
			}
			if resp.ID != 42 {
				t.Fatalf("ID = %d, want 42", resp.ID)
			}
		})
	}
}

func TestProcessQueryTranslateIDModes(t *testing.T) {
	tests := []struct {
		name        string
		grantJSON   string
		qtype       dnsmessage.Type
		wantErr     bool
		wantRCode   dnsmessage.RCode
		wantAnswers int
		wantAnsType dnsmessage.Type
		wantBackend bool
		wantQType   dnsmessage.Type
		wantVia     bool
	}{
		{
			name:        "omitted forwards MX",
			grantJSON:   `{"test.local":{"dns":["10.0.0.1:53"]}}`,
			qtype:       dnsmessage.TypeMX,
			wantRCode:   dnsmessage.RCodeSuccess,
			wantAnswers: 1,
			wantAnsType: dnsmessage.TypeMX,
			wantBackend: true,
			wantQType:   dnsmessage.TypeMX,
		},
		{
			name:        "explicit zero is authoritative for A",
			grantJSON:   `{"test.local":{"dns":["10.0.0.1:53"],"translateid":0}}`,
			qtype:       dnsmessage.TypeA,
			wantRCode:   dnsmessage.RCodeSuccess,
			wantAnswers: 1,
			wantAnsType: dnsmessage.TypeA,
			wantBackend: true,
			wantQType:   dnsmessage.TypeA,
		},
		{
			name:        "explicit zero returns empty MX",
			grantJSON:   `{"test.local":{"dns":["10.0.0.1:53"],"translateid":0}}`,
			qtype:       dnsmessage.TypeMX,
			wantRCode:   dnsmessage.RCodeSuccess,
			wantAnswers: 0,
		},
		{
			name:        "explicit zero returns empty TXT",
			grantJSON:   `{"test.local":{"dns":["10.0.0.1:53"],"translateid":0}}`,
			qtype:       dnsmessage.TypeTXT,
			wantRCode:   dnsmessage.RCodeSuccess,
			wantAnswers: 0,
		},
		{
			name:        "positive returns empty A",
			grantJSON:   `{"test.local":{"dns":["10.0.0.1:53"],"translateid":4}}`,
			qtype:       dnsmessage.TypeA,
			wantRCode:   dnsmessage.RCodeSuccess,
			wantAnswers: 0,
			wantBackend: true,
			wantQType:   dnsmessage.TypeA,
		},
		{
			name:        "positive synthesizes AAAA",
			grantJSON:   `{"test.local":{"dns":["10.0.0.1:53"],"translateid":4}}`,
			qtype:       dnsmessage.TypeAAAA,
			wantRCode:   dnsmessage.RCodeSuccess,
			wantAnswers: 1,
			wantAnsType: dnsmessage.TypeAAAA,
			wantBackend: true,
			wantQType:   dnsmessage.TypeA,
			wantVia:     true,
		},
		{
			name:        "negative forwards TXT",
			grantJSON:   `{"test.local":{"dns":["10.0.0.1:53"],"translateid":-1}}`,
			qtype:       dnsmessage.TypeTXT,
			wantRCode:   dnsmessage.RCodeSuccess,
			wantAnswers: 1,
			wantAnsType: dnsmessage.TypeTXT,
			wantBackend: true,
			wantQType:   dnsmessage.TypeTXT,
		},
		{
			name:        "negative forwards MX",
			grantJSON:   `{"test.local":{"dns":["10.0.0.1:53"],"translateid":-5}}`,
			qtype:       dnsmessage.TypeMX,
			wantRCode:   dnsmessage.RCodeSuccess,
			wantAnswers: 1,
			wantAnsType: dnsmessage.TypeMX,
			wantBackend: true,
			wantQType:   dnsmessage.TypeMX,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			var saw atomic.Uint32
			backend := &mockBackend{queryFunc: func(ctx context.Context, query []byte) ([]byte, error) {
				var q dnsmessage.Message
				if err := q.Unpack(query); err != nil {
					return nil, err
				}
				calls.Add(1)
				if len(q.Questions) > 0 {
					saw.Store(uint32(q.Questions[0].Type))
				}
				return answerLikeQuestion(q)
			}}
			server := &Server{
				GrantParser: grants.NewParser(),
				BackendMgr:  &mockBackendManager{backend: backend},
				Logf:        t.Logf,
			}
			query := &dnsmessage.Message{
				Header: dnsmessage.Header{ID: 9, RecursionDesired: true},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("svc.test.local."),
					Type:  tc.qtype,
					Class: dnsmessage.ClassINET,
				}},
			}
			response, err := server.processQuery(context.Background(), query, []grants.GrantConfig{mustGrant(t, tc.grantJSON)}, netip.Addr{})
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("processQuery: %v", err)
			}
			var resp dnsmessage.Message
			if err := resp.Unpack(response); err != nil {
				t.Fatalf("unpack: %v", err)
			}
			if resp.RCode != tc.wantRCode {
				t.Fatalf("RCode = %v, want %v", resp.RCode, tc.wantRCode)
			}
			if len(resp.Answers) != tc.wantAnswers {
				t.Fatalf("answers = %d, want %d", len(resp.Answers), tc.wantAnswers)
			}
			if tc.wantAnswers > 0 && resp.Answers[0].Header.Type != tc.wantAnsType {
				t.Fatalf("answer type = %v, want %v", resp.Answers[0].Header.Type, tc.wantAnsType)
			}
			if tc.wantAnsType == dnsmessage.TypeA && resp.Answers[0].Header.TTL != 300 {
				t.Fatalf("TTL = %d, want 300", resp.Answers[0].Header.TTL)
			}
			if tc.wantVia {
				aaaa, ok := resp.Answers[0].Body.(*dnsmessage.AAAAResource)
				if !ok {
					t.Fatalf("answer body = %T, want AAAA", resp.Answers[0].Body)
				}
				addr := netip.AddrFrom16(aaaa.AAAA)
				if !strings.HasPrefix(addr.String(), "fd7a:115c:a1e0:b1a:0:4:") {
					t.Fatalf("synthetic address = %s, want site 4 prefix", addr)
				}
			}
			gotCalls := calls.Load() > 0
			if gotCalls != tc.wantBackend {
				t.Fatalf("backend queried = %v, want %v", gotCalls, tc.wantBackend)
			}
			if tc.wantBackend && dnsmessage.Type(saw.Load()) != tc.wantQType {
				t.Fatalf("backend question = %v, want %v", dnsmessage.Type(saw.Load()), tc.wantQType)
			}
		})
	}
}

func TestProcessQueryRejectsSiteIDAboveMax(t *testing.T) {
	server := &Server{
		GrantParser: grants.NewParser(),
		BackendMgr:  &mockBackendManager{backend: &mockBackend{}},
		Logf:        t.Logf,
	}
	query := &dnsmessage.Message{
		Header: dnsmessage.Header{ID: 3},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName("svc.test.local."),
			Type:  dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET,
		}},
	}
	grant := grants.GrantConfig{
		"test.local": {DNS: []string{"10.0.0.1:53"}, TranslateID: translateID(grants.MaxTranslateID + 1)},
	}
	_, err := server.processQuery(context.Background(), query, []grants.GrantConfig{grant}, netip.Addr{})
	if err == nil {
		t.Fatal("expected error for translateid above 65535")
	}
}

func TestHandleQueryRecoversAndReturnsSERVFAIL(t *testing.T) {
	var logs strings.Builder
	var mu sync.Mutex
	server := newPanicServer(t, func(format string, args ...any) {
		mu.Lock()
		fmt.Fprintf(&logs, format, args...)
		logs.WriteByte('\n')
		mu.Unlock()
	})
	pc := &mockPacketConn{}
	var got []byte
	pc.writeToFunc = func(b []byte, addr net.Addr) (int, error) {
		got = append([]byte(nil), b...)
		return len(b), nil
	}
	packet := packQuestion(t, 11, "svc.test.local.", dnsmessage.TypeA)
	addr := &net.UDPAddr{IP: net.IPv4(10, 9, 8, 7), Port: 53}

	server.handleQuery(context.Background(), pc, addr, packet, "udp")

	assertPanicSERVFAIL(t, got, 11, logs.String(), "udp")
}

func TestTCPAndServiceRecoverPerQuery(t *testing.T) {
	for _, via := range []string{"tcp", "service"} {
		t.Run(via, func(t *testing.T) {
			var logs strings.Builder
			var mu sync.Mutex
			var calls atomic.Int32
			server := newPanicServer(t, func(format string, args ...any) {
				mu.Lock()
				fmt.Fprintf(&logs, format, args...)
				logs.WriteByte('\n')
				mu.Unlock()
			})
			server.BackendMgr = &mockBackendManager{backend: &mockBackend{queryFunc: func(ctx context.Context, query []byte) ([]byte, error) {
				calls.Add(1)
				var q dnsmessage.Message
				if err := q.Unpack(query); err != nil {
					return nil, err
				}
				return answerLikeQuestion(q)
			}}}

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			t.Cleanup(func() { _ = ln.Close() })

			client, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("deadline: %v", err)
			}

			serverConn, err := ln.Accept()
			if err != nil {
				t.Fatalf("accept: %v", err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				server.handleTCPConnection(context.Background(), serverConn, via)
			}()

			writeTCPMsg(t, client, packQuestion(t, 1, "svc.test.local.", dnsmessage.TypeA))
			first := readTCPMsg(t, client)
			assertPanicSERVFAIL(t, first, 1, "", via)

			writeTCPMsg(t, client, packQuestion(t, 2, "svc.test.local.", dnsmessage.TypeMX))
			secondRaw := readTCPMsg(t, client)
			var second dnsmessage.Message
			if err := second.Unpack(secondRaw); err != nil {
				t.Fatalf("unpack second: %v", err)
			}
			if second.ID != 2 || second.RCode != dnsmessage.RCodeSuccess || len(second.Answers) != 1 {
				t.Fatalf("second response id=%d rcode=%v answers=%d, want success with one answer", second.ID, second.RCode, len(second.Answers))
			}
			if second.Answers[0].Header.Type != dnsmessage.TypeMX {
				t.Fatalf("second answer type = %v, want MX", second.Answers[0].Header.Type)
			}
			if calls.Load() == 0 {
				t.Fatal("second query did not reach the backend")
			}

			_ = client.Close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("connection handler did not return")
			}
			mu.Lock()
			logged := logs.String()
			mu.Unlock()
			if !strings.Contains(logged, "panic handling "+via+" query") {
				t.Fatalf("log %q does not mention a %s query panic", logged, via)
			}
		})
	}
}

func newPanicServer(t *testing.T, logf func(string, ...any)) *Server {
	t.Helper()
	var n atomic.Int32
	server := &Server{
		LocalClient: &mockLocalClient{whoisFunc: func(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
			if n.Add(1) == 1 {
				panic("injected query panic")
			}
			return &apitype.WhoIsResponse{
				Node: &tailcfg.Node{Name: "node.example"},
				CapMap: tailcfg.PeerCapMap{
					"rajsingh.info/cap/tsdnsproxy": {
						`{"test.local":{"dns":["10.0.0.1:53"],"translateid":-1}}`,
					},
				},
			}, nil
		}},
		WhoisCache:  cache.NewWhoisCache(time.Minute),
		GrantCache:  cache.NewGrantCache(time.Minute),
		GrantParser: grants.NewParser(),
		BackendMgr:  &mockBackendManager{backend: &mockBackend{}},
		Logf:        logf,
	}
	t.Cleanup(func() {
		server.WhoisCache.Close()
		server.GrantCache.Close()
	})
	return server
}

func serverWithGrants(t *testing.T, cfgs []grants.GrantConfig, backend *mockBackend) *Server {
	t.Helper()
	server := &Server{
		LocalClient: &mockLocalClient{whoisFunc: func(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
			return nil, fmt.Errorf("no whois")
		}},
		WhoisCache:   cache.NewWhoisCache(time.Minute),
		GrantCache:   cache.NewGrantCache(time.Minute),
		GrantParser:  grants.NewParser(),
		BackendMgr:   &mockBackendManager{backend: backend},
		Logf:         t.Logf,
		serverGrants: cfgs,
	}
	t.Cleanup(func() {
		server.WhoisCache.Close()
		server.GrantCache.Close()
	})
	return server
}

func mustGrant(t *testing.T, raw string) grants.GrantConfig {
	t.Helper()
	var cfg grants.GrantConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("grant json: %v", err)
	}
	return cfg
}

func packQuestion(t *testing.T, id uint16, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(name),
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack question: %v", err)
	}
	return packed
}

func answerLikeQuestion(q dnsmessage.Message) ([]byte, error) {
	if len(q.Questions) == 0 {
		return nil, fmt.Errorf("no question")
	}
	question := q.Questions[0]
	ans := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  question.Name,
			Type:  question.Type,
			Class: question.Class,
			TTL:   60,
		},
	}
	switch question.Type {
	case dnsmessage.TypeA:
		ans.Body = &dnsmessage.AResource{A: [4]byte{10, 0, 0, 8}}
	case dnsmessage.TypeAAAA:
		ans.Body = &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8}}
	case dnsmessage.TypeMX:
		ans.Body = &dnsmessage.MXResource{Pref: 10, MX: dnsmessage.MustNewName("mail.test.")}
	case dnsmessage.TypeTXT:
		ans.Body = &dnsmessage.TXTResource{TXT: []string{"ok"}}
	default:
		return nil, fmt.Errorf("unsupported question type %v", question.Type)
	}
	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: q.Questions,
		Answers:   []dnsmessage.Resource{ans},
	}
	return resp.Pack()
}

func assertPanicSERVFAIL(t *testing.T, raw []byte, id uint16, logText, via string) {
	t.Helper()
	if len(raw) == 0 {
		t.Fatal("expected a SERVFAIL response")
	}
	var resp dnsmessage.Message
	if err := resp.Unpack(raw); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if resp.ID != id {
		t.Fatalf("ID = %d, want %d", resp.ID, id)
	}
	if resp.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("RCode = %v, want SERVFAIL", resp.RCode)
	}
	if logText != "" && !strings.Contains(logText, "panic handling "+via+" query") {
		t.Fatalf("log %q does not mention a %s query panic", logText, via)
	}
}

func writeTCPMsg(t *testing.T, w io.Writer, payload []byte) {
	t.Helper()
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		t.Fatalf("write length: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
}

func readTCPMsg(t *testing.T, r io.Reader) []byte {
	t.Helper()
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatalf("read length: %v", err)
	}
	buf := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	return buf
}
