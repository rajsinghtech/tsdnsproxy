package dns

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"golang.org/x/net/dns/dnsmessage"
)

func TestClientUDPLimit(t *testing.T) {
	q := &dnsmessage.Message{Header: dnsmessage.Header{ID: 1}}
	if got := clientUDPLimit(q, 0); got != minUDPPayload {
		t.Fatalf("no edns = %d", got)
	}
	q.Additionals = []dnsmessage.Resource{optResource(4096)}
	if got := clientUDPLimit(q, 0); got != defaultMaxUDP {
		t.Fatalf("capped = %d", got)
	}
	if got := clientUDPLimit(q, 4096); got != 4096 {
		t.Fatalf("raised cap = %d", got)
	}
	q.Additionals = []dnsmessage.Resource{optResource(1200)}
	if got := clientUDPLimit(q, 0); got != 1200 {
		t.Fatalf("client size = %d", got)
	}
}

func TestFitUDPPassesSmallResponse(t *testing.T) {
	q := question(t, "a.example.internal.")
	raw := mustPack(t, answerA(q, [4]byte{10, 0, 0, 1}))
	got, err := fitUDP(q, raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatal("small response was rewritten")
	}
	if messageTruncated(got) {
		t.Fatal("small response set TC")
	}
}

func TestFitUDPTruncatesOversize(t *testing.T) {
	q := question(t, "big.example.internal.")
	resp := answerTXT(q, strings.Repeat("x", 900))
	raw := mustPack(t, resp)
	if len(raw) <= minUDPPayload {
		t.Fatalf("fixture is %d bytes, want > %d", len(raw), minUDPPayload)
	}
	got, err := fitUDP(q, raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > minUDPPayload {
		t.Fatalf("truncated len = %d", len(got))
	}
	if !messageTruncated(got) {
		t.Fatal("TC bit clear")
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(got); err != nil {
		t.Fatal(err)
	}
	if len(msg.Answers) != 0 || msg.ID != q.ID {
		t.Fatalf("truncated message id=%d answers=%d", msg.ID, len(msg.Answers))
	}
}

func TestFitUDPHonorsEDNS(t *testing.T) {
	q := question(t, "edns.example.internal.")
	q.Additionals = []dnsmessage.Resource{optResource(1200)}
	resp := answerTXT(q, strings.Repeat("y", 700))
	resp.Additionals = nil
	raw := mustPack(t, resp)
	if len(raw) <= minUDPPayload || len(raw) > 1200 {
		t.Fatalf("fixture len = %d", len(raw))
	}
	got, err := fitUDP(q, raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	if messageTruncated(got) {
		t.Fatal("response within EDNS size was truncated")
	}

	huge := answerTXT(q, strings.Repeat("z", 1400))
	huge.Additionals = nil
	raw = mustPack(t, huge)
	got, err = fitUDP(q, raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !messageTruncated(got) || len(got) > 1200 {
		t.Fatalf("edns truncate len=%d tc=%v", len(got), messageTruncated(got))
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(got); err != nil {
		t.Fatal(err)
	}
	if !hasOPT(&msg) {
		t.Fatal("truncated EDNS response dropped OPT")
	}
}

func TestFitUDPRejectsGarbageByTruncating(t *testing.T) {
	q := question(t, "a.example.internal.")
	raw := append([]byte{0, 9, 0x02, 0}, make([]byte, 600)...)
	got, err := fitUDP(q, raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !messageTruncated(got) || len(got) > minUDPPayload {
		t.Fatalf("garbage fit len=%d", len(got))
	}
}

func TestHandleQueryTruncatesUDPOnly(t *testing.T) {
	q := question(t, "big.example.internal.")
	q.Questions[0].Type = dnsmessage.TypeTXT
	huge := answerTXT(q, strings.Repeat("x", 1400))
	raw := mustPack(t, huge)
	backend := &mockBackend{queryFunc: func(ctx context.Context, query []byte) ([]byte, error) {
		return raw, nil
	}}
	id := translateID(-1)
	server := serverWithGrants(t, []grants.GrantConfig{{
		"example.internal": {DNS: []string{"10.0.0.1:53"}, TranslateID: id},
	}}, backend)

	udp := &mockPacketConn{}
	var udpGot []byte
	udp.writeToFunc = func(b []byte, addr net.Addr) (int, error) {
		udpGot = append([]byte(nil), b...)
		return len(b), nil
	}
	packet := mustPack(t, q)
	server.handleQuery(context.Background(), udp, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 53}, packet, "udp")
	if !messageTruncated(udpGot) {
		t.Fatalf("udp response len=%d tc=%v", len(udpGot), messageTruncated(udpGot))
	}

	tcp := &mockPacketConn{}
	var tcpGot []byte
	tcp.writeToFunc = func(b []byte, addr net.Addr) (int, error) {
		tcpGot = append([]byte(nil), b...)
		return len(b), nil
	}
	server.handleQuery(context.Background(), tcp, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 53}, packet, "tcp")
	if messageTruncated(tcpGot) || len(tcpGot) <= minUDPPayload {
		t.Fatalf("tcp response len=%d tc=%v", len(tcpGot), messageTruncated(tcpGot))
	}
}

func question(t *testing.T, name string) *dnsmessage.Message {
	t.Helper()
	return &dnsmessage.Message{
		Header: dnsmessage.Header{ID: 9, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(name),
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET,
		}},
	}
}

func answerA(q *dnsmessage.Message, ip [4]byte) *dnsmessage.Message {
	resp := *q
	resp.Response = true
	resp.Questions = append([]dnsmessage.Question(nil), q.Questions...)
	resp.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{
			Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30,
		},
		Body: &dnsmessage.AResource{A: ip},
	}}
	return &resp
}

func answerTXT(q *dnsmessage.Message, text string) *dnsmessage.Message {
	resp := *q
	resp.Response = true
	resp.Questions = append([]dnsmessage.Question(nil), q.Questions...)
	resp.Additionals = nil
	var chunks []string
	for len(text) > 0 {
		n := 255
		if len(text) < n {
			n = len(text)
		}
		chunks = append(chunks, text[:n])
		text = text[n:]
	}
	resp.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{
			Name: q.Questions[0].Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 30,
		},
		Body: &dnsmessage.TXTResource{TXT: chunks},
	}}
	return &resp
}

func optResource(size int) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: dnsmessage.Class(size),
		},
		Body: &dnsmessage.OPTResource{},
	}
}

func mustPack(t *testing.T, msg *dnsmessage.Message) []byte {
	t.Helper()
	raw, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
