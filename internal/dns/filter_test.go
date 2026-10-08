package dns

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"golang.org/x/net/dns/dnsmessage"
)

func TestTranslationAddressFilters(t *testing.T) {
	tests := []struct {
		name        string
		grants      []grants.GrantConfig
		qtype       dnsmessage.Type
		backendIP   [4]byte
		wantAnswers int
		wantType    dnsmessage.Type
		wantA       [4]byte
		wantPrefix  string
	}{
		{
			name:        "eligible address is translated",
			grants:      []grants.GrantConfig{{"site-a.example": {DNS: []string{"10.1.0.10:53"}, TranslateID: translateID(1)}}},
			qtype:       dnsmessage.TypeAAAA,
			backendIP:   [4]byte{10, 1, 2, 3},
			wantAnswers: 1,
			wantType:    dnsmessage.TypeAAAA,
			wantPrefix:  "fd7a:115c:a1e0:b1a:0:1:",
		},
		{
			name:        "shared range is served unchanged on A",
			grants:      []grants.GrantConfig{{"site-a.example": {DNS: []string{"10.1.0.10:53"}, TranslateID: translateID(1)}}},
			qtype:       dnsmessage.TypeA,
			backendIP:   [4]byte{100, 64, 1, 5},
			wantAnswers: 1,
			wantType:    dnsmessage.TypeA,
			wantA:       [4]byte{100, 64, 1, 5},
		},
		{
			name:        "shared range is not synthesized",
			grants:      []grants.GrantConfig{{"site-a.example": {DNS: []string{"10.1.0.10:53"}, TranslateID: translateID(1)}}},
			qtype:       dnsmessage.TypeAAAA,
			backendIP:   [4]byte{100, 64, 1, 5},
			wantAnswers: 0,
		},
		{
			name: "allowips can opt the shared range back in",
			grants: []grants.GrantConfig{{"site-a.example": {
				DNS: []string{"10.1.0.10:53"}, TranslateID: translateID(1), AllowIPs: []string{"100.64.0.0/10"},
			}}},
			qtype:       dnsmessage.TypeAAAA,
			backendIP:   [4]byte{100, 64, 1, 5},
			wantAnswers: 1,
			wantType:    dnsmessage.TypeAAAA,
			wantPrefix:  "fd7a:115c:a1e0:b1a:0:1:",
		},
		{
			name: "denyips leaves an otherwise eligible address unchanged",
			grants: []grants.GrantConfig{{"site-a.example": {
				DNS: []string{"10.1.0.10:53"}, TranslateID: translateID(1), DenyIPs: []string{"10.1.2.0/24"},
			}}},
			qtype:       dnsmessage.TypeA,
			backendIP:   [4]byte{10, 1, 2, 9},
			wantAnswers: 1,
			wantType:    dnsmessage.TypeA,
			wantA:       [4]byte{10, 1, 2, 9},
		},
		{
			name: "allowips drops addresses outside the list",
			grants: []grants.GrantConfig{{"site-a.example": {
				DNS: []string{"10.1.0.10:53"}, TranslateID: translateID(1), AllowIPs: []string{"192.168.0.0/16"},
			}}},
			qtype:       dnsmessage.TypeAAAA,
			backendIP:   [4]byte{10, 1, 2, 3},
			wantAnswers: 0,
		},
		{
			name: "prefix rule selects a different site",
			grants: []grants.GrantConfig{{
				"site-a.example": {DNS: []string{"10.1.0.10:53"}, TranslateID: translateID(1)},
				"10.9.0.0/16":    {TranslateID: translateID(2)},
			}},
			qtype:       dnsmessage.TypeAAAA,
			backendIP:   [4]byte{10, 9, 1, 8},
			wantAnswers: 1,
			wantType:    dnsmessage.TypeAAAA,
			wantPrefix:  "fd7a:115c:a1e0:b1a:0:2:",
		},
		{
			name: "prefix rule with site zero leaves the address unchanged",
			grants: []grants.GrantConfig{{
				"site-a.example": {DNS: []string{"10.1.0.10:53"}, TranslateID: translateID(1)},
				"10.9.0.0/16":    {TranslateID: translateID(0)},
			}},
			qtype:       dnsmessage.TypeA,
			backendIP:   [4]byte{10, 9, 1, 8},
			wantAnswers: 1,
			wantType:    dnsmessage.TypeA,
			wantA:       [4]byte{10, 9, 1, 8},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := &Server{
				BackendMgr:  &mockBackendManager{backend: aRecordBackend(tc.backendIP)},
				GrantParser: grants.NewParser(),
				Logf:        t.Logf,
			}
			query := &dnsmessage.Message{
				Header: dnsmessage.Header{ID: 7},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("app.site-a.example."),
					Type:  tc.qtype,
					Class: dnsmessage.ClassINET,
				}},
			}
			domain, grant, ok := server.GrantParser.FindBestMatch("app.site-a.example", tc.grants)
			if !ok {
				t.Fatal("missing domain grant")
			}
			raw, err := server.handleAuthoritative4via6(query, &grant, domain, tc.grants)
			if err != nil {
				t.Fatalf("handle: %v", err)
			}
			var resp dnsmessage.Message
			if err := resp.Unpack(raw); err != nil {
				t.Fatal(err)
			}
			if resp.RCode != dnsmessage.RCodeSuccess {
				t.Fatalf("rcode %v", resp.RCode)
			}
			if len(resp.Answers) != tc.wantAnswers {
				t.Fatalf("answers = %d, want %d", len(resp.Answers), tc.wantAnswers)
			}
			if tc.wantAnswers == 0 {
				return
			}
			if resp.Answers[0].Header.Type != tc.wantType {
				t.Fatalf("type %v", resp.Answers[0].Header.Type)
			}
			switch tc.wantType {
			case dnsmessage.TypeA:
				body := resp.Answers[0].Body.(*dnsmessage.AResource)
				if body.A != tc.wantA {
					t.Fatalf("A = %v, want %v", body.A, tc.wantA)
				}
			case dnsmessage.TypeAAAA:
				body := resp.Answers[0].Body.(*dnsmessage.AAAAResource)
				addr := netip.AddrFrom16(body.AAAA)
				if !strings.HasPrefix(addr.String(), tc.wantPrefix) {
					t.Fatalf("AAAA %s, want prefix %s", addr, tc.wantPrefix)
				}
			}
		})
	}
}

func aRecordBackend(ip [4]byte) *mockBackend {
	return &mockBackend{queryFunc: func(ctx context.Context, query []byte) ([]byte, error) {
		var q dnsmessage.Message
		if err := q.Unpack(query); err != nil {
			return nil, err
		}
		resp := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: q.ID, Response: true, RCode: dnsmessage.RCodeSuccess},
			Questions: q.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60,
				},
				Body: &dnsmessage.AResource{A: ip},
			}},
		}
		return resp.Pack()
	}}
}
