package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/backend"
	"github.com/rajsinghtech/tsdnsproxy/internal/cache"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// mockLocalClient implements a mock Tailscale LocalClient for testing
type mockLocalClient struct {
	whoisFunc  func(ctx context.Context, addr string) (*apitype.WhoIsResponse, error)
	statusFunc func(ctx context.Context) (*ipnstate.Status, error)
}

func (m *mockLocalClient) WhoIs(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
	if m.whoisFunc != nil {
		return m.whoisFunc(ctx, addr)
	}
	return &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			Name: "test-node.example.com",
		},
	}, nil
}

func (m *mockLocalClient) Status(ctx context.Context) (*ipnstate.Status, error) {
	if m.statusFunc != nil {
		return m.statusFunc(ctx)
	}
	return &ipnstate.Status{}, nil
}

// mockBackend implements a test DNS backend
type mockBackend struct {
	queryFunc func(ctx context.Context, query []byte) ([]byte, error)
}

func (m *mockBackend) Query(ctx context.Context, query []byte) ([]byte, error) {
	if m.queryFunc != nil {
		return m.queryFunc(ctx, query)
	}
	// Default: echo the query back as response
	return query, nil
}

func (m *mockBackend) String() string {
	return "mock-backend"
}

// mockBackendManager implements a mock backend manager for testing
type mockBackendManager struct {
	backend backend.Backend
}

func (m *mockBackendManager) Query(ctx context.Context, backends []backend.Backend, query []byte) ([]byte, error) {
	if m.backend != nil {
		return m.backend.Query(ctx, query)
	}
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backends available")
	}
	return backends[0].Query(ctx, query)
}

func (m *mockBackendManager) CreateBackends(servers []string) []backend.Backend {
	if m.backend != nil {
		return []backend.Backend{m.backend}
	}
	return nil
}

func TestServer_unrewriteResponse(t *testing.T) {
	server := &Server{
		Logf: func(format string, args ...any) {
			t.Logf(format, args...)
		},
	}

	tests := []struct {
		name         string
		response     *dnsmessage.Message
		originalName string
		validate     func(t *testing.T, response *dnsmessage.Message)
	}{
		{
			name: "unrewrite_with_question_section",
			response: &dnsmessage.Message{
				Header: dnsmessage.Header{
					Response: true,
				},
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("service.cluster.local."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("service.cluster.local."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   300,
						},
						Body: &dnsmessage.AResource{
							A: [4]byte{10, 0, 0, 1},
						},
					},
				},
			},
			originalName: "service.cluster1.local.",
			validate: func(t *testing.T, response *dnsmessage.Message) {
				// Check question was updated
				if len(response.Questions) != 1 {
					t.Fatalf("expected 1 question, got %d", len(response.Questions))
				}
				if response.Questions[0].Name.String() != "service.cluster1.local." {
					t.Errorf("question name = %s, want service.cluster1.local.", response.Questions[0].Name)
				}
				// Check answer was updated to match the original query domain
				if len(response.Answers) != 1 {
					t.Fatalf("expected 1 answer, got %d", len(response.Answers))
				}
				if response.Answers[0].Header.Name.String() != "service.cluster1.local." {
					t.Errorf("answer name = %s, want service.cluster1.local.", response.Answers[0].Header.Name)
				}
			},
		},
		{
			name: "unrewrite_with_authority_section",
			response: &dnsmessage.Message{
				Header: dnsmessage.Header{
					Response: true,
				},
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("service.cluster.local."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
				Authorities: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("cluster.local."),
							Type:  dnsmessage.TypeSOA,
							Class: dnsmessage.ClassINET,
							TTL:   300,
						},
						Body: &dnsmessage.SOAResource{
							NS:      dnsmessage.MustNewName("ns1.cluster.local."),
							MBox:    dnsmessage.MustNewName("admin.cluster.local."),
							Serial:  1,
							Refresh: 3600,
							Retry:   600,
							Expire:  86400,
							MinTTL:  300,
						},
					},
				},
			},
			originalName: "service.cluster1.local.",
			validate: func(t *testing.T, response *dnsmessage.Message) {
				if len(response.Authorities) != 1 {
					t.Fatalf("expected 1 authority, got %d", len(response.Authorities))
				}
				// Authority section should NOT be updated (it should remain as returned by backend)
				if response.Authorities[0].Header.Name.String() != "cluster.local." {
					t.Errorf("authority name = %s, want cluster.local.", response.Authorities[0].Header.Name)
				}
			},
		},
		{
			name: "unrewrite_with_additional_section",
			response: &dnsmessage.Message{
				Header: dnsmessage.Header{
					Response: true,
				},
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("service.cluster.local."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
				Additionals: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("ns1.cluster.local."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   300,
						},
						Body: &dnsmessage.AResource{
							A: [4]byte{10, 0, 0, 10},
						},
					},
				},
			},
			originalName: "service.cluster1.local.",
			validate: func(t *testing.T, response *dnsmessage.Message) {
				if len(response.Additionals) != 1 {
					t.Fatalf("expected 1 additional, got %d", len(response.Additionals))
				}
				// Additional records should NOT be updated (they should remain as returned by backend)
				if response.Additionals[0].Header.Name.String() != "ns1.cluster.local." {
					t.Errorf("additional name = %s, want ns1.cluster.local.", response.Additionals[0].Header.Name)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origName := dnsmessage.MustNewName(tt.originalName)
			server.unrewriteResponse(tt.response, origName)
			tt.validate(t, tt.response)
		})
	}
}

func TestServer_translate4via6(t *testing.T) {
	server := &Server{
		Logf: func(format string, args ...any) {
			t.Logf(format, args...)
		},
	}

	tests := []struct {
		name          string
		response      *dnsmessage.Message
		originalQuery *dnsmessage.Message
		siteID        uint32
		validate      func(t *testing.T, response *dnsmessage.Message)
	}{
		{
			name: "AAAA_query_translates_A_to_AAAA",
			response: &dnsmessage.Message{
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("test.example.com."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   300,
						},
						Body: &dnsmessage.AResource{
							A: [4]byte{10, 0, 0, 1}, // 10.0.0.1
						},
					},
				},
			},
			originalQuery: &dnsmessage.Message{
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("test.example.com."),
						Type:  dnsmessage.TypeAAAA,
						Class: dnsmessage.ClassINET,
					},
				},
			},
			siteID: 1,
			validate: func(t *testing.T, response *dnsmessage.Message) {
				if len(response.Answers) != 1 {
					t.Fatalf("expected 1 answer, got %d", len(response.Answers))
				}
				ans := response.Answers[0]
				if ans.Header.Type != dnsmessage.TypeAAAA {
					t.Errorf("answer type = %v, want TypeAAAA", ans.Header.Type)
				}
				aaaa, ok := ans.Body.(*dnsmessage.AAAAResource)
				if !ok {
					t.Fatalf("answer body is not AAAAResource")
				}
				// Check the IPv6 address starts with fd7a:115c:a1e0:b1a:0:1:
				// which is the 4via6 prefix for site 1
				addr := netip.AddrFrom16(aaaa.AAAA)
				if !addr.Is6() {
					t.Errorf("result is not IPv6: %v", addr)
				}
				// The address should be in the 4via6 range
				addrStr := addr.String()
				if !strings.HasPrefix(addrStr, "fd7a:115c:a1e0:b1a:0:1:") {
					t.Errorf("4via6 address = %s, want prefix fd7a:115c:a1e0:b1a:0:1:", addrStr)
				}
			},
		},
		{
			name: "A_query_keeps_original_A_record",
			response: &dnsmessage.Message{
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("test.example.com."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   300,
						},
						Body: &dnsmessage.AResource{
							A: [4]byte{10, 0, 0, 1}, // 10.0.0.1
						},
					},
				},
			},
			originalQuery: &dnsmessage.Message{
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("test.example.com."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
			},
			siteID: 1,
			validate: func(t *testing.T, response *dnsmessage.Message) {
				if len(response.Answers) != 1 {
					t.Fatalf("expected 1 answer, got %d", len(response.Answers))
				}
				ans := response.Answers[0]
				if ans.Header.Type != dnsmessage.TypeA {
					t.Errorf("answer type = %v, want TypeA", ans.Header.Type)
				}
				a, ok := ans.Body.(*dnsmessage.AResource)
				if !ok {
					t.Fatalf("answer body is not AResource")
				}
				expected := [4]byte{10, 0, 0, 1}
				if a.A != expected {
					t.Errorf("A record = %v, want %v", a.A, expected)
				}
			},
		},
		{
			name: "preserve_non_A_records",
			response: &dnsmessage.Message{
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("test.example.com."),
							Type:  dnsmessage.TypeCNAME,
							Class: dnsmessage.ClassINET,
							TTL:   300,
						},
						Body: &dnsmessage.CNAMEResource{
							CNAME: dnsmessage.MustNewName("target.example.com."),
						},
					},
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("test.example.com."),
							Type:  dnsmessage.TypeAAAA,
							Class: dnsmessage.ClassINET,
							TTL:   300,
						},
						Body: &dnsmessage.AAAAResource{
							AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8}, // 2001:db8::
						},
					},
				},
			},
			originalQuery: &dnsmessage.Message{
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("test.example.com."),
						Type:  dnsmessage.TypeAAAA,
						Class: dnsmessage.ClassINET,
					},
				},
			},
			siteID: 1,
			validate: func(t *testing.T, response *dnsmessage.Message) {
				if len(response.Answers) != 2 {
					t.Fatalf("expected 2 answers, got %d", len(response.Answers))
				}
				// CNAME should be preserved
				if response.Answers[0].Header.Type != dnsmessage.TypeCNAME {
					t.Errorf("first answer type = %v, want TypeCNAME", response.Answers[0].Header.Type)
				}
				// Existing AAAA should be preserved
				if response.Answers[1].Header.Type != dnsmessage.TypeAAAA {
					t.Errorf("second answer type = %v, want TypeAAAA", response.Answers[1].Header.Type)
				}
			},
		},
		{
			name: "translate_multiple_A_records_for_AAAA_query",
			response: &dnsmessage.Message{
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("test.example.com."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   300,
						},
						Body: &dnsmessage.AResource{
							A: [4]byte{10, 0, 0, 1},
						},
					},
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("test.example.com."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   300,
						},
						Body: &dnsmessage.AResource{
							A: [4]byte{10, 0, 0, 2},
						},
					},
				},
			},
			originalQuery: &dnsmessage.Message{
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("test.example.com."),
						Type:  dnsmessage.TypeAAAA,
						Class: dnsmessage.ClassINET,
					},
				},
			},
			siteID: 2,
			validate: func(t *testing.T, response *dnsmessage.Message) {
				if len(response.Answers) != 2 {
					t.Fatalf("expected 2 answers, got %d", len(response.Answers))
				}
				// Both should be AAAA records
				for i, ans := range response.Answers {
					if ans.Header.Type != dnsmessage.TypeAAAA {
						t.Errorf("answer[%d] type = %v, want TypeAAAA", i, ans.Header.Type)
					}
					aaaa, ok := ans.Body.(*dnsmessage.AAAAResource)
					if !ok {
						t.Fatalf("answer[%d] body is not AAAAResource", i)
					}
					addr := netip.AddrFrom16(aaaa.AAAA)
					// Should have site ID 2 prefix
					if !strings.HasPrefix(addr.String(), "fd7a:115c:a1e0:b1a:0:2:") {
						t.Errorf("answer[%d] 4via6 address = %s, want prefix fd7a:115c:a1e0:b1a:0:2:", i, addr)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server.translate4via6(tt.response, tt.siteID, tt.originalQuery)
			tt.validate(t, tt.response)
		})
	}
}

func TestServer_rewriteQuery(t *testing.T) {
	server := &Server{
		GrantParser: grants.NewParser(),
		Logf: func(format string, args ...any) {
			t.Logf(format, args...)
		},
	}

	tests := []struct {
		name          string
		query         *dnsmessage.Message
		targetDomain  string
		rewriteDomain string
		validate      func(t *testing.T, rewriteed *dnsmessage.Message)
	}{
		{
			name: "rewrite_exact_match",
			query: &dnsmessage.Message{
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("cluster1.local."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
			},
			targetDomain:  "cluster1.local",
			rewriteDomain: "cluster.local",
			validate: func(t *testing.T, rewriteed *dnsmessage.Message) {
				if len(rewriteed.Questions) != 1 {
					t.Fatalf("expected 1 question, got %d", len(rewriteed.Questions))
				}
				if rewriteed.Questions[0].Name.String() != "cluster.local." {
					t.Errorf("rewriteed name = %s, want cluster.local.", rewriteed.Questions[0].Name)
				}
			},
		},
		{
			name: "rewrite_subdomain",
			query: &dnsmessage.Message{
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("service.namespace.cluster1.local."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
			},
			targetDomain:  "cluster1.local",
			rewriteDomain: "cluster.local",
			validate: func(t *testing.T, rewriteed *dnsmessage.Message) {
				if len(rewriteed.Questions) != 1 {
					t.Fatalf("expected 1 question, got %d", len(rewriteed.Questions))
				}
				if rewriteed.Questions[0].Name.String() != "service.namespace.cluster.local." {
					t.Errorf("rewriteed name = %s, want service.namespace.cluster.local.", rewriteed.Questions[0].Name)
				}
			},
		},
		{
			name: "rewrite_multiple_questions",
			query: &dnsmessage.Message{
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("svc1.cluster1.local."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
					{
						Name:  dnsmessage.MustNewName("svc2.cluster1.local."),
						Type:  dnsmessage.TypeAAAA,
						Class: dnsmessage.ClassINET,
					},
				},
			},
			targetDomain:  "cluster1.local",
			rewriteDomain: "cluster.local",
			validate: func(t *testing.T, rewriteed *dnsmessage.Message) {
				if len(rewriteed.Questions) != 2 {
					t.Fatalf("expected 2 questions, got %d", len(rewriteed.Questions))
				}
				if rewriteed.Questions[0].Name.String() != "svc1.cluster.local." {
					t.Errorf("rewriteed name[0] = %s, want svc1.cluster.local.", rewriteed.Questions[0].Name)
				}
				if rewriteed.Questions[1].Name.String() != "svc2.cluster.local." {
					t.Errorf("rewriteed name[1] = %s, want svc2.cluster.local.", rewriteed.Questions[1].Name)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rewriteed := server.rewriteQuery(tt.query, tt.targetDomain, tt.rewriteDomain)
			tt.validate(t, rewriteed)
		})
	}
}

func TestServer_processQuery(t *testing.T) {
	ctx := context.Background()

	mockGrants := []grants.GrantConfig{
		{
			"test.local": grants.DNSGrant{
				DNS:         []string{"10.0.0.10:53"},
				Rewrite:     "prod.local",
				TranslateID: 1,
			},
		},
	}

	// Create a mock backend that returns a simple A record
	mockBackendFunc := func(ctx context.Context, query []byte) ([]byte, error) {
		// Parse the query
		var q dnsmessage.Message
		if err := q.Unpack(query); err != nil {
			return nil, err
		}

		// Build response
		resp := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:       q.ID,
				Response: true,
				RCode:    dnsmessage.RCodeSuccess,
			},
			Questions: q.Questions,
			Answers: []dnsmessage.Resource{
				{
					Header: dnsmessage.ResourceHeader{
						Name:  q.Questions[0].Name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   300,
					},
					Body: &dnsmessage.AResource{
						A: [4]byte{10, 0, 0, 1},
					},
				},
			},
		}

		return resp.Pack()
	}

	server := &Server{
		WhoisCache:  cache.NewWhoisCache(5 * time.Minute),
		GrantCache:  cache.NewGrantCache(5 * time.Minute),
		GrantParser: grants.NewParser(),
		Logf: func(format string, args ...any) {
			t.Logf(format, args...)
		},
	}
	defer server.WhoisCache.Close()
	defer server.GrantCache.Close()

	tests := []struct {
		name     string
		query    *dnsmessage.Message
		grants   []grants.GrantConfig
		backend  backend.Backend
		validate func(t *testing.T, response []byte, err error)
	}{
		{
			name: "A_query_to_4via6_domain_returns_NODATA",
			query: &dnsmessage.Message{
				Header: dnsmessage.Header{
					ID: 1234,
				},
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("service.test.local."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
			},
			grants:  mockGrants,
			backend: &mockBackend{queryFunc: mockBackendFunc},
			validate: func(t *testing.T, response []byte, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				var resp dnsmessage.Message
				if err := resp.Unpack(response); err != nil {
					t.Fatalf("failed to unpack response: %v", err)
				}

				// Check question was unrewritten back to original
				if len(resp.Questions) != 1 {
					t.Fatalf("expected 1 question, got %d", len(resp.Questions))
				}
				if resp.Questions[0].Name.String() != "service.test.local." {
					t.Errorf("question name = %s, want service.test.local.", resp.Questions[0].Name)
				}

				// Check A query to 4via6 domain returns NODATA (authoritative behavior)
				if len(resp.Answers) != 0 {
					t.Fatalf("expected 0 answers (NODATA), got %d", len(resp.Answers))
				}
				// Should still be a successful response (not NXDOMAIN)
				if resp.RCode != dnsmessage.RCodeSuccess {
					t.Errorf("RCode = %v, want RCodeSuccess", resp.RCode)
				}
			},
		},
		{
			name: "AAAA_query_with_rewriting_and_4via6",
			query: &dnsmessage.Message{
				Header: dnsmessage.Header{
					ID: 1235,
				},
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("service.test.local."),
						Type:  dnsmessage.TypeAAAA,
						Class: dnsmessage.ClassINET,
					},
				},
			},
			grants:  mockGrants,
			backend: &mockBackend{queryFunc: mockBackendFunc},
			validate: func(t *testing.T, response []byte, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				var resp dnsmessage.Message
				if err := resp.Unpack(response); err != nil {
					t.Fatalf("failed to unpack response: %v", err)
				}

				// Check question was unrewritten back to original
				if len(resp.Questions) != 1 {
					t.Fatalf("expected 1 question, got %d", len(resp.Questions))
				}
				if resp.Questions[0].Name.String() != "service.test.local." {
					t.Errorf("question name = %s, want service.test.local.", resp.Questions[0].Name)
				}

				// Check answer was translated to AAAA
				if len(resp.Answers) != 1 {
					t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
				}
				if resp.Answers[0].Header.Type != dnsmessage.TypeAAAA {
					t.Errorf("answer type = %v, want TypeAAAA", resp.Answers[0].Header.Type)
				}
			},
		},
		{
			name: "query_no_grant_match",
			query: &dnsmessage.Message{
				Header: dnsmessage.Header{
					ID: 5678,
				},
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("nomatch.example.com."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
			},
			grants:  mockGrants,
			backend: &mockBackend{queryFunc: mockBackendFunc},
			validate: func(t *testing.T, response []byte, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				var resp dnsmessage.Message
				if err := resp.Unpack(response); err != nil {
					t.Fatalf("failed to unpack response: %v", err)
				}

				// Should use default backend (no rewriting or translation)
				if len(resp.Answers) != 1 {
					t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
				}
				if resp.Answers[0].Header.Type != dnsmessage.TypeA {
					t.Errorf("answer type = %v, want TypeA", resp.Answers[0].Header.Type)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up backend manager
			server.BackendMgr = &mockBackendManager{
				backend: tt.backend,
			}

			response, err := server.processQuery(ctx, tt.query, tt.grants)
			tt.validate(t, response, err)
		})
	}
}

func TestServer_getGrantsForSource(t *testing.T) {
	ctx := context.Background()

	server := &Server{
		LocalClient: &mockLocalClient{
			whoisFunc: func(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{
					Node: &tailcfg.Node{
						Name: "test-node.example.com",
					},
					CapMap: tailcfg.PeerCapMap{
						"rajsingh.info/cap/tsdnsproxy": {
							`{"test.local": {"dns": ["10.0.0.10:53"]}}`,
						},
					},
				}, nil
			},
		},
		WhoisCache:  cache.NewWhoisCache(5 * time.Minute),
		GrantCache:  cache.NewGrantCache(5 * time.Minute),
		GrantParser: grants.NewParser(),
		Logf: func(format string, args ...any) {
			t.Logf(format, args...)
		},
	}
	defer server.WhoisCache.Close()
	defer server.GrantCache.Close()

	// First call should perform whois lookup
	grants1, err := server.getGrantsForSource(ctx, "10.0.0.1:12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(grants1) != 1 {
		t.Errorf("expected 1 grant, got %d", len(grants1))
	}

	// Second call should use cache
	grants2, err := server.getGrantsForSource(ctx, "10.0.0.1:12345")
	if err != nil {
		t.Fatalf("unexpected error on cached call: %v", err)
	}
	if len(grants2) != 1 {
		t.Errorf("expected 1 grant from cache, got %d", len(grants2))
	}
}

func TestServer_sendError(t *testing.T) {
	// Create a mock PacketConn to capture the response
	type capturedWrite struct {
		data []byte
		addr net.Addr
	}

	var captured capturedWrite
	mockConn := &mockPacketConn{
		writeToFunc: func(b []byte, addr net.Addr) (int, error) {
			captured.data = make([]byte, len(b))
			copy(captured.data, b)
			captured.addr = addr
			return len(b), nil
		},
	}

	server := &Server{
		Logf: func(format string, args ...any) {
			t.Logf(format, args...)
		},
	}

	query := &dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: 9999,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("error.test.com."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	testAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 53}
	server.sendError(mockConn, testAddr, query, dnsmessage.RCodeServerFailure)

	// Verify response
	var resp dnsmessage.Message
	if err := resp.Unpack(captured.data); err != nil {
		t.Fatalf("failed to unpack error response: %v", err)
	}

	if resp.ID != query.ID {
		t.Errorf("response ID = %d, want %d", resp.ID, query.ID)
	}
	if !resp.Response {
		t.Error("response flag not set")
	}
	if resp.RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("response RCode = %v, want RCodeServerFailure", resp.RCode)
	}
	if len(resp.Questions) != 1 {
		t.Errorf("response questions = %d, want 1", len(resp.Questions))
	}
}

// mockPacketConn implements net.PacketConn for testing
type mockPacketConn struct {
	writeToFunc func(b []byte, addr net.Addr) (int, error)
}

func (m *mockPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	return 0, nil, net.ErrClosed
}

func (m *mockPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if m.writeToFunc != nil {
		return m.writeToFunc(b, addr)
	}
	return len(b), nil
}

func (m *mockPacketConn) Close() error {
	return nil
}

func (m *mockPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 53}
}

func (m *mockPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestServer_handleAuthoritative4via6(t *testing.T) {
	tests := []struct {
		name     string
		query    *dnsmessage.Message
		grant    *grants.DNSGrant
		domain   string
		backend  backend.Backend
		validate func(t *testing.T, response []byte, err error)
	}{
		{
			name: "translateID_0_A_query_returns_IPv4",
			query: &dnsmessage.Message{
				Header: dnsmessage.Header{
					ID: 1,
				},
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("service.test.local."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
			},
			grant: &grants.DNSGrant{
				DNS:         []string{"10.0.0.10:53"},
				Rewrite:     "svc.cluster.local",
				TranslateID: 0,
			},
			domain: "test.local",
			backend: &mockBackend{
				queryFunc: func(ctx context.Context, query []byte) ([]byte, error) {
					var q dnsmessage.Message
					if err := q.Unpack(query); err != nil {
						return nil, err
					}
					resp := dnsmessage.Message{
						Header: dnsmessage.Header{
							ID:       q.ID,
							Response: true,
							RCode:    dnsmessage.RCodeSuccess,
						},
						Questions: q.Questions,
						Answers: []dnsmessage.Resource{
							{
								Header: dnsmessage.ResourceHeader{
									Name:  q.Questions[0].Name,
									Type:  dnsmessage.TypeA,
									Class: dnsmessage.ClassINET,
									TTL:   300,
								},
								Body: &dnsmessage.AResource{
									A: [4]byte{10, 2, 26, 202},
								},
							},
						},
					}
					return resp.Pack()
				},
			},
			validate: func(t *testing.T, response []byte, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				var resp dnsmessage.Message
				if err := resp.Unpack(response); err != nil {
					t.Fatalf("failed to unpack response: %v", err)
				}
				if !resp.Authoritative {
					t.Error("response should be authoritative")
				}
				if len(resp.Answers) != 1 {
					t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
				}
				if resp.Answers[0].Header.Type != dnsmessage.TypeA {
					t.Errorf("answer type = %v, want TypeA", resp.Answers[0].Header.Type)
				}
				a, ok := resp.Answers[0].Body.(*dnsmessage.AResource)
				if !ok {
					t.Fatal("answer body is not AResource")
				}
				expected := [4]byte{10, 2, 26, 202}
				if a.A != expected {
					t.Errorf("A record = %v, want %v", a.A, expected)
				}
			},
		},
		{
			name: "translateID_0_AAAA_query_returns_IPv6",
			query: &dnsmessage.Message{
				Header: dnsmessage.Header{
					ID: 2,
				},
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("service.test.local."),
						Type:  dnsmessage.TypeAAAA,
						Class: dnsmessage.ClassINET,
					},
				},
			},
			grant: &grants.DNSGrant{
				DNS:         []string{"10.0.0.10:53"},
				Rewrite:     "svc.cluster.local",
				TranslateID: 0,
			},
			domain: "test.local",
			backend: &mockBackend{
				queryFunc: func(ctx context.Context, query []byte) ([]byte, error) {
					var q dnsmessage.Message
					if err := q.Unpack(query); err != nil {
						return nil, err
					}
					resp := dnsmessage.Message{
						Header: dnsmessage.Header{
							ID:       q.ID,
							Response: true,
							RCode:    dnsmessage.RCodeSuccess,
						},
						Questions: q.Questions,
						Answers: []dnsmessage.Resource{
							{
								Header: dnsmessage.ResourceHeader{
									Name:  q.Questions[0].Name,
									Type:  dnsmessage.TypeAAAA,
									Class: dnsmessage.ClassINET,
									TTL:   300,
								},
								Body: &dnsmessage.AAAAResource{
									AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
								},
							},
						},
					}
					return resp.Pack()
				},
			},
			validate: func(t *testing.T, response []byte, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				var resp dnsmessage.Message
				if err := resp.Unpack(response); err != nil {
					t.Fatalf("failed to unpack response: %v", err)
				}
				if !resp.Authoritative {
					t.Error("response should be authoritative")
				}
				if len(resp.Answers) != 1 {
					t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
				}
				if resp.Answers[0].Header.Type != dnsmessage.TypeAAAA {
					t.Errorf("answer type = %v, want TypeAAAA", resp.Answers[0].Header.Type)
				}
				aaaa, ok := resp.Answers[0].Body.(*dnsmessage.AAAAResource)
				if !ok {
					t.Fatal("answer body is not AAAAResource")
				}
				addr := netip.AddrFrom16(aaaa.AAAA)
				if addr.String() != "2001:db8::1" {
					t.Errorf("AAAA record = %v, want 2001:db8::1", addr)
				}
			},
		},
		{
			name: "translateID_1_A_query_returns_NODATA",
			query: &dnsmessage.Message{
				Header: dnsmessage.Header{
					ID: 3,
				},
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("service.test.local."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
			},
			grant: &grants.DNSGrant{
				DNS:         []string{"10.0.0.10:53"},
				Rewrite:     "svc.cluster.local",
				TranslateID: 1,
			},
			domain: "test.local",
			backend: &mockBackend{
				queryFunc: func(ctx context.Context, query []byte) ([]byte, error) {
					var q dnsmessage.Message
					if err := q.Unpack(query); err != nil {
						return nil, err
					}
					resp := dnsmessage.Message{
						Header: dnsmessage.Header{
							ID:       q.ID,
							Response: true,
							RCode:    dnsmessage.RCodeSuccess,
						},
						Questions: q.Questions,
						Answers: []dnsmessage.Resource{
							{
								Header: dnsmessage.ResourceHeader{
									Name:  q.Questions[0].Name,
									Type:  dnsmessage.TypeA,
									Class: dnsmessage.ClassINET,
									TTL:   300,
								},
								Body: &dnsmessage.AResource{
									A: [4]byte{10, 2, 26, 202},
								},
							},
						},
					}
					return resp.Pack()
				},
			},
			validate: func(t *testing.T, response []byte, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				var resp dnsmessage.Message
				if err := resp.Unpack(response); err != nil {
					t.Fatalf("failed to unpack response: %v", err)
				}
				if !resp.Authoritative {
					t.Error("response should be authoritative")
				}
				// Should return NODATA (empty answers)
				if len(resp.Answers) != 0 {
					t.Fatalf("expected 0 answers (NODATA), got %d", len(resp.Answers))
				}
				if resp.RCode != dnsmessage.RCodeSuccess {
					t.Errorf("RCode = %v, want RCodeSuccess", resp.RCode)
				}
			},
		},
		{
			name: "translateID_1_AAAA_query_returns_4via6",
			query: &dnsmessage.Message{
				Header: dnsmessage.Header{
					ID: 4,
				},
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("service.test.local."),
						Type:  dnsmessage.TypeAAAA,
						Class: dnsmessage.ClassINET,
					},
				},
			},
			grant: &grants.DNSGrant{
				DNS:         []string{"10.0.0.10:53"},
				Rewrite:     "svc.cluster.local",
				TranslateID: 1,
			},
			domain: "test.local",
			backend: &mockBackend{
				queryFunc: func(ctx context.Context, query []byte) ([]byte, error) {
					var q dnsmessage.Message
					if err := q.Unpack(query); err != nil {
						return nil, err
					}
					// Backend returns A record
					resp := dnsmessage.Message{
						Header: dnsmessage.Header{
							ID:       q.ID,
							Response: true,
							RCode:    dnsmessage.RCodeSuccess,
						},
						Questions: q.Questions,
						Answers: []dnsmessage.Resource{
							{
								Header: dnsmessage.ResourceHeader{
									Name:  q.Questions[0].Name,
									Type:  dnsmessage.TypeA,
									Class: dnsmessage.ClassINET,
									TTL:   300,
								},
								Body: &dnsmessage.AResource{
									A: [4]byte{10, 2, 26, 202},
								},
							},
						},
					}
					return resp.Pack()
				},
			},
			validate: func(t *testing.T, response []byte, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				var resp dnsmessage.Message
				if err := resp.Unpack(response); err != nil {
					t.Fatalf("failed to unpack response: %v", err)
				}
				if !resp.Authoritative {
					t.Error("response should be authoritative")
				}
				if len(resp.Answers) != 1 {
					t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
				}
				if resp.Answers[0].Header.Type != dnsmessage.TypeAAAA {
					t.Errorf("answer type = %v, want TypeAAAA", resp.Answers[0].Header.Type)
				}
				aaaa, ok := resp.Answers[0].Body.(*dnsmessage.AAAAResource)
				if !ok {
					t.Fatal("answer body is not AAAAResource")
				}
				addr := netip.AddrFrom16(aaaa.AAAA)
				// Should have 4via6 prefix for site 1
				if !strings.HasPrefix(addr.String(), "fd7a:115c:a1e0:b1a:0:1:") {
					t.Errorf("4via6 address = %v, want prefix fd7a:115c:a1e0:b1a:0:1:", addr)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{
				BackendMgr: &mockBackendManager{
					backend: tt.backend,
				},
				GrantParser: grants.NewParser(),
				Logf: func(format string, args ...any) {
					t.Logf(format, args...)
				},
			}

			response, err := server.handleAuthoritative4via6(tt.query, tt.grant, tt.domain)
			tt.validate(t, response, err)
		})
	}
}
