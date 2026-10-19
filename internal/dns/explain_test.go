package dns

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/cache"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"github.com/rajsinghtech/tsdnsproxy/internal/ui"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

func TestExplainSkipsUpstreamUntilAsked(t *testing.T) {
	var calls atomic.Int32
	server := &Server{
		LocalClient: &mockLocalClient{whoisFunc: func(context.Context, string) (*apitype.WhoIsResponse, error) {
			return &apitype.WhoIsResponse{
				Node:        &tailcfg.Node{Name: "a.example.ts.net", Tags: []string{"tag:dns"}},
				UserProfile: &tailcfg.UserProfile{LoginName: "alice@example.com"},
				CapMap: tailcfg.PeerCapMap{
					grants.DefaultCapName: {tailcfg.RawMessage(`{"example.internal":{"dns":["10.0.0.53:53"],"translateid":-1}}`)},
				},
			}, nil
		}},
		WhoisCache:  cache.NewWhoisCache(0),
		GrantCache:  cache.NewGrantCache(0),
		GrantParser: grants.NewParser(),
		BackendMgr: &mockBackendManager{backend: &mockBackend{queryFunc: func(context.Context, []byte) ([]byte, error) {
			calls.Add(1)
			return packedA(1, "app.example.internal.", 30, [4]byte{10, 1, 2, 3}), nil
		}}},
		Logf: t.Logf,
	}
	t.Cleanup(func() {
		server.WhoisCache.Close()
		server.GrantCache.Close()
	})
	got, err := server.Explain(context.Background(), ui.LookupRequest{
		Name: "app.example.internal", Type: "A", Peer: "100.64.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Matched || got.Forwarded || got.Rule == nil || got.Rule.Domain != "example.internal" {
		t.Fatalf("%+v", got)
	}
	if calls.Load() != 0 {
		t.Fatalf("dry run contacted upstream %d times", calls.Load())
	}
	got, err = server.Explain(context.Background(), ui.LookupRequest{
		Name: "app.example.internal", Type: "A", Peer: "100.64.0.2", Forward: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Forwarded || got.RCode != "NOERROR" || len(got.Answers) != 1 {
		t.Fatalf("%+v", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("forward calls %d", calls.Load())
	}
}

func TestLearnedPeerRecordsGrantSource(t *testing.T) {
	server := &Server{
		LocalClient: &mockLocalClient{whoisFunc: func(_ context.Context, addr string) (*apitype.WhoIsResponse, error) {
			return &apitype.WhoIsResponse{
				Node:        &tailcfg.Node{Name: "a.example.ts.net"},
				UserProfile: &tailcfg.UserProfile{LoginName: "alice@example.com"},
				CapMap: tailcfg.PeerCapMap{
					grants.DefaultCapName: {tailcfg.RawMessage(`{"example.internal":{"dns":["10.0.0.53:53"],"rewrite":"svc.example"}}`)},
				},
			}, nil
		}},
		WhoisCache:  cache.NewWhoisCache(time.Minute),
		GrantCache:  cache.NewGrantCache(time.Minute),
		GrantParser: grants.NewParser(),
		Logf:        t.Logf,
	}
	t.Cleanup(func() {
		server.WhoisCache.Close()
		server.GrantCache.Close()
	})
	if _, err := server.getGrantsForSource(context.Background(), "100.64.0.2:5353"); err != nil {
		t.Fatal(err)
	}
	peers := server.UIPeers()
	if len(peers) != 1 || peers[0].Node != "a.example.ts.net" || peers[0].User != "alice@example.com" {
		t.Fatalf("%+v", peers)
	}
	if len(peers[0].Rules) != 1 || peers[0].Rules[0].Source != "grant" || peers[0].Rules[0].Rewrite != "svc.example" {
		t.Fatalf("rules %+v", peers[0].Rules)
	}
	if peers[0].CacheExpire.IsZero() {
		t.Fatal("missing cache expiry")
	}
}
