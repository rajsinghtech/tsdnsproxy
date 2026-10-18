package dns

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/cache"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

func TestServerGrantsRefresh(t *testing.T) {
	var calls atomic.Int32
	server := &Server{
		LocalClient: &mockLocalClient{whoisFunc: func(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
			if addr != "100.64.0.1" {
				return nil, fmt.Errorf("no whois")
			}
			n := calls.Add(1)
			raw := fmt.Sprintf(`{"example.internal":{"dns":["10.0.0.%d:53"],"translateid":-1}}`, n)
			return &apitype.WhoIsResponse{CapMap: tailcfg.PeerCapMap{
				grants.DefaultCapName: {tailcfg.RawMessage(raw)},
			}}, nil
		}},
		WhoisCache:   cache.NewWhoisCache(time.Hour),
		GrantCache:   cache.NewGrantCache(time.Hour),
		GrantParser:  grants.NewParser(),
		Logf:         t.Logf,
		selfIP:       "100.64.0.1",
		grantsLoaded: time.Now().Add(-2 * time.Hour),
		serverGrants: []grants.GrantConfig{{"old.example": {DNS: []string{"10.9.9.9:53"}}}},
	}
	t.Cleanup(func() {
		server.WhoisCache.Close()
		server.GrantCache.Close()
	})

	got, err := server.getGrantsForSource(context.Background(), "192.0.2.10:5353")
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("whois calls = %d", calls.Load())
	}
	grant, ok := got[0]["example.internal"]
	if !ok || len(grant.DNS) != 1 || grant.DNS[0] != "10.0.0.1:53" {
		t.Fatalf("grants = %+v", got)
	}

	if _, err := server.getGrantsForSource(context.Background(), "192.0.2.11:5353"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("refresh ran again inside the ttl: %d", calls.Load())
	}
}
