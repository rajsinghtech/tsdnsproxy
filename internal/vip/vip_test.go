package vip

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
)

func servicesCap(t *testing.T, svcs map[string][]string, hosted map[string][]string) tailcfg.NodeCapMap {
	t.Helper()
	cm := tailcfg.NodeCapMap{}
	for name, addrs := range svcs {
		d := tailcfg.ServiceDetails{Name: tailcfg.ServiceName(name)}
		for _, a := range addrs {
			d.Addrs = append(d.Addrs, netip.MustParseAddr(a))
		}
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		cm[nodecap.Cap(string(nodecap.ServicesPrefix)+name)] = []tailcfg.RawMessage{tailcfg.RawMessage(raw)}
	}
	if hosted != nil {
		raw, err := json.Marshal(hosted)
		if err != nil {
			t.Fatal(err)
		}
		cm[nodecap.ServiceHost] = []tailcfg.RawMessage{tailcfg.RawMessage(raw)}
	}
	return cm
}

func TestFromSelfNode(t *testing.T) {
	cm := servicesCap(t,
		map[string][]string{"svc:app": {"100.64.0.10", "2001:db8::a"}, "svc:empty": nil},
		map[string][]string{"svc:app": {"100.64.0.99"}, "svc:dns": {"100.64.0.53"}},
	)
	got := FromSelfNode((&tailcfg.Node{CapMap: cm}).View())
	if len(got) != 2 {
		t.Fatalf("services %v", got)
	}
	if a := got["svc:app"]; len(a) != 2 || a[0].String() != "100.64.0.10" || a[1].String() != "2001:db8::a" {
		t.Fatalf("svc:app %v", a)
	}
	if a := got["svc:dns"]; len(a) != 1 || a[0].String() != "100.64.0.53" {
		t.Fatalf("hosted svc:dns %v", a)
	}
}

func TestTableGeneration(t *testing.T) {
	var tb Table
	if _, ok := tb.Lookup("svc:app"); ok || tb.Generation() != 0 {
		t.Fatal("zero table is not empty")
	}
	m := map[tailcfg.ServiceName][]netip.Addr{"svc:app": {netip.MustParseAddr("100.64.0.10")}}
	if !tb.Set(m) || tb.Generation() != 1 {
		t.Fatal("first set did not change the table")
	}
	if tb.Set(map[tailcfg.ServiceName][]netip.Addr{"svc:app": {netip.MustParseAddr("100.64.0.10")}}) || tb.Generation() != 1 {
		t.Fatal("same map bumped the generation")
	}
	m["svc:app"][0] = netip.MustParseAddr("100.64.0.11")
	if got, _ := tb.Lookup("svc:app"); got[0].String() != "100.64.0.10" {
		t.Fatal("table shares the caller's slice")
	}
	got, _ := tb.Lookup("svc:app")
	got[0] = netip.MustParseAddr("100.64.0.12")
	if again, _ := tb.Lookup("svc:app"); again[0].String() != "100.64.0.10" {
		t.Fatal("lookup returned the table's slice")
	}
	if !tb.Set(nil) || tb.Generation() != 2 {
		t.Fatal("clearing did not change the table")
	}
}

type fakeBus struct {
	mu       sync.Mutex
	sessions []chan ipn.Notify
	opened   chan struct{}
}

func newFakeBus() *fakeBus { return &fakeBus{opened: make(chan struct{}, 8)} }

func (b *fakeBus) WatchIPNBus(ctx context.Context, mask ipn.NotifyWatchOpt) (Watcher, error) {
	if mask&ipn.NotifyInitialStatus == 0 {
		return nil, errors.New("initial status not requested")
	}
	ch := make(chan ipn.Notify, 8)
	b.mu.Lock()
	b.sessions = append(b.sessions, ch)
	b.mu.Unlock()
	b.opened <- struct{}{}
	return &fakeWatcher{ctx: ctx, ch: ch}, nil
}

func (b *fakeBus) send(n ipn.Notify) {
	b.mu.Lock()
	ch := b.sessions[len(b.sessions)-1]
	b.mu.Unlock()
	ch <- n
}

func (b *fakeBus) drop() {
	b.mu.Lock()
	close(b.sessions[len(b.sessions)-1])
	b.mu.Unlock()
}

type fakeWatcher struct {
	ctx context.Context
	ch  chan ipn.Notify
}

func (w *fakeWatcher) Next() (ipn.Notify, error) {
	select {
	case n, ok := <-w.ch:
		if !ok {
			return ipn.Notify{}, errors.New("session closed")
		}
		return n, nil
	case <-w.ctx.Done():
		return ipn.Notify{}, w.ctx.Err()
	}
}

func (w *fakeWatcher) Close() error { return nil }

func waitFor(t *testing.T, tb *Table, name, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, ok := tb.Lookup(name)
		if (want == "" && !ok) || (ok && got[0].String() == want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	got, _ := tb.Lookup(name)
	t.Fatalf("%s = %v, want %q", name, got, want)
}

func TestWatchFollowsSelfNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus := newFakeBus()
	var tb Table
	done := make(chan struct{})
	go func() {
		Watch(ctx, bus, &tb, t.Logf)
		close(done)
	}()

	<-bus.opened
	bus.send(ipn.Notify{InitialStatus: &ipnstate.Status{Self: &ipnstate.PeerStatus{
		CapMap: servicesCap(t, map[string][]string{"svc:app": {"100.64.0.10"}}, nil),
	}}})
	waitFor(t, &tb, "svc:app", "100.64.0.10")

	bus.send(ipn.Notify{SelfChange: &tailcfg.Node{
		CapMap: servicesCap(t, map[string][]string{"svc:app": {"100.64.0.11"}}, nil),
	}})
	waitFor(t, &tb, "svc:app", "100.64.0.11")

	bus.send(ipn.Notify{SelfChange: &tailcfg.Node{}})
	waitFor(t, &tb, "svc:app", "")

	bus.drop()
	<-bus.opened
	bus.send(ipn.Notify{InitialStatus: &ipnstate.Status{Self: &ipnstate.PeerStatus{
		CapMap: servicesCap(t, map[string][]string{"svc:app": {"100.64.0.12"}}, nil),
	}}})
	waitFor(t, &tb, "svc:app", "100.64.0.12")

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not stop")
	}
}
