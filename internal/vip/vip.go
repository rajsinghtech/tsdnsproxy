// Package vip tracks the VIP addresses of Tailscale Services from the node's netmap.
package vip

import (
	"context"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// Source reports the VIP addresses of Tailscale Services.
// Generation changes whenever any service's addresses change.
type Source interface {
	Lookup(name string) ([]netip.Addr, bool)
	Generation() uint64
}

// Table is a Source holding the latest service map. The zero value is empty.
type Table struct {
	mu  sync.RWMutex
	m   map[tailcfg.ServiceName][]netip.Addr
	gen uint64
}

// Lookup returns a copy of the addresses for name.
// It returns false when the service is absent or has no addresses.
func (t *Table) Lookup(name string) ([]netip.Addr, bool) {
	if t == nil {
		return nil, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	addrs := t.m[tailcfg.ServiceName(name)]
	if len(addrs) == 0 {
		return nil, false
	}
	return slices.Clone(addrs), true
}

// Generation is bumped by Set when the map changes.
func (t *Table) Generation() uint64 {
	if t == nil {
		return 0
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.gen
}

// Set replaces the map. It reports whether anything changed.
func (t *Table) Set(m map[tailcfg.ServiceName][]netip.Addr) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if maps.EqualFunc(t.m, m, slices.Equal[[]netip.Addr]) {
		return false
	}
	t.m = make(map[tailcfg.ServiceName][]netip.Addr, len(m))
	for name, addrs := range m {
		t.m[name] = slices.Clone(addrs)
	}
	t.gen++
	return true
}

// FromSelfNode decodes service VIPs from the self node's capabilities.
// Services visible to the node come from [netmap.NetworkMap.Services].
// Services the node hosts, from [netmap.NetworkMap.GetVIPServiceIPMap],
// fill in names the first list lacks.
func FromSelfNode(self tailcfg.NodeView) map[tailcfg.ServiceName][]netip.Addr {
	nm := &netmap.NetworkMap{SelfNode: self}
	out := make(map[tailcfg.ServiceName][]netip.Addr)
	for name, svc := range nm.Services() {
		if len(svc.Addrs) > 0 {
			out[name] = slices.Clone(svc.Addrs)
		}
	}
	for name, addrs := range nm.GetVIPServiceIPMap() {
		if _, ok := out[name]; !ok && len(addrs) > 0 {
			out[name] = slices.Clone(addrs)
		}
	}
	return out
}

// Watcher yields IPN bus notifications.
type Watcher interface {
	Next() (ipn.Notify, error)
	Close() error
}

// Bus opens an IPN bus watch.
type Bus interface {
	WatchIPNBus(ctx context.Context, mask ipn.NotifyWatchOpt) (Watcher, error)
}

type localBus struct{ lc *local.Client }

func (b localBus) WatchIPNBus(ctx context.Context, mask ipn.NotifyWatchOpt) (Watcher, error) {
	return b.lc.WatchIPNBus(ctx, mask)
}

// LocalBus adapts a tsnet local client.
func LocalBus(lc *local.Client) Bus {
	return localBus{lc: lc}
}

const (
	minRetry = time.Second
	maxRetry = 30 * time.Second
)

// Watch keeps t in step with the self node until ctx is done.
// Each session is seeded from the initial status and updated on every
// self node change. A dropped session is reopened with backoff.
func Watch(ctx context.Context, bus Bus, t *Table, logf func(string, ...any)) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	wait := minRetry
	for ctx.Err() == nil {
		healthy := watchOnce(ctx, bus, t, logf)
		if ctx.Err() != nil {
			return
		}
		if healthy {
			wait = minRetry
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, maxRetry)
	}
}

// watchOnce runs one bus session. It reports whether any notification arrived.
func watchOnce(ctx context.Context, bus Bus, t *Table, logf func(string, ...any)) bool {
	w, err := bus.WatchIPNBus(ctx, ipn.NotifyInitialStatus)
	if err != nil {
		logf("service vips: watch: %v", err)
		return false
	}
	defer w.Close()
	got := false
	for {
		n, err := w.Next()
		if err != nil {
			if ctx.Err() == nil {
				logf("service vips: watch: %v", err)
			}
			return got
		}
		got = true
		var self tailcfg.NodeView
		switch {
		case n.SelfChange != nil:
			self = n.SelfChange.View()
		case n.InitialStatus != nil && n.InitialStatus.Self != nil:
			self = (&tailcfg.Node{CapMap: n.InitialStatus.Self.CapMap}).View()
		default:
			continue
		}
		m := FromSelfNode(self)
		if t.Set(m) {
			logf("service vips: %d services", len(m))
		}
	}
}
