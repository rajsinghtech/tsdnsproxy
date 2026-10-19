package ui

import (
	"sync"
	"testing"
	"time"
)

func TestRingKeepsNewest(t *testing.T) {
	r := NewRing(2)
	r.Add(Query{Name: "one.example.internal", RCode: "NOERROR"})
	r.Add(Query{Name: "two.example.internal", RCode: "NOERROR"})
	r.Add(Query{Name: "three.example.internal", RCode: "REFUSED"})
	got := r.List("", "", "", "")
	if len(got) != 2 || got[0].Name != "three.example.internal" || got[1].Name != "two.example.internal" {
		t.Fatalf("%+v", got)
	}
	off := NewRing(0)
	off.Add(Query{Name: "x.example.internal"})
	if got := off.List("", "", "", ""); len(got) != 0 {
		t.Fatalf("disabled ring stored %+v", got)
	}
}

func TestRingFiltersAndRedacts(t *testing.T) {
	r := NewRing(8)
	r.Add(Query{
		Time:   time.Unix(10, 0).UTC(),
		PeerIP: "100.64.0.2",
		Node:   "a.example.ts.net",
		User:   "alice@example.com",
		Name:   "app.example.internal",
		RCode:  "NOERROR",
	})
	r.Add(Query{
		PeerIP: "100.64.0.3",
		Node:   "b.example.ts.net",
		User:   "bob@example.com",
		Name:   "tskey-auth-secret.example.internal",
		RCode:  "REFUSED",
	})
	byPeer := r.List("a.example.ts.net", "", "", "")
	if len(byPeer) != 1 || byPeer[0].User != "alice@example.com" {
		t.Fatalf("%+v", byPeer)
	}
	byDomain := r.List("", "", "example.internal", "REFUSED")
	if len(byDomain) != 1 || byDomain[0].RCode != "REFUSED" {
		t.Fatalf("%+v", byDomain)
	}
	if byDomain[0].Name != "tskey-redacted.example.internal" {
		t.Fatalf("name %q", byDomain[0].Name)
	}
}

func TestAccessAggregation(t *testing.T) {
	r := NewRing(10)
	r.Add(Query{Node: "a.example.ts.net", Name: "app.example.internal", RCode: "NOERROR"})
	r.Add(Query{Node: "a.example.ts.net", Name: "app.example.internal", RCode: "REFUSED"})
	r.Add(Query{Node: "b.example.ts.net", Name: "other.example", RCode: "NXDOMAIN"})
	got := r.Access()
	if got.Total != 3 || got.Refused != 1 || !got.History {
		t.Fatalf("%+v", got)
	}
	if len(got.Peers) == 0 || got.Peers[0].Name != "a.example.ts.net" || got.Peers[0].Queries != 2 || got.Peers[0].Refused != 1 {
		t.Fatalf("peers %+v", got.Peers)
	}
	if got.Domains[0].Name != "app.example.internal" {
		t.Fatalf("domains %+v", got.Domains)
	}
}

func TestRingConcurrentAdd(t *testing.T) {
	r := NewRing(64)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Add(Query{Name: "app.example.internal", RCode: "NOERROR", PeerIP: "100.64.0.2"})
		}()
	}
	wg.Wait()
	if len(r.List("", "", "", "")) != 32 {
		t.Fatalf("len %d", len(r.List("", "", "", "")))
	}
}
