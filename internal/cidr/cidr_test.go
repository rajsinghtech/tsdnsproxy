package cidr

import (
	"net/netip"
	"testing"
)

func TestParseList(t *testing.T) {
	got, err := ParseList(nil)
	if err != nil || got != nil {
		t.Fatalf("empty list = %v, %v", got, err)
	}
	got, err = ParseList([]string{"10.0.0.0/8", "192.168.1.10/32"})
	if err != nil || len(got) != 2 {
		t.Fatalf("parse = %v, %v", got, err)
	}
	if _, err := ParseList([]string{"not-a-cidr"}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := ParseList([]string{""}); err == nil {
		t.Fatal("expected error for empty string")
	}
}

func TestContainsAndMostSpecific(t *testing.T) {
	prefixes, err := ParseList([]string{"10.0.0.0/8", "10.1.0.0/16", "192.168.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("10.1.2.3")
	if !Contains(prefixes, ip) {
		t.Fatal("expected contain")
	}
	best, ok := MostSpecific(prefixes, ip)
	if !ok || best.String() != "10.1.0.0/16" {
		t.Fatalf("most specific = %v, %v", best, ok)
	}
	if _, ok := MostSpecific(prefixes, netip.MustParseAddr("172.16.0.1")); ok {
		t.Fatal("unexpected match")
	}
}

func TestPolicy(t *testing.T) {
	allow, err := ParseList([]string{"10.0.0.0/8", "100.64.0.0/10"})
	if err != nil {
		t.Fatal(err)
	}
	deny, err := ParseList([]string{"10.1.50.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{Allow: allow, Deny: deny, ApplyDefaults: true}

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"10.1.50.9", false},
		{"11.0.0.1", false},
		{"100.64.1.1", true},
		{"100.128.1.1", false},
		{"127.0.0.1", false},
		{"0.1.2.3", false},
		{"169.254.1.1", false},
		{"224.0.0.1", false},
		{"255.255.255.255", false},
	}
	for _, tc := range cases {
		ip := netip.MustParseAddr(tc.ip)
		if got := p.Permits(ip); got != tc.want {
			t.Errorf("Permits(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}

	defaultsOnly := Policy{ApplyDefaults: true}
	if defaultsOnly.Permits(netip.MustParseAddr("8.8.8.8")) != true {
		t.Fatal("public address should be permitted when no allow list is set")
	}
	if defaultsOnly.Permits(netip.MustParseAddr("100.64.0.1")) != false {
		t.Fatal("shared range should be blocked by default")
	}
	if (Policy{}).Permits(netip.MustParseAddr("100.64.0.1")) != true {
		t.Fatal("without defaults, shared range is permitted")
	}
	if (Policy{}).Permits(netip.Addr{}) != false {
		t.Fatal("invalid address should be rejected")
	}
	v6 := Policy{Allow: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}}
	if !v6.Permits(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("ipv6 allow should match")
	}
}
