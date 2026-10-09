// Package cidr parses and matches IP prefixes shared by translation filters
// and encoded-name grants.
package cidr

import (
	"fmt"
	"net/netip"
)

// DefaultBlocked lists IPv4 ranges that are not translated or encoded unless
// an allow list entry covers the address. The shared 100.64.0.0/10 range is
// included so those answers are left unchanged.
func DefaultBlocked() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("100.64.0.0/10"),
	}
}

// Policy decides whether an address is eligible.
// Deny always rejects. When ApplyDefaults is set, DefaultBlocked rejects
// unless Allow also covers the address. A non-empty Allow list requires a match.
type Policy struct {
	Allow         []netip.Prefix
	Deny          []netip.Prefix
	ApplyDefaults bool
}

// ParseList parses CIDR strings. An empty input is valid and returns nil.
func ParseList(cidrs []string) ([]netip.Prefix, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, raw := range cidrs {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// Contains reports whether any prefix covers ip.
func Contains(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// MostSpecific returns the longest prefix that covers ip.
func MostSpecific(prefixes []netip.Prefix, ip netip.Addr) (netip.Prefix, bool) {
	var best netip.Prefix
	found := false
	for _, p := range prefixes {
		if !p.Contains(ip) {
			continue
		}
		if !found || p.Bits() > best.Bits() {
			best = p
			found = true
		}
	}
	return best, found
}

// Permits reports whether ip is eligible under the policy.
func (p Policy) Permits(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if Contains(p.Deny, ip) {
		return false
	}
	if p.ApplyDefaults && ip.Is4() && Contains(DefaultBlocked(), ip) && !Contains(p.Allow, ip) {
		return false
	}
	if len(p.Allow) > 0 && !Contains(p.Allow, ip) {
		return false
	}
	return true
}
