package grants

import (
	"fmt"
	"net/netip"

	"tailscale.com/tailcfg"
)

// DefaultServiceTTL is the answer TTL, in seconds, for a service rule without ttl.
const DefaultServiceTTL = 30

// ServiceTTL returns the answer TTL for a service rule.
func (g DNSGrant) ServiceTTL() uint32 {
	if g.TTL == nil || *g.TTL < minStaticTTL || *g.TTL > maxStaticTTL {
		return DefaultServiceTTL
	}
	return uint32(*g.TTL) //nolint:gosec // bounded by maxStaticTTL
}

// ServiceAddrs returns the parsed addrs fallback. Invalid entries are skipped.
func (g DNSGrant) ServiceAddrs() []netip.Addr {
	out := make([]netip.Addr, 0, len(g.Addrs))
	for _, raw := range g.Addrs {
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		out = append(out, ip.Unmap())
	}
	return out
}

func validateService(domain string, g DNSGrant, isPrefix, wildcard bool) error {
	if g.Service == "" {
		if len(g.Addrs) > 0 {
			return fmt.Errorf("addrs requires service for %s", domain)
		}
		if g.TTL != nil {
			return fmt.Errorf("ttl requires service for %s", domain)
		}
		return nil
	}
	if isPrefix {
		return fmt.Errorf("service cannot use CIDR key %s", domain)
	}
	if wildcard {
		return fmt.Errorf("service cannot use wildcard key %s", domain)
	}
	if err := tailcfg.ServiceName(g.Service).Validate(); err != nil {
		return fmt.Errorf("service %q for %s must look like svc:<name>", g.Service, domain)
	}
	conflicts := []struct {
		set  bool
		name string
	}{
		{g.Rewrite != "", "rewrite"},
		{g.Static != nil, "static"},
		{g.IPNames != nil, "ipnames"},
		{g.Zone != nil, "zone"},
		{len(g.DNS) > 0, "dns"},
		{g.TranslateID != nil, "translateid"},
		{len(g.AllowIPs) > 0 || len(g.DenyIPs) > 0, "allowips or denyips"},
	}
	for _, c := range conflicts {
		if c.set {
			return fmt.Errorf("service cannot be combined with %s for %s", c.name, domain)
		}
	}
	if g.TTL != nil && (*g.TTL < minStaticTTL || *g.TTL > maxStaticTTL) {
		return fmt.Errorf("service %s: ttl %d is outside %d-%d", domain, *g.TTL, minStaticTTL, maxStaticTTL)
	}
	seen := make(map[netip.Addr]struct{}, len(g.Addrs))
	for _, raw := range g.Addrs {
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			return fmt.Errorf("service %s: address %q is not an IP", domain, raw)
		}
		ip = ip.Unmap()
		if ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return fmt.Errorf("service %s: address %s is not usable", domain, ip)
		}
		if _, dup := seen[ip]; dup {
			return fmt.Errorf("service %s: duplicate address %s", domain, ip)
		}
		seen[ip] = struct{}{}
	}
	return nil
}
