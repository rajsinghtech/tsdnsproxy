package grants

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/rajsinghtech/tsdnsproxy/internal/cidr"
)

const (
	defaultStaticTTL = 300
	minStaticTTL     = 1
	maxStaticTTL     = 86400

	// Rank classes. A longer name is worth more than the class gap.
	rankSuffix = 0
	rankApex   = 1
	rankWild   = 2
	rankExact  = 3
)

// StaticConfig is a fixed A and AAAA answer for one name or single-label wildcard.
// A nil pointer means the field was omitted.
type StaticConfig struct {
	A        []string `json:"a,omitempty"`
	AAAA     []string `json:"aaaa,omitempty"`
	TTL      *int     `json:"ttl,omitempty"`
	Apex     *bool    `json:"apex,omitempty"`
	AllowSrc []string `json:"allowsrc,omitempty"`

	a        []netip.Addr
	aaaa     []netip.Addr
	ttl      uint32
	allowSrc []netip.Prefix
	ready    bool
}

func (c *StaticConfig) prepare() error {
	if c == nil {
		return fmt.Errorf("missing config")
	}
	if len(c.A) == 0 && len(c.AAAA) == 0 {
		return fmt.Errorf("needs an a or aaaa address")
	}
	ttl := defaultStaticTTL
	if c.TTL != nil {
		if *c.TTL < minStaticTTL || *c.TTL > maxStaticTTL {
			return fmt.Errorf("ttl %d is outside %d-%d", *c.TTL, minStaticTTL, maxStaticTTL)
		}
		ttl = *c.TTL
	}
	a, err := parseStaticAddrs(c.A, false)
	if err != nil {
		return err
	}
	aaaa, err := parseStaticAddrs(c.AAAA, true)
	if err != nil {
		return err
	}
	allowSrc, err := cidr.ParseList(c.AllowSrc)
	if err != nil {
		return fmt.Errorf("allowsrc: %w", err)
	}
	c.a = a
	c.aaaa = aaaa
	c.ttl = uint32(ttl)
	c.allowSrc = allowSrc
	c.ready = true
	return nil
}

func (c *StaticConfig) ensure() error {
	if c == nil {
		return fmt.Errorf("missing config")
	}
	if c.ready {
		return nil
	}
	return c.prepare()
}

func (c *StaticConfig) clone() *StaticConfig {
	if c == nil {
		return nil
	}
	cp := *c
	cp.A = append([]string(nil), c.A...)
	cp.AAAA = append([]string(nil), c.AAAA...)
	cp.AllowSrc = append([]string(nil), c.AllowSrc...)
	cp.a = append([]netip.Addr(nil), c.a...)
	cp.aaaa = append([]netip.Addr(nil), c.aaaa...)
	cp.allowSrc = append([]netip.Prefix(nil), c.allowSrc...)
	if c.TTL != nil {
		v := *c.TTL
		cp.TTL = &v
	}
	if c.Apex != nil {
		v := *c.Apex
		cp.Apex = &v
	}
	return &cp
}

// ApexEnabled reports whether a wildcard also answers its parent name.
func (c *StaticConfig) ApexEnabled() bool {
	return c != nil && c.Apex != nil && *c.Apex
}

// AnswerTTL is the TTL used on positive and negative answers.
func (c *StaticConfig) AnswerTTL() uint32 {
	if err := c.ensure(); err != nil {
		return defaultStaticTTL
	}
	return c.ttl
}

// SourceAllowed reports whether a client address may use this rule.
// An empty allowsrc list allows every source.
func (c *StaticConfig) SourceAllowed(src netip.Addr) bool {
	if err := c.ensure(); err != nil {
		return false
	}
	if len(c.allowSrc) == 0 {
		return true
	}
	if !src.IsValid() {
		return false
	}
	return cidr.Contains(c.allowSrc, src)
}

// ARecords returns configured IPv4 addresses the policy permits.
func (c *StaticConfig) ARecords(policy cidr.Policy) []netip.Addr {
	if err := c.ensure(); err != nil {
		return nil
	}
	var out []netip.Addr
	for _, ip := range c.a {
		if policy.Permits(ip) {
			out = append(out, ip)
		}
	}
	return out
}

// AAAARecords returns configured IPv6 addresses that are not denied.
// allowips is an IPv4 filter and does not apply here.
func (c *StaticConfig) AAAARecords(deny []netip.Prefix) []netip.Addr {
	if err := c.ensure(); err != nil {
		return nil
	}
	var out []netip.Addr
	for _, ip := range c.aaaa {
		if cidr.Contains(deny, ip) {
			continue
		}
		out = append(out, ip)
	}
	return out
}

func parseStaticAddrs(raw []string, v6 bool) ([]netip.Addr, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]netip.Addr, 0, len(raw))
	seen := make(map[netip.Addr]struct{}, len(raw))
	family := "IPv4"
	if v6 {
		family = "IPv6"
	}
	for _, item := range raw {
		if item == "" {
			return nil, fmt.Errorf("empty %s address", family)
		}
		ip, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("address %q is not an IP", item)
		}
		if v6 {
			if !ip.Is6() || ip.Is4In6() {
				return nil, fmt.Errorf("aaaa address %s is not IPv6", ip)
			}
		} else if !ip.Is4() {
			return nil, fmt.Errorf("a address %s is not IPv4", ip)
		}
		if ip.IsUnspecified() || ip.IsMulticast() || (ip.Is4() && ip == netip.MustParseAddr("255.255.255.255")) {
			return nil, fmt.Errorf("address %s is not usable", ip)
		}
		if _, ok := seen[ip]; ok {
			return nil, fmt.Errorf("duplicate address %s", ip)
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out, nil
}

// splitRecordKey reports whether key is a single-label wildcard.
// The parent of "*.apps.example.internal" is "apps.example.internal".
func splitRecordKey(domain string) (wildcard bool, parent string, err error) {
	domain = NormalizeDomain(domain)
	if strings.HasPrefix(domain, "*.") {
		parent = strings.TrimPrefix(domain, "*.")
		if parent == "" || strings.Contains(parent, "*") {
			return false, "", fmt.Errorf("invalid wildcard %q", domain)
		}
		if err := validateZoneName(parent); err != nil {
			return false, "", fmt.Errorf("invalid wildcard %q", domain)
		}
		return true, parent, nil
	}
	if strings.Contains(domain, "*") {
		return false, "", fmt.Errorf("invalid zone %q", domain)
	}
	if err := validateZoneName(domain); err != nil {
		return false, "", err
	}
	return false, domain, nil
}

func matchScore(query, key string, grant DNSGrant) (int, bool) {
	query = NormalizeDomain(query)
	key = NormalizeDomain(key)
	wildcard, parent, err := splitRecordKey(key)
	if err != nil {
		return 0, false
	}
	if grant.Static != nil {
		if wildcard {
			if query == parent && grant.Static.ApexEnabled() {
				return labelCount(parent)*10 + rankApex, true
			}
			if oneLabelUnder(query, parent) {
				return labelCount(parent)*10 + rankWild, true
			}
			return 0, false
		}
		if query == key {
			return labelCount(key)*10 + rankExact, true
		}
		return 0, false
	}
	if wildcard {
		return 0, false
	}
	if query == key || strings.HasSuffix(query, "."+key) {
		return labelCount(key)*10 + rankSuffix, true
	}
	return 0, false
}

func oneLabelUnder(query, parent string) bool {
	suffix := "." + parent
	if !strings.HasSuffix(query, suffix) {
		return false
	}
	head := strings.TrimSuffix(query, suffix)
	return head != "" && !strings.Contains(head, ".")
}

func labelCount(name string) int {
	if name == "" {
		return 0
	}
	return strings.Count(name, ".") + 1
}
