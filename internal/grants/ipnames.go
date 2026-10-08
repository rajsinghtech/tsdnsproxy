package grants

import (
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"

	"github.com/rajsinghtech/tsdnsproxy/internal/cidr"
)

const (
	defaultIPNamesTTL    = 300
	defaultIPNamesNegTTL = 60
	maxIPNamesTTL        = 86400
)

// IPNamesConfig is the optional encoded-name block on one zone.
// SiteID must be present. A nil pointer means the field was omitted.
type IPNamesConfig struct {
	SiteID    *int     `json:"siteid"`
	A         string   `json:"a,omitempty"`
	TTL       *int     `json:"ttl,omitempty"`
	NegTTL    *int     `json:"negttl,omitempty"`
	AllowSrc  []string `json:"allowsrc,omitempty"`
	DirectSrc []string `json:"directsrc,omitempty"`
	AllowIPs  []string `json:"allowips,omitempty"`

	siteID    int
	mode      string
	ttl       uint32
	negTTL    uint32
	allowSrc  []netip.Prefix
	directSrc []netip.Prefix
	allowIPs  []netip.Prefix
	ready     bool
}

func (c *IPNamesConfig) prepare() error {
	if c == nil {
		return fmt.Errorf("missing config")
	}
	if c.SiteID == nil {
		return fmt.Errorf("siteid is required")
	}
	if *c.SiteID < 0 || *c.SiteID > MaxTranslateID {
		return fmt.Errorf("siteid %d is outside 0-%d", *c.SiteID, MaxTranslateID)
	}
	mode := c.A
	if mode == "" {
		mode = "never"
	}
	switch mode {
	case "never", "always", "direct":
	default:
		return fmt.Errorf("a %q is not never, always, or direct", mode)
	}
	ttl := defaultIPNamesTTL
	if c.TTL != nil {
		if *c.TTL < 1 || *c.TTL > maxIPNamesTTL {
			return fmt.Errorf("ttl %d is outside 1-%d", *c.TTL, maxIPNamesTTL)
		}
		ttl = *c.TTL
	}
	neg := defaultIPNamesNegTTL
	if c.NegTTL != nil {
		if *c.NegTTL < 1 || *c.NegTTL > maxIPNamesTTL {
			return fmt.Errorf("negttl %d is outside 1-%d", *c.NegTTL, maxIPNamesTTL)
		}
		neg = *c.NegTTL
	}
	allowSrc, err := cidr.ParseList(c.AllowSrc)
	if err != nil {
		return fmt.Errorf("allowsrc: %w", err)
	}
	directSrc, err := cidr.ParseList(c.DirectSrc)
	if err != nil {
		return fmt.Errorf("directsrc: %w", err)
	}
	allowIPs, err := cidr.ParseList(c.AllowIPs)
	if err != nil {
		return fmt.Errorf("allowips: %w", err)
	}
	if mode == "direct" && len(directSrc) == 0 {
		return fmt.Errorf("directsrc is required when a is direct")
	}
	c.siteID = *c.SiteID
	c.mode = mode
	c.ttl = uint32(ttl)
	c.negTTL = uint32(neg)
	c.allowSrc = allowSrc
	c.directSrc = directSrc
	c.allowIPs = allowIPs
	c.ready = true
	return nil
}

func (c *IPNamesConfig) ensure() error {
	if c == nil {
		return fmt.Errorf("missing config")
	}
	if c.ready {
		return nil
	}
	return c.prepare()
}

// SiteIDValue returns the configured site id.
func (c *IPNamesConfig) SiteIDValue() (int, error) {
	if err := c.ensure(); err != nil {
		return 0, err
	}
	return c.siteID, nil
}

// AMode is never, always, or direct.
func (c *IPNamesConfig) AMode() string {
	if err := c.ensure(); err != nil {
		return "never"
	}
	return c.mode
}

// AnswerTTL is the positive answer TTL.
func (c *IPNamesConfig) AnswerTTL() uint32 {
	if err := c.ensure(); err != nil {
		return defaultIPNamesTTL
	}
	return c.ttl
}

// NegativeTTL is the SOA minimum used on negative answers.
func (c *IPNamesConfig) NegativeTTL() uint32 {
	if err := c.ensure(); err != nil {
		return defaultIPNamesNegTTL
	}
	return c.negTTL
}

// SourceAllowed reports whether a client address may use this zone.
// An empty allowsrc list allows every source.
func (c *IPNamesConfig) SourceAllowed(src netip.Addr) bool {
	if err := c.ensure(); err != nil {
		return false
	}
	if len(c.allowSrc) == 0 {
		return true
	}
	return cidr.Contains(c.allowSrc, src)
}

// AAllowed reports whether an A answer should be synthesized for src.
func (c *IPNamesConfig) AAllowed(src netip.Addr) bool {
	if err := c.ensure(); err != nil {
		return false
	}
	switch c.mode {
	case "always":
		return true
	case "direct":
		return cidr.Contains(c.directSrc, src)
	default:
		return false
	}
}

// EncodedAllowed reports whether ip may be encoded for this zone.
// Built-in blocked ranges apply unless allowips covers the address.
func (c *IPNamesConfig) EncodedAllowed(ip netip.Addr) bool {
	if err := c.ensure(); err != nil {
		return false
	}
	return (cidr.Policy{Allow: c.allowIPs, ApplyDefaults: true}).Permits(ip)
}

func validateIPNamesZone(zone string) error {
	zone = NormalizeDomain(zone)
	if zone == "" || strings.Contains(zone, "..") {
		return fmt.Errorf("invalid ipnames zone %q", zone)
	}
	labels := strings.Split(zone, ".")
	if len(labels) < 2 {
		return fmt.Errorf("ipnames zone %q needs at least two labels", zone)
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("invalid ipnames zone %q", zone)
		}
	}
	return nil
}

type ipNamesSight struct {
	idx  int
	key  string
	zone string
	cfg  IPNamesConfig
}

func resolveIPNamesConflicts(configs []GrantConfig) []GrantConfig {
	var all []ipNamesSight
	for i, cfg := range configs {
		for key, grant := range cfg {
			if grant.IPNames == nil {
				continue
			}
			all = append(all, ipNamesSight{i, key, NormalizeDomain(key), *grant.IPNames})
		}
	}
	byZone := map[string][]ipNamesSight{}
	for _, s := range all {
		byZone[s.zone] = append(byZone[s.zone], s)
	}
	drop := map[string]bool{}
	for zone, group := range byZone {
		if len(group) < 2 {
			continue
		}
		same := true
		for _, s := range group[1:] {
			if !ipNamesEqual(group[0].cfg, s.cfg) {
				same = false
				break
			}
		}
		if !same {
			log.Printf("warning: dropping ipnames zone %s: conflicting settings", zone)
			drop[zone] = true
			continue
		}
		for _, s := range group[1:] {
			delete(configs[s.idx], s.key)
		}
	}

	var zones []string
	for zone := range byZone {
		if !drop[zone] {
			zones = append(zones, zone)
		}
	}
	sort.Strings(zones)
	for i := 0; i < len(zones); i++ {
		for j := i + 1; j < len(zones); j++ {
			if ipNamesNested(zones[i], zones[j]) {
				log.Printf("warning: dropping nested ipnames zones %s and %s", zones[i], zones[j])
				drop[zones[i]] = true
				drop[zones[j]] = true
			}
		}
	}
	for _, s := range all {
		if drop[s.zone] {
			delete(configs[s.idx], s.key)
		}
	}
	out := make([]GrantConfig, 0, len(configs))
	for _, cfg := range configs {
		if len(cfg) > 0 {
			out = append(out, cfg)
		}
	}
	return out
}

func ipNamesNested(a, b string) bool {
	return strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

func ipNamesEqual(a, b IPNamesConfig) bool {
	if !intPtrEqual(a.SiteID, b.SiteID) || a.A != b.A || !intPtrEqual(a.TTL, b.TTL) || !intPtrEqual(a.NegTTL, b.NegTTL) {
		return false
	}
	return sameStringSet(a.AllowSrc, b.AllowSrc) && sameStringSet(a.DirectSrc, b.DirectSrc) && sameStringSet(a.AllowIPs, b.AllowIPs)
}

func intPtrEqual(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}
