package grants

import (
	"fmt"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/backend"
)

const (
	// DefaultZoneTimeout bounds one upstream or fallback attempt.
	DefaultZoneTimeout = time.Second
	minZoneTimeout     = 50 * time.Millisecond
	maxZoneTimeout     = 5 * time.Second
)

// DefaultZonePrivate is used as allowips on a zone rule that sets none.
var DefaultZonePrivate = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

// ZoneConfig forwards a whole zone and handles each answer.
// A private A answer is translated with the rule's translateid. Other answers
// pass through. An empty, failed, or slow upstream answer is retried on
// Fallback, or on the default upstreams when Fallback is empty.
type ZoneConfig struct {
	Fallback []string `json:"fallback,omitempty"`
	Timeout  string   `json:"timeout,omitempty"`
}

// TimeoutValue returns the per-attempt timeout.
// An empty or invalid value returns DefaultZoneTimeout.
func (c *ZoneConfig) TimeoutValue() time.Duration {
	if c == nil || c.Timeout == "" {
		return DefaultZoneTimeout
	}
	d, err := parseZoneTimeout(c.Timeout)
	if err != nil {
		return DefaultZoneTimeout
	}
	return d
}

func (c *ZoneConfig) clone() *ZoneConfig {
	if c == nil {
		return nil
	}
	cp := *c
	cp.Fallback = append([]string(nil), c.Fallback...)
	return &cp
}

func parseZoneTimeout(raw string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("timeout %q: %w", raw, err)
	}
	if d < minZoneTimeout || d > maxZoneTimeout {
		return 0, fmt.Errorf("timeout %s is outside %s-%s", d, minZoneTimeout, maxZoneTimeout)
	}
	return d, nil
}

// ZoneGrant returns g with allowips set to DefaultZonePrivate when it is empty.
func (g DNSGrant) ZoneGrant() DNSGrant {
	if len(g.AllowIPs) == 0 {
		g.AllowIPs = append([]string(nil), DefaultZonePrivate...)
	}
	return g
}

func validateZone(domain string, g DNSGrant) error {
	z := g.Zone
	if g.Static != nil || g.IPNames != nil {
		return fmt.Errorf("zone cannot be combined with static or ipnames for %s", domain)
	}
	if g.Rewrite != "" {
		return fmt.Errorf("zone cannot be combined with rewrite for %s", domain)
	}
	if len(g.DNS) == 0 {
		return fmt.Errorf("zone requires dns for %s", domain)
	}
	id, ok := g.ExplicitTranslateID()
	if !ok || id < 1 || id > MaxTranslateID {
		return fmt.Errorf("zone requires translateid 1-%d for %s", MaxTranslateID, domain)
	}
	if z.Timeout != "" {
		if _, err := parseZoneTimeout(z.Timeout); err != nil {
			return fmt.Errorf("zone %s: %w", domain, err)
		}
	}
	for _, server := range z.Fallback {
		if server == "" {
			return fmt.Errorf("empty fallback server in zone %s", domain)
		}
		if _, err := backend.ParseEndpoint(server, backend.DialDirect); err != nil {
			return fmt.Errorf("fallback server %q for %s: %w", server, domain, err)
		}
	}
	return nil
}
