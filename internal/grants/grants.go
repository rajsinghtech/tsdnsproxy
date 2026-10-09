package grants

import (
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"strings"

	"github.com/rajsinghtech/tsdnsproxy/internal/cidr"
	"tailscale.com/tailcfg"
)

// NormalizeDomain converts a domain to lowercase and removes trailing dot
func NormalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(domain), ".")
}

// MaxTranslateID is the largest site id that can be encoded for translation.
const MaxTranslateID = 65535

// DNSGrant represents a DNS configuration grant.
// TranslateID is nil when the field is omitted. Nil and any negative value
// forward the query. An explicit value from 0 through MaxTranslateID is
// authoritative: 0 returns backend addresses unchanged, and a positive value
// is the site id used for translation.
type DNSGrant struct {
	DNS         []string `json:"dns,omitempty"`     // Backend DNS servers
	Rewrite     string   `json:"rewrite,omitempty"` // Domain rewrite target
	TranslateID *int     `json:"translateid,omitempty"`
	// AllowIPs, when non-empty, limits which IPv4 answers are translated.
	// DenyIPs are never translated. Both use the shared CIDR matcher.
	AllowIPs []string `json:"allowips,omitempty"`
	DenyIPs  []string `json:"denyips,omitempty"`
}

// IPPolicy builds the translation filter for this grant.
// Defaults block shared and non-routable ranges unless AllowIPs covers them.
func (g DNSGrant) IPPolicy() (cidr.Policy, error) {
	allow, err := cidr.ParseList(g.AllowIPs)
	if err != nil {
		return cidr.Policy{}, err
	}
	deny, err := cidr.ParseList(g.DenyIPs)
	if err != nil {
		return cidr.Policy{}, err
	}
	return cidr.Policy{Allow: allow, Deny: deny, ApplyDefaults: true}, nil
}

// PrefixKey parses key as a CIDR rule. Domain keys return false.
func PrefixKey(key string) (netip.Prefix, bool) {
	if !strings.Contains(key, "/") {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(key)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// ExplicitTranslateID reports whether translateid was present in the grant.
func (g DNSGrant) ExplicitTranslateID() (int, bool) {
	if g.TranslateID == nil {
		return 0, false
	}
	return *g.TranslateID, true
}

// Authoritative reports whether the grant should answer the query itself.
func (g DNSGrant) Authoritative() bool {
	id, ok := g.ExplicitTranslateID()
	return ok && id >= 0 && id <= MaxTranslateID
}

// GrantConfig maps domains to their DNS grants
type GrantConfig map[string]DNSGrant

// Parser handles parsing of grants from capabilities
type Parser struct {
}

// NewParser creates a new grant parser
func NewParser() *Parser {
	return &Parser{}
}

// ParseGrants extracts DNS grants from capability map
func (p *Parser) ParseGrants(capMap tailcfg.PeerCapMap) ([]GrantConfig, error) {

	var grantConfigs []GrantConfig

	rawMessages, exists := capMap["rajsingh.info/cap/tsdnsproxy"]
	if !exists {
		return nil, nil
	}

	for i, raw := range rawMessages {
		log.Printf("[v] parsing grant %d, raw: %s", i, raw)
		var grant GrantConfig
		if err := json.Unmarshal([]byte(raw), &grant); err != nil {
			// Log the error to help with debugging configuration issues
			log.Printf("warning: failed to unmarshal grant %d: %v", i, err)
			log.Printf("warning: raw grant data: %s", raw)
			continue // Skip invalid grants
		}

		log.Printf("[v] parsed grant %d successfully: %+v", i, grant)
		if err := p.validateGrant(grant); err != nil {
			log.Printf("warning: invalid grant %d: %v", i, err)
			continue
		}
		log.Printf("[v] validated grant %d successfully", i)
		grantConfigs = append(grantConfigs, grant)
	}

	return grantConfigs, nil
}

// FindBestMatch finds the most specific domain match for a query
func (p *Parser) FindBestMatch(queryDomain string, grants []GrantConfig) (string, DNSGrant, bool) {
	queryDomain = NormalizeDomain(queryDomain)

	var bestMatch string
	var bestGrant DNSGrant
	var found bool

	for _, grantConfig := range grants {
		for domain, grant := range grantConfig {
			domain = NormalizeDomain(domain)
			if _, ok := PrefixKey(domain); ok {
				continue
			}

			// Check if query matches this domain
			if p.domainMatches(queryDomain, domain) {
				// Use the most specific (longest) match
				if len(domain) > len(bestMatch) {
					bestMatch = domain
					bestGrant = grant
					found = true
				}
			}
		}
	}

	return bestMatch, bestGrant, found
}

// MatchPrefix returns the longest CIDR-keyed grant that covers ip.
func (p *Parser) MatchPrefix(ip netip.Addr, grants []GrantConfig) (netip.Prefix, DNSGrant, bool) {
	var best netip.Prefix
	var bestGrant DNSGrant
	var found bool

	for _, grantConfig := range grants {
		for key, grant := range grantConfig {
			prefix, ok := PrefixKey(NormalizeDomain(key))
			if !ok || !prefix.Contains(ip) {
				continue
			}
			if !found || prefix.Bits() > best.Bits() {
				best = prefix
				bestGrant = grant
				found = true
			}
		}
	}
	return best, bestGrant, found
}

// domainMatches checks if a query domain matches a grant domain
// Grant domains act as wildcards: "cluster.local" matches "*.cluster.local"
func (p *Parser) domainMatches(queryDomain, grantDomain string) bool {
	if queryDomain == grantDomain {
		return true
	}

	return strings.HasSuffix(queryDomain, "."+grantDomain)
}

// validateGrant performs basic validation on a grant
func (p *Parser) validateGrant(grant GrantConfig) error {
	for domain, dnsGrant := range grant {
		if domain == "" {
			return fmt.Errorf("empty domain in grant")
		}

		prefix, isPrefix := PrefixKey(domain)
		if strings.Contains(domain, "/") && !isPrefix {
			return fmt.Errorf("invalid CIDR %q", domain)
		}
		if isPrefix && !prefix.IsValid() {
			return fmt.Errorf("invalid CIDR %q", domain)
		}

		hasFilter := len(dnsGrant.AllowIPs) > 0 || len(dnsGrant.DenyIPs) > 0
		hasTranslate := dnsGrant.TranslateID != nil
		if isPrefix {
			if !hasFilter && !hasTranslate && len(dnsGrant.DNS) == 0 && dnsGrant.Rewrite == "" {
				return fmt.Errorf("empty grant for %s", domain)
			}
		} else if len(dnsGrant.DNS) == 0 && dnsGrant.Rewrite == "" {
			return fmt.Errorf("empty grant for %s", domain)
		}

		// Validate DNS server addresses
		for _, server := range dnsGrant.DNS {
			if server == "" {
				return fmt.Errorf("empty DNS server in grant for %s", domain)
			}
		}

		if _, err := dnsGrant.IPPolicy(); err != nil {
			return fmt.Errorf("grant %s: %w", domain, err)
		}

		// Negative values select forwarding. Only a non-negative site id is bounded.
		if id, ok := dnsGrant.ExplicitTranslateID(); ok && id > MaxTranslateID {
			return fmt.Errorf("translateid %d for %s is outside 0-%d", id, domain, MaxTranslateID)
		}
	}

	return nil
}

// RewriteDomain applies domain rewrite to a query name
func (p *Parser) RewriteDomain(queryName, targetDomain, rewriteDomain string) string {
	// Preserve original format (with or without trailing dot)
	hadTrailingDot := strings.HasSuffix(queryName, ".")

	queryName = NormalizeDomain(queryName)
	targetDomain = NormalizeDomain(targetDomain)
	rewriteDomain = NormalizeDomain(rewriteDomain)

	var result string

	// If query exactly matches target, replace with rewrite
	if queryName == targetDomain {
		result = rewriteDomain
	} else if strings.HasSuffix(queryName, "."+targetDomain) {
		// If query is subdomain of target, replace suffix
		prefix := strings.TrimSuffix(queryName, "."+targetDomain)
		result = prefix + "." + rewriteDomain
	} else {
		result = queryName
	}

	// Restore trailing dot if original had one
	if hadTrailingDot && !strings.HasSuffix(result, ".") {
		result += "."
	}

	return result
}
