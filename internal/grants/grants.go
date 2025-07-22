package grants

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"tailscale.com/tailcfg"
)

// NormalizeDomain converts a domain to lowercase and removes trailing dot
func NormalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(domain), ".")
}

// DNSGrant represents a DNS configuration grant
type DNSGrant struct {
	DNS         []string `json:"dns"`         // Backend DNS servers
	Rewrite     string   `json:"rewrite"`     // Domain rewrite target
	TranslateID int      `json:"translateid"` // 4via6 site ID for translation
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
		var grant GrantConfig
		if err := json.Unmarshal([]byte(raw), &grant); err != nil {
			// Log the error to help with debugging configuration issues
			log.Printf("warning: failed to unmarshal grant %d: %v", i, err)
			continue // Skip invalid grants
		}

		if err := p.validateGrant(grant); err != nil {
			log.Printf("warning: invalid grant %d: %v", i, err)
			continue
		}
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

		if len(dnsGrant.DNS) == 0 && dnsGrant.Rewrite == "" {
			return fmt.Errorf("empty grant for %s", domain)
		}

		// Validate DNS server addresses
		for _, server := range dnsGrant.DNS {
			if server == "" {
				return fmt.Errorf("empty DNS server in grant for %s", domain)
			}
		}

		if dnsGrant.TranslateID < 0 {
			return fmt.Errorf("negative translate ID for %s", domain)
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
