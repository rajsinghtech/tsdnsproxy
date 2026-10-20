package grants

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/rajsinghtech/tsdnsproxy/internal/backend"
	"github.com/rajsinghtech/tsdnsproxy/internal/cidr"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
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
	// IPNames synthesizes answers for dashed IPv4 labels under this zone.
	// It cannot be combined with Rewrite or TranslateID.
	IPNames *IPNamesConfig `json:"ipnames,omitempty"`
	// Static answers the matched name from configured addresses.
	// It cannot be combined with DNS, Rewrite, TranslateID, or IPNames.
	Static *StaticConfig `json:"static,omitempty"`
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

// Parser handles parsing of grants from one peer capability.
type Parser struct {
	capName string
}

// NewParser creates a parser that reads DefaultCapName.
func NewParser() *Parser {
	return &Parser{capName: DefaultCapName}
}

// NewParserWithName returns a parser that reads name.
// Surrounding whitespace is removed before validation.
func NewParserWithName(name string) (*Parser, error) {
	name = strings.TrimSpace(name)
	if err := ValidateCapName(name); err != nil {
		return nil, err
	}
	return &Parser{capName: name}, nil
}

// CapName returns the capability this parser reads.
// A zero parser reads DefaultCapName.
func (p *Parser) CapName() string {
	if p == nil || p.capName == "" {
		return DefaultCapName
	}
	return p.capName
}

// ParseGrants extracts DNS grants for this parser's capability from capMap.
// Entries under any other capability name are ignored.
func (p *Parser) ParseGrants(capMap tailcfg.PeerCapMap) ([]GrantConfig, error) {

	var grantConfigs []GrantConfig

	rawMessages, exists := capMap[peercap.Cap(p.CapName())]
	if !exists {
		return nil, nil
	}

	for i, raw := range rawMessages {
		slog.Debug(fmt.Sprintf("parsing grant %d, raw: %s", i, raw))
		var grant GrantConfig
		if err := json.Unmarshal([]byte(raw), &grant); err != nil {
			// Log the error to help with debugging configuration issues
			slog.Warn("failed to unmarshal grant", "index", i, "err", err.Error())
			slog.Debug("raw grant", "index", i, "raw", string(raw))
			continue // Skip invalid grants
		}

		slog.Debug(fmt.Sprintf("parsed grant %d: %d domains", i, len(grant)))
		if err := p.validateGrant(grant); err != nil {
			slog.Warn("invalid grant", "index", i, "err", err.Error())
			continue
		}
		slog.Debug("validated grant", "index", i)
		grantConfigs = append(grantConfigs, grant)
	}

	return resolveIPNamesConflicts(grantConfigs), nil
}

// FindBestMatch finds the most specific domain match for a query.
// A static name matches only itself. A static wildcard matches one label
// under its parent, and the parent only when apex is set.
// Other domain rules match themselves and any name under them.
// An exact static name beats a wildcard, a wildcard beats a zone of the
// same parent, and a longer name beats a shorter one.
func (p *Parser) FindBestMatch(queryDomain string, grants []GrantConfig) (string, DNSGrant, bool) {
	queryDomain = NormalizeDomain(queryDomain)

	var bestMatch string
	var bestGrant DNSGrant
	var bestScore int
	var found bool

	for _, grantConfig := range grants {
		for domain, grant := range grantConfig {
			domain = NormalizeDomain(domain)
			if _, ok := PrefixKey(domain); ok {
				continue
			}
			score, ok := matchScore(queryDomain, domain, grant)
			if !ok {
				continue
			}
			if !found || score > bestScore || (score == bestScore && len(domain) > len(bestMatch)) {
				bestMatch = domain
				bestGrant = grant
				bestScore = score
				found = true
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
		var wildcard bool
		if !isPrefix {
			var err error
			wildcard, _, err = splitRecordKey(domain)
			if err != nil {
				return err
			}
		}

		hasFilter := len(dnsGrant.AllowIPs) > 0 || len(dnsGrant.DenyIPs) > 0
		hasTranslate := dnsGrant.TranslateID != nil
		hasIPNames := dnsGrant.IPNames != nil
		hasStatic := dnsGrant.Static != nil
		if hasIPNames && isPrefix {
			return fmt.Errorf("ipnames cannot use CIDR key %s", domain)
		}
		if hasStatic && isPrefix {
			return fmt.Errorf("static cannot use CIDR key %s", domain)
		}
		if hasStatic {
			if !wildcard && dnsGrant.Static.ApexEnabled() {
				return fmt.Errorf("apex is only valid on a wildcard for %s", domain)
			}
			if dnsGrant.Rewrite != "" {
				return fmt.Errorf("static cannot be combined with rewrite for %s", domain)
			}
			if dnsGrant.TranslateID != nil {
				return fmt.Errorf("static cannot be combined with translateid for %s", domain)
			}
			if len(dnsGrant.DNS) > 0 {
				return fmt.Errorf("static cannot be combined with dns for %s", domain)
			}
			if hasIPNames {
				return fmt.Errorf("static cannot be combined with ipnames for %s", domain)
			}
			if err := dnsGrant.Static.prepare(); err != nil {
				return fmt.Errorf("static %s: %w", domain, err)
			}
			grant[domain] = dnsGrant
		}
		if wildcard && !hasStatic {
			return fmt.Errorf("wildcard %s requires static", NormalizeDomain(domain))
		}
		if isPrefix {
			if !hasFilter && !hasTranslate && !hasIPNames && !hasStatic && len(dnsGrant.DNS) == 0 && dnsGrant.Rewrite == "" {
				return fmt.Errorf("empty grant for %s", domain)
			}
		} else if !hasIPNames && !hasStatic && len(dnsGrant.DNS) == 0 && dnsGrant.Rewrite == "" {
			return fmt.Errorf("empty grant for %s", domain)
		}
		if hasIPNames {
			if err := validateIPNamesZone(domain); err != nil {
				return err
			}
			if dnsGrant.Rewrite != "" {
				return fmt.Errorf("ipnames cannot be combined with rewrite for %s", domain)
			}
			if dnsGrant.TranslateID != nil {
				return fmt.Errorf("ipnames cannot be combined with translateid for %s", domain)
			}
			if len(dnsGrant.DNS) > 0 {
				slog.Warn("dns servers on an ipnames zone are ignored", "zone", domain)
			}
			if err := dnsGrant.IPNames.prepare(); err != nil {
				return fmt.Errorf("ipnames %s: %w", domain, err)
			}
			grant[domain] = dnsGrant
		}

		// Validate DNS server addresses. bare, direct://, and tailnet:// are allowed.
		for _, server := range dnsGrant.DNS {
			if server == "" {
				return fmt.Errorf("empty DNS server in grant for %s", domain)
			}
			if _, err := backend.ParseEndpoint(server, backend.DialDirect); err != nil {
				return fmt.Errorf("dns server %q for %s: %w", server, domain, err)
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
