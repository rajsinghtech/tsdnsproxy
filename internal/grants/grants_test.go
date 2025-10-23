package grants

import (
	"testing"

	"tailscale.com/tailcfg"
)

func TestParser_FindBestMatch(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name        string
		queryDomain string
		grants      []GrantConfig
		wantDomain  string
		wantFound   bool
	}{
		{
			name:        "exact match",
			queryDomain: "cluster.local",
			grants: []GrantConfig{
				{"cluster.local": DNSGrant{DNS: []string{"10.0.0.1:53"}}},
			},
			wantDomain: "cluster.local",
			wantFound:  true,
		},
		{
			name:        "subdomain match",
			queryDomain: "api.cluster.local",
			grants: []GrantConfig{
				{"cluster.local": DNSGrant{DNS: []string{"10.0.0.1:53"}}},
			},
			wantDomain: "cluster.local",
			wantFound:  true,
		},
		{
			name:        "most specific match wins",
			queryDomain: "api.svc.cluster.local",
			grants: []GrantConfig{
				{"cluster.local": DNSGrant{DNS: []string{"10.0.0.1:53"}}},
				{"svc.cluster.local": DNSGrant{DNS: []string{"10.0.0.2:53"}}},
			},
			wantDomain: "svc.cluster.local",
			wantFound:  true,
		},
		{
			name:        "no match",
			queryDomain: "example.com",
			grants: []GrantConfig{
				{"cluster.local": DNSGrant{DNS: []string{"10.0.0.1:53"}}},
			},
			wantDomain: "",
			wantFound:  false,
		},
		{
			name:        "case insensitive",
			queryDomain: "API.CLUSTER.LOCAL",
			grants: []GrantConfig{
				{"cluster.local": DNSGrant{DNS: []string{"10.0.0.1:53"}}},
			},
			wantDomain: "cluster.local",
			wantFound:  true,
		},
		{
			name:        "trailing dot handling",
			queryDomain: "api.cluster.local.",
			grants: []GrantConfig{
				{"cluster.local": DNSGrant{DNS: []string{"10.0.0.1:53"}}},
			},
			wantDomain: "cluster.local",
			wantFound:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, _, found := p.FindBestMatch(tt.queryDomain, tt.grants)
			if found != tt.wantFound {
				t.Errorf("FindBestMatch() found = %v, want %v", found, tt.wantFound)
			}
			if domain != tt.wantDomain {
				t.Errorf("FindBestMatch() domain = %v, want %v", domain, tt.wantDomain)
			}
		})
	}
}

func TestParser_RewriteDomain(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name          string
		queryName     string
		targetDomain  string
		rewriteDomain string
		want          string
	}{
		{
			name:          "exact match rewrite",
			queryName:     "cluster1.local",
			targetDomain:  "cluster1.local",
			rewriteDomain: "cluster.local",
			want:          "cluster.local",
		},
		{
			name:          "subdomain rewriting",
			queryName:     "api.cluster1.local",
			targetDomain:  "cluster1.local",
			rewriteDomain: "cluster.local",
			want:          "api.cluster.local",
		},
		{
			name:          "deep subdomain rewriting",
			queryName:     "v1.api.svc.cluster1.local",
			targetDomain:  "cluster1.local",
			rewriteDomain: "cluster.local",
			want:          "v1.api.svc.cluster.local",
		},
		{
			name:          "no rewriting needed",
			queryName:     "example.com",
			targetDomain:  "cluster1.local",
			rewriteDomain: "cluster.local",
			want:          "example.com",
		},
		{
			name:          "case insensitive",
			queryName:     "API.CLUSTER1.LOCAL",
			targetDomain:  "cluster1.local",
			rewriteDomain: "cluster.local",
			want:          "api.cluster.local",
		},
		{
			name:          "trailing dots",
			queryName:     "api.cluster1.local.",
			targetDomain:  "cluster1.local.",
			rewriteDomain: "cluster.local.",
			want:          "api.cluster.local.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.RewriteDomain(tt.queryName, tt.targetDomain, tt.rewriteDomain)
			if got != tt.want {
				t.Errorf("RewriteDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParser_ValidateGrant(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name    string
		grant   GrantConfig
		wantErr bool
	}{
		{
			name: "valid grant with DNS",
			grant: GrantConfig{
				"cluster.local": DNSGrant{DNS: []string{"10.0.0.1:53"}},
			},
			wantErr: false,
		},
		{
			name: "valid grant with rewriting",
			grant: GrantConfig{
				"cluster1.local": DNSGrant{Rewrite: "cluster.local"},
			},
			wantErr: false,
		},
		{
			name: "valid grant with both DNS and rewriting",
			grant: GrantConfig{
				"cluster1.local": DNSGrant{
					DNS:     []string{"10.0.0.1:53"},
					Rewrite: "cluster.local",
				},
			},
			wantErr: false,
		},
		{
			name: "valid grant with translateID",
			grant: GrantConfig{
				"cluster.local": DNSGrant{
					DNS:         []string{"10.0.0.1:53"},
					TranslateID: 42,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid - empty domain",
			grant: GrantConfig{
				"": DNSGrant{DNS: []string{"10.0.0.1:53"}},
			},
			wantErr: true,
		},
		{
			name: "invalid - no DNS or rewriting",
			grant: GrantConfig{
				"cluster.local": DNSGrant{},
			},
			wantErr: true,
		},
		{
			name: "invalid - empty DNS server",
			grant: GrantConfig{
				"cluster.local": DNSGrant{DNS: []string{""}},
			},
			wantErr: true,
		},
		{
			name: "valid - negative translateID for standard forwarding",
			grant: GrantConfig{
				"cluster.local": DNSGrant{
					DNS:         []string{"10.0.0.1:53"},
					TranslateID: -1,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.validateGrant(tt.grant)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateGrant() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParser_ParseGrants(t *testing.T) {
	p := NewParser()

	// Test with valid grants
	validCapMap := tailcfg.PeerCapMap{
		"rajsingh.info/cap/tsdnsproxy": []tailcfg.RawMessage{
			tailcfg.RawMessage(`{"cluster.local": {"dns": ["10.0.0.1:53"]}}`),
			tailcfg.RawMessage(`{"cluster2.local": {"dns": ["10.0.0.2:53"], "rewrite": "cluster.local"}}`),
		},
	}

	grants, err := p.ParseGrants(validCapMap)
	if err != nil {
		t.Fatalf("ParseGrants() unexpected error: %v", err)
	}

	if len(grants) != 2 {
		t.Errorf("ParseGrants() returned %d grants, want 2", len(grants))
	}

	// Test with invalid JSON - should skip and not return error
	invalidCapMap := tailcfg.PeerCapMap{
		"rajsingh.info/cap/tsdnsproxy": []tailcfg.RawMessage{
			tailcfg.RawMessage(`invalid json`),
			tailcfg.RawMessage(`{"valid.local": {"dns": ["10.0.0.3:53"]}}`),
		},
	}

	grants, err = p.ParseGrants(invalidCapMap)
	if err != nil {
		t.Errorf("ParseGrants() unexpected error: %v", err)
	}
	// Should have parsed the valid grant and skipped the invalid one
	if len(grants) != 1 {
		t.Errorf("ParseGrants() returned %d grants, want 1 (should skip invalid)", len(grants))
	}

	// Test with no grants
	emptyCapMap := tailcfg.PeerCapMap{}
	grants, err = p.ParseGrants(emptyCapMap)
	if err != nil {
		t.Errorf("ParseGrants() unexpected error for empty map: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("ParseGrants() returned %d grants for empty map, want 0", len(grants))
	}
}

func TestParser_ParseGrants_InvalidGrants(t *testing.T) {
	p := NewParser()

	// Test with a mix of valid and invalid grants (invalid ones should be skipped)
	capMap := tailcfg.PeerCapMap{
		"rajsingh.info/cap/tsdnsproxy": []tailcfg.RawMessage{
			// Valid grant
			tailcfg.RawMessage(`{"cluster1.local": {"dns": ["10.0.0.1:53"]}}`),
			// Invalid - empty domain
			tailcfg.RawMessage(`{"": {"dns": ["10.0.0.2:53"]}}`),
			// Invalid - no DNS or rewrite
			tailcfg.RawMessage(`{"cluster2.local": {}}`),
			// Valid grant with rewriting
			tailcfg.RawMessage(`{"cluster3.local": {"rewrite": "prod.local"}}`),
		},
	}

	grants, err := p.ParseGrants(capMap)
	if err != nil {
		t.Fatalf("ParseGrants() unexpected error: %v", err)
	}

	// Should only have 2 valid grants
	if len(grants) != 2 {
		t.Errorf("ParseGrants() returned %d grants, want 2 (valid ones only)", len(grants))
	}

	// Verify the valid grants were parsed
	validDomains := map[string]bool{
		"cluster1.local": false,
		"cluster3.local": false,
	}

	for _, grant := range grants {
		for domain := range grant {
			if _, ok := validDomains[domain]; ok {
				validDomains[domain] = true
			}
		}
	}

	for domain, found := range validDomains {
		if !found {
			t.Errorf("ParseGrants() missing valid domain %s", domain)
		}
	}
}

func TestParser_DomainMatches(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name        string
		queryDomain string
		grantDomain string
		wantMatch   bool
	}{
		{
			name:        "exact match",
			queryDomain: "cluster.local",
			grantDomain: "cluster.local",
			wantMatch:   true,
		},
		{
			name:        "subdomain match",
			queryDomain: "api.cluster.local",
			grantDomain: "cluster.local",
			wantMatch:   true,
		},
		{
			name:        "deep subdomain match",
			queryDomain: "v1.api.svc.cluster.local",
			grantDomain: "cluster.local",
			wantMatch:   true,
		},
		{
			name:        "no match - different domain",
			queryDomain: "example.com",
			grantDomain: "cluster.local",
			wantMatch:   false,
		},
		{
			name:        "no match - partial suffix",
			queryDomain: "notcluster.local",
			grantDomain: "cluster.local",
			wantMatch:   false,
		},
		{
			name:        "no match - grant is subdomain of query",
			queryDomain: "local",
			grantDomain: "cluster.local",
			wantMatch:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.domainMatches(tt.queryDomain, tt.grantDomain)
			if got != tt.wantMatch {
				t.Errorf("domainMatches(%q, %q) = %v, want %v", tt.queryDomain, tt.grantDomain, got, tt.wantMatch)
			}
		})
	}
}

func TestParser_FindBestMatch_ComplexScenarios(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name        string
		queryDomain string
		grants      []GrantConfig
		wantDomain  string
		wantGrant   DNSGrant
		wantFound   bool
	}{
		{
			name:        "multiple overlapping domains - most specific wins",
			queryDomain: "api.v1.svc.cluster.local",
			grants: []GrantConfig{
				{"local": DNSGrant{DNS: []string{"10.0.0.1:53"}}},
				{"cluster.local": DNSGrant{DNS: []string{"10.0.0.2:53"}}},
				{"svc.cluster.local": DNSGrant{DNS: []string{"10.0.0.3:53"}}},
				{"v1.svc.cluster.local": DNSGrant{DNS: []string{"10.0.0.4:53"}}},
			},
			wantDomain: "v1.svc.cluster.local",
			wantGrant:  DNSGrant{DNS: []string{"10.0.0.4:53"}},
			wantFound:  true,
		},
		{
			name:        "grant with all features",
			queryDomain: "service.test.local",
			grants: []GrantConfig{
				{"test.local": DNSGrant{
					DNS:         []string{"10.0.0.1:53", "10.0.0.2:53"},
					Rewrite:     "prod.local",
					TranslateID: 42,
				}},
			},
			wantDomain: "test.local",
			wantGrant: DNSGrant{
				DNS:         []string{"10.0.0.1:53", "10.0.0.2:53"},
				Rewrite:     "prod.local",
				TranslateID: 42,
			},
			wantFound: true,
		},
		{
			name:        "empty grants list",
			queryDomain: "cluster.local",
			grants:      []GrantConfig{},
			wantDomain:  "",
			wantGrant:   DNSGrant{},
			wantFound:   false,
		},
		{
			name:        "grants with same domain in different configs",
			queryDomain: "api.cluster.local",
			grants: []GrantConfig{
				{"cluster.local": DNSGrant{DNS: []string{"10.0.0.1:53"}}},
				{"cluster.local": DNSGrant{DNS: []string{"10.0.0.2:53"}}}, // Duplicate domain
			},
			wantDomain: "cluster.local",
			// Skip grant comparison for this test since it's implementation dependent
			wantFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, grant, found := p.FindBestMatch(tt.queryDomain, tt.grants)
			if found != tt.wantFound {
				t.Errorf("FindBestMatch() found = %v, want %v", found, tt.wantFound)
			}
			if domain != tt.wantDomain {
				t.Errorf("FindBestMatch() domain = %v, want %v", domain, tt.wantDomain)
			}
			if found && tt.wantFound && tt.name != "grants with same domain in different configs" {
				// Compare grants when found (skip for duplicate domain test)
				if len(grant.DNS) != len(tt.wantGrant.DNS) {
					t.Errorf("FindBestMatch() grant.DNS len = %v, want %v", len(grant.DNS), len(tt.wantGrant.DNS))
				}
				if grant.Rewrite != tt.wantGrant.Rewrite {
					t.Errorf("FindBestMatch() grant.Rewrite = %v, want %v", grant.Rewrite, tt.wantGrant.Rewrite)
				}
				if grant.TranslateID != tt.wantGrant.TranslateID {
					t.Errorf("FindBestMatch() grant.TranslateID = %v, want %v", grant.TranslateID, tt.wantGrant.TranslateID)
				}
			}
		})
	}
}
