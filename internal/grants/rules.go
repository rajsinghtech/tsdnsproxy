package grants

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/hujson"
)

// RulesPollInterval is how often a rules file is checked for changes.
const RulesPollInterval = 2 * time.Second

// RulesFile is a grant map loaded from disk and applied to every client.
// Reload keeps the previous rules when a new read fails.
type RulesFile struct {
	mu     sync.RWMutex
	path   string
	rules  GrantConfig
	loaded bool
	sum    [32]byte
}

// ParseRules parses a JSON or HuJSON rules document.
// The document is one map of domain or CIDR to a grant, the same shape as a
// single ACL grant value. A rule that would be rejected as a grant is an error.
func ParseRules(data []byte) (GrantConfig, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, fmt.Errorf("rules file is empty")
	}
	standardized, err := hujson.Standardize(data)
	if err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	var cfg GrantConfig
	if err := json.Unmarshal(standardized, &cfg); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	cfg, err = normalizeRules(cfg)
	if err != nil {
		return nil, err
	}
	if err := validateRulesConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// OpenRulesFile reads and validates path. The process should exit when this fails.
func OpenRulesFile(path string) (*RulesFile, error) {
	if path == "" {
		return nil, fmt.Errorf("rules file path is empty")
	}
	r := &RulesFile{path: path}
	if _, err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Path returns the file this set of rules was loaded from.
func (r *RulesFile) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}

// Current returns the last valid rules. The boolean is false when nothing is loaded.
func (r *RulesFile) Current() (GrantConfig, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.loaded {
		return nil, false
	}
	return r.rules, true
}

// Reload reads the file again. changed is false when the bytes are unchanged.
// A parse error leaves the previous rules in place.
func (r *RulesFile) Reload() (bool, error) {
	data, err := os.ReadFile(r.path)
	if err != nil {
		return false, fmt.Errorf("read rules file: %w", err)
	}
	sum := sha256.Sum256(data)
	r.mu.RLock()
	same := r.loaded && sum == r.sum
	r.mu.RUnlock()
	if same {
		return false, nil
	}
	cfg, err := ParseRules(data)
	if err != nil {
		return false, fmt.Errorf("rules file %s: %w", r.path, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loaded && sum == r.sum {
		return false, nil
	}
	r.rules = cfg
	r.sum = sum
	r.loaded = true
	return true, nil
}

// Watch reloads the file until ctx is cancelled.
// interval is RulesPollInterval when it is not positive.
func (r *RulesFile) Watch(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = RulesPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastErr string
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			changed, err := r.Reload()
			if err != nil {
				msg := err.Error()
				if msg != lastErr {
					log.Printf("rules reload failed: %v", err)
					lastErr = msg
				}
				continue
			}
			lastErr = ""
			if changed {
				log.Printf("reloaded rules from %s", r.path)
			}
		}
	}
}

// ApplyRules combines a rules file with ACL grants.
// rulesOnly returns the file and ignores grants.
// An ACL grant that names the same domain or CIDR replaces the file rule.
// File rules for every other name are kept.
func ApplyRules(file GrantConfig, acl []GrantConfig, rulesOnly bool) []GrantConfig {
	if rulesOnly {
		if len(file) == 0 {
			return nil
		}
		return []GrantConfig{file}
	}
	if len(file) == 0 {
		return acl
	}

	overridden := map[string]struct{}{}
	for _, cfg := range acl {
		for domain := range cfg {
			key := NormalizeDomain(domain)
			if fileHas(file, key) {
				overridden[key] = struct{}{}
			}
		}
	}

	base := make(GrantConfig, len(file))
	for domain, grant := range file {
		key := NormalizeDomain(domain)
		if _, skip := overridden[key]; skip {
			continue
		}
		base[key] = grant
	}

	out := make([]GrantConfig, 0, len(acl)+1)
	if len(base) > 0 {
		out = append(out, base)
	}
	for _, cfg := range acl {
		if len(cfg) == 0 {
			continue
		}
		out = append(out, cfg)
	}
	return out
}

func fileHas(file GrantConfig, key string) bool {
	if _, ok := file[key]; ok {
		return true
	}
	for domain := range file {
		if NormalizeDomain(domain) == key {
			return true
		}
	}
	return false
}

func normalizeRules(cfg GrantConfig) (GrantConfig, error) {
	if cfg == nil {
		return nil, fmt.Errorf("rules file must be an object")
	}
	out := make(GrantConfig, len(cfg))
	for domain, grant := range cfg {
		key := NormalizeDomain(domain)
		if key == "" {
			return nil, fmt.Errorf("empty domain in rules file")
		}
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("duplicate rule for %s", key)
		}
		out[key] = grant
	}
	return out, nil
}

func validateRulesConfig(cfg GrantConfig) error {
	if err := NewParser().validateGrant(cfg); err != nil {
		return err
	}
	var zones []string
	for domain, grant := range cfg {
		if grant.IPNames != nil {
			zones = append(zones, NormalizeDomain(domain))
		}
	}
	sort.Strings(zones)
	for i := 0; i < len(zones); i++ {
		for j := i + 1; j < len(zones); j++ {
			if ipNamesNested(zones[i], zones[j]) {
				return fmt.Errorf("nested ipnames zones %s and %s", zones[i], zones[j])
			}
		}
	}
	return nil
}
