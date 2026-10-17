package grants

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

func TestParseRulesJSONAndHuJSON(t *testing.T) {
	jsonBody := `{
		"Example.Internal.": {
			"dns": ["10.0.0.53:53"],
			"translateid": 1,
			"allowips": ["10.0.0.0/8"],
			"denyips": ["10.1.0.0/24"]
		},
		"site-a.example": {"ipnames": {"siteid": 1, "a": "never", "ttl": 300}}
	}`
	hujsonBody := `{
		// lab zone
		"example.internal": {
			"dns": ["10.0.0.53:53"],
			"translateid": 1,
			"allowips": ["10.0.0.0/8"],
		},
	}`

	cfg, err := ParseRules([]byte(jsonBody))
	if err != nil {
		t.Fatalf("ParseRules json: %v", err)
	}
	grant, ok := cfg["example.internal"]
	if !ok {
		t.Fatalf("keys = %v, want normalized example.internal", keys(cfg))
	}
	id, explicit := grant.ExplicitTranslateID()
	if !explicit || id != 1 {
		t.Fatalf("translateid = %d explicit=%v, want 1", id, explicit)
	}
	if len(grant.DNS) != 1 || grant.DNS[0] != "10.0.0.53:53" {
		t.Fatalf("dns = %v", grant.DNS)
	}
	if len(grant.AllowIPs) != 1 || grant.AllowIPs[0] != "10.0.0.0/8" {
		t.Fatalf("allowips = %v", grant.AllowIPs)
	}
	if len(grant.DenyIPs) != 1 || grant.DenyIPs[0] != "10.1.0.0/24" {
		t.Fatalf("denyips = %v", grant.DenyIPs)
	}
	names, ok := cfg["site-a.example"]
	if !ok || names.IPNames == nil {
		t.Fatal("missing ipnames rule")
	}
	siteID, err := names.IPNames.SiteIDValue()
	if err != nil || siteID != 1 {
		t.Fatalf("siteid = %d err=%v", siteID, err)
	}

	huj, err := ParseRules([]byte(hujsonBody))
	if err != nil {
		t.Fatalf("ParseRules hujson: %v", err)
	}
	id, explicit = huj["example.internal"].ExplicitTranslateID()
	if !explicit || id != 1 {
		t.Fatalf("hujson translateid = %d explicit=%v", id, explicit)
	}
	if _, ok := huj["Example.Internal."]; ok {
		t.Fatal("hujson key was not normalized")
	}
}

func TestParseRulesRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "syntax", body: `{`, want: "parse rules"},
		{name: "empty", body: ``, want: "empty"},
		{name: "whitespace", body: " \n\t", want: "empty"},
		{name: "null", body: `null`, want: "object"},
		{name: "array", body: `[{"example.internal":{"dns":["10.0.0.53:53"]}}]`, want: "parse rules"},
		{name: "empty grant", body: `{"example.internal":{}}`, want: "empty grant"},
		{name: "translateid range", body: `{"example.internal":{"dns":["10.0.0.53:53"],"translateid":65536}}`, want: "translateid"},
		{name: "bad allowips", body: `{"example.internal":{"dns":["10.0.0.53:53"],"allowips":["nope"]}}`, want: "nope"},
		{name: "bad cidr key", body: `{"10.0.0.0/99":{"translateid":1}}`, want: "CIDR"},
		{name: "ipnames and translateid", body: `{"example.internal":{"translateid":1,"ipnames":{"siteid":1}}}`, want: "translateid"},
		{name: "missing siteid", body: `{"example.internal":{"ipnames":{}}}`, want: "siteid"},
		{
			name: "duplicate",
			body: `{
				"Example.Internal": {"dns": ["10.0.0.1:53"]},
				"example.internal.": {"dns": ["10.0.0.2:53"]}
			}`,
			want: "duplicate",
		},
		{
			name: "nested ipnames",
			body: `{
				"example.internal": {"ipnames": {"siteid": 1}},
				"a.example.internal": {"ipnames": {"siteid": 2}}
			}`,
			want: "nested ipnames",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRules([]byte(tt.body))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

func TestOpenRulesFileMissingAndInvalid(t *testing.T) {
	_, err := OpenRulesFile(filepath.Join(t.TempDir(), "missing.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file err = %v, want not exist", err)
	}

	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(`{"example.internal":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = OpenRulesFile(path)
	if err == nil {
		t.Fatal("expected invalid file error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error %q does not name %s", err, path)
	}
}

func TestApplyRulesGrantWinsPerDomain(t *testing.T) {
	file, err := ParseRules([]byte(`{
		"example.internal": {"dns": ["10.0.0.53:53"], "translateid": 1},
		"app.example.internal": {"dns": ["10.0.0.53:53"], "translateid": 4},
		"other.internal": {"dns": ["10.0.0.54:53"], "translateid": 2},
		"10.9.0.0/16": {"translateid": 1}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	acl, err := NewParser().ParseGrants(tailcfg.PeerCapMap{
		"rajsingh.info/cap/tsdnsproxy": {
			`{"Example.Internal":{"dns":["10.9.9.9:53"],"translateid":9},"10.9.0.0/16":{"translateid":8}}`,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	merged := ApplyRules(file, acl, false)
	p := NewParser()

	if _, grant, ok := p.FindBestMatch("svc.example.internal", merged); !ok || translateOf(t, grant) != 9 {
		t.Fatalf("same domain = %+v, want grant translateid 9", grant)
	}
	if _, grant, ok := p.FindBestMatch("app.example.internal", merged); !ok || translateOf(t, grant) != 4 {
		t.Fatalf("more specific file rule = %+v, want translateid 4", grant)
	}
	if _, grant, ok := p.FindBestMatch("host.other.internal", merged); !ok || translateOf(t, grant) != 2 {
		t.Fatalf("file-only domain = %+v, want translateid 2", grant)
	}
	if _, grant, ok := p.MatchPrefix(netip.MustParseAddr("10.9.1.1"), merged); !ok || translateOf(t, grant) != 8 {
		t.Fatalf("cidr override = %+v, want translateid 8", grant)
	}

	only := ApplyRules(file, acl, true)
	if _, grant, ok := p.FindBestMatch("svc.example.internal", only); !ok || translateOf(t, grant) != 1 {
		t.Fatalf("rules-only = %+v, want file translateid 1", grant)
	}
	if _, _, ok := p.FindBestMatch("host.other.internal", only); !ok {
		t.Fatal("rules-only dropped a file rule")
	}
}

func TestRulesFileReloadKeepsLastGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	writeRules(t, path, rulesJSON(1))
	rf, err := OpenRulesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if rf.Path() != path {
		t.Fatalf("path = %s", rf.Path())
	}

	changed, err := rf.Reload()
	if err != nil || changed {
		t.Fatalf("unchanged reload changed=%v err=%v", changed, err)
	}

	writeRules(t, path, `{`)
	if _, err := rf.Reload(); err == nil {
		t.Fatal("expected reload error")
	}
	if id := currentTranslateID(t, rf); id != 1 {
		t.Fatalf("translateid after bad reload = %d, want 1", id)
	}

	writeRules(t, path, rulesJSON(3))
	changed, err = rf.Reload()
	if err != nil || !changed {
		t.Fatalf("reload changed=%v err=%v", changed, err)
	}
	if id := currentTranslateID(t, rf); id != 3 {
		t.Fatalf("translateid = %d, want 3", id)
	}
}

func TestRulesFileWatchReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	writeRules(t, path, rulesJSON(1))
	rf, err := OpenRulesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rf.Watch(ctx, 10*time.Millisecond)

	writeRules(t, path, rulesJSON(3))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		cfg, ok := rf.Current()
		if ok {
			if id, explicit := cfg["example.internal"].ExplicitTranslateID(); explicit && id == 3 {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("rules were not reloaded")
}

func TestRulesFileConcurrentReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	writeRules(t, path, rulesJSON(1))
	rf, err := OpenRulesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rf.Watch(ctx, 5*time.Millisecond)
	}()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				cfg, ok := rf.Current()
				if !ok || len(cfg) != 1 {
					t.Errorf("cfg len=%d ok=%v", len(cfg), ok)
					return
				}
				id, explicit := cfg["example.internal"].ExplicitTranslateID()
				if !explicit || id < 1 {
					t.Errorf("translateid = %d explicit=%v", id, explicit)
					return
				}
			}
		}()
	}
	for id := 2; id <= 5; id++ {
		writeRules(t, path, rulesJSON(id))
		time.Sleep(15 * time.Millisecond)
	}
	cancel()
	wg.Wait()
}

func rulesJSON(id int) string {
	return fmt.Sprintf(`{"example.internal":{"dns":["10.0.0.53:53"],"translateid":%d,"allowips":["10.0.0.0/8"]}}`, id)
}

func writeRules(t *testing.T, path, body string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestCurrentReturnsACopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	body := `{"example.internal":{"dns":["10.0.0.53:53"],"translateid":1,"allowips":["10.0.0.0/8"]}}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	rf, err := OpenRulesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := rf.Current()
	if !ok {
		t.Fatal("missing rules")
	}
	got["example.internal"] = DNSGrant{DNS: []string{"10.9.9.9:53"}}
	again, _ := rf.Current()
	if again["example.internal"].DNS[0] != "10.0.0.53:53" {
		t.Fatalf("stored rules changed: %+v", again["example.internal"])
	}
}

func currentTranslateID(t *testing.T, rf *RulesFile) int {
	t.Helper()
	cfg, ok := rf.Current()
	if !ok {
		t.Fatal("rules not loaded")
	}
	id, explicit := cfg["example.internal"].ExplicitTranslateID()
	if !explicit {
		t.Fatal("translateid missing")
	}
	return id
}

func translateOf(t *testing.T, grant DNSGrant) int {
	t.Helper()
	id, ok := grant.ExplicitTranslateID()
	if !ok {
		t.Fatal("translateid missing")
	}
	return id
}

func keys(cfg GrantConfig) []string {
	out := make([]string, 0, len(cfg))
	for k := range cfg {
		out = append(out, k)
	}
	return out
}
