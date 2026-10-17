package grants

import (
	"strings"
	"testing"

	"tailscale.com/tailcfg"
)

func TestDefaultCapNameUnchanged(t *testing.T) {
	const want = "rajsingh.info/cap/tsdnsproxy"
	if DefaultCapName != want {
		t.Fatalf("DefaultCapName = %q, want %q", DefaultCapName, want)
	}
	if err := ValidateCapName(DefaultCapName); err != nil {
		t.Fatalf("default capability name is invalid: %v", err)
	}

	p := NewParser()
	if p.CapName() != want {
		t.Fatalf("NewParser cap = %q, want %q", p.CapName(), want)
	}

	var zero Parser
	if zero.CapName() != want {
		t.Fatalf("zero parser cap = %q, want %q", zero.CapName(), want)
	}

	got, err := p.ParseGrants(tailcfg.PeerCapMap{
		want:                  {`{"cluster.local":{"dns":["10.0.0.1:53"]}}`},
		"example.com/cap/dns": {`{"other.example":{"dns":["10.2.0.1:53"]}}`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("parsed %d grants, want 1", len(got))
	}
	if _, ok := got[0]["cluster.local"]; !ok {
		t.Fatalf("default parser grants = %#v", got)
	}
	if _, ok := got[0]["other.example"]; ok {
		t.Fatal("default parser read a different capability")
	}
}

func TestCustomCapNameParsesGrants(t *testing.T) {
	const custom = "example.com/cap/dns"
	p, err := NewParserWithName("  " + custom + "  ")
	if err != nil {
		t.Fatal(err)
	}
	if p.CapName() != custom {
		t.Fatalf("cap = %q, want %q", p.CapName(), custom)
	}

	got, err := p.ParseGrants(tailcfg.PeerCapMap{
		custom: {`{"custom.example":{"dns":["10.9.0.1:53"],"rewrite":"internal.example"}}`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("parsed %d grants, want 1", len(got))
	}
	grant, ok := got[0]["custom.example"]
	if !ok {
		t.Fatalf("grants = %#v", got)
	}
	if grant.Rewrite != "internal.example" || len(grant.DNS) != 1 || grant.DNS[0] != "10.9.0.1:53" {
		t.Fatalf("grant = %#v", grant)
	}
}

func TestCustomCapNameIgnoresDefault(t *testing.T) {
	const custom = "example.com/cap/dns"
	p, err := NewParserWithName(custom)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("old name only", func(t *testing.T) {
		got, err := p.ParseGrants(tailcfg.PeerCapMap{
			DefaultCapName: {`{"old.example":{"dns":["10.0.0.1:53"]}}`},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("parsed %d grants, want none", len(got))
		}
	})

	t.Run("old and custom", func(t *testing.T) {
		got, err := p.ParseGrants(tailcfg.PeerCapMap{
			DefaultCapName: {`{"old.example":{"dns":["10.0.0.1:53"]}}`},
			custom:         {`{"custom.example":{"dns":["10.9.0.1:53"]}}`},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("parsed %d grants, want 1", len(got))
		}
		if _, ok := got[0]["custom.example"]; !ok {
			t.Fatalf("grants = %#v", got)
		}
		if _, ok := got[0]["old.example"]; ok {
			t.Fatal("custom parser read the default capability")
		}
	})
}

func TestValidateCapName(t *testing.T) {
	valid := []string{
		DefaultCapName,
		"example.com/cap/dns",
		"example.com/cap/dns/extra",
		"sub.example.com/cap/dns",
		"Example.COM/cap/DNS",
		"https://example.com/cap/dns",
		"http://example.com/cap/dns",
		"HTTPS://example.com/cap/dns",
		"example.com:8443/cap/dns",
		"https://example.com:443/cap/dns",
	}
	invalid := []string{
		"",
		" ",
		"  example.com/cap/dns",
		"example.com/cap/dns  ",
		"example.com",
		"example.com/",
		"/cap/dns",
		"not-a-cap",
		"example/cap/dns",
		"example.com/cap/dns extra",
		"example.com/cap//dns",
		"example.com/cap/dns?x=1",
		"https://",
		"ftp://example.com/cap/dns",
		"10.0.0.1/cap/dns",
		"example.com:99999/cap/dns",
		"-example.com/cap/dns",
		"example-.com/cap/dns",
	}

	for _, name := range valid {
		t.Run("valid "+name, func(t *testing.T) {
			if err := ValidateCapName(name); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, name := range invalid {
		t.Run("invalid "+strconvQuote(name), func(t *testing.T) {
			err := ValidateCapName(name)
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.TrimSpace(name) == "" && !strings.Contains(err.Error(), "empty") {
				t.Fatalf("error = %v, want empty", err)
			}
		})
	}

	if _, err := NewParserWithName(""); err == nil {
		t.Fatal("empty name accepted")
	}
	if _, err := NewParserWithName("not-a-cap"); err == nil {
		t.Fatal("implausible name accepted")
	}
}

func strconvQuote(s string) string {
	if s == "" {
		return "empty"
	}
	return strings.ReplaceAll(s, " ", "_")
}
