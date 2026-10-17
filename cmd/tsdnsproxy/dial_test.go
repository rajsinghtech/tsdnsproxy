package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rajsinghtech/tsdnsproxy/internal/backend"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
)

func TestNeedsTailnetRoutes(t *testing.T) {
	yes, err := needsTailnetRoutes(true, false, []string{"10.0.0.53:53"}, nil)
	if err != nil || !yes {
		t.Fatalf("accept-routes = %v %v", yes, err)
	}
	yes, err = needsTailnetRoutes(false, true, []string{"10.0.0.53:53"}, nil)
	if err != nil || !yes {
		t.Fatalf("explicit dial tailnet = %v %v", yes, err)
	}
	no, err := needsTailnetRoutes(false, false, []string{"10.0.0.53:53", "direct://10.0.0.54:53"}, nil)
	if err != nil || no {
		t.Fatalf("bare default = %v %v", no, err)
	}
	yes, err = needsTailnetRoutes(false, false, []string{"10.0.0.53:53", "tailnet://10.0.0.53:53"}, nil)
	if err != nil || !yes {
		t.Fatalf("prefix = %v %v", yes, err)
	}

	path := filepath.Join(t.TempDir(), "rules.json")
	body := `{
	  "example.internal": {
	    "dns": ["tailnet://10.0.0.53:53"],
	    "translateid": 1
	  }
	}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, err := grants.OpenRulesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	yes, err = needsTailnetRoutes(false, false, []string{"10.0.0.53:53"}, rules)
	if err != nil || !yes {
		t.Fatalf("rules file = %v %v", yes, err)
	}

	barePath := filepath.Join(t.TempDir(), "bare.json")
	bareBody := `{
	  "example.internal": {
	    "dns": ["10.0.0.53:53"],
	    "translateid": 1
	  }
	}`
	if err := os.WriteFile(barePath, []byte(bareBody), 0o644); err != nil {
		t.Fatal(err)
	}
	bareRules, err := grants.OpenRulesFile(barePath)
	if err != nil {
		t.Fatal(err)
	}
	no, err = needsTailnetRoutes(false, false, []string{"10.0.0.53:53"}, bareRules)
	if err != nil || no {
		t.Fatalf("bare rules = %v %v", no, err)
	}
	if _, err := needsTailnetRoutes(false, false, []string{"ftp://10.0.0.53:53"}, nil); err == nil {
		t.Fatal("expected bad scheme error")
	}
}

func TestExplicitDialTailnet(t *testing.T) {
	orig, had := os.LookupEnv("TSDNSPROXY_DIAL")
	t.Cleanup(func() {
		var err error
		if had {
			err = os.Setenv("TSDNSPROXY_DIAL", orig)
		} else {
			err = os.Unsetenv("TSDNSPROXY_DIAL")
		}
		if err != nil {
			t.Errorf("restore TSDNSPROXY_DIAL: %v", err)
		}
	})

	if err := os.Unsetenv("TSDNSPROXY_DIAL"); err != nil {
		t.Fatal(err)
	}
	if explicitDialTailnet(backend.DialTailnet) {
		t.Fatal("the built-in tailnet default should not count as explicit")
	}
	if err := os.Setenv("TSDNSPROXY_DIAL", "tailnet"); err != nil {
		t.Fatal(err)
	}
	if !explicitDialTailnet(backend.DialTailnet) {
		t.Fatal("env tailnet should be explicit")
	}
	if err := os.Setenv("TSDNSPROXY_DIAL", "direct"); err != nil {
		t.Fatal(err)
	}
	if explicitDialTailnet(backend.DialDirect) {
		t.Fatal("direct dial should not request tailnet routes")
	}
}
