package dns

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestValidateQueryName(t *testing.T) {
	ok := []string{".", "example.internal.", "app.example.internal.", "_srv.example.internal.", "*.example.internal.", "ip."}
	for _, name := range ok {
		n, err := dnsmessage.NewName(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateQueryName(n); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	n, err := dnsmessage.NewName("bad/label.example.")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateQueryName(n); err == nil {
		t.Fatal("accepted a slash in a label")
	}
}

func TestSourceLimiter(t *testing.T) {
	if !newSourceLimiter(0, 1).allow("192.0.2.1:1") {
		t.Fatal("disabled limiter refused")
	}
	lim := newSourceLimiter(1, 1)
	if !lim.allow("192.0.2.1:53") {
		t.Fatal("first query refused")
	}
	if lim.allow("192.0.2.1:54") {
		t.Fatal("burst exceeded")
	}
	if !lim.allow("192.0.2.2:53") {
		t.Fatal("other client refused")
	}
}
