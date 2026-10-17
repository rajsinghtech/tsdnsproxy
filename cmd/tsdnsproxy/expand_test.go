package main

import "testing"

func TestExpandEnvRefs(t *testing.T) {
	t.Setenv("POD_NAME", "tsdnsproxy-0")
	got := expandEnvRefs("kube:tsdnsproxy-state-$(POD_NAME)")
	if got != "kube:tsdnsproxy-state-tsdnsproxy-0" {
		t.Fatalf("paren = %q", got)
	}
	if got := expandEnvRefs("host-${POD_NAME}"); got != "host-tsdnsproxy-0" {
		t.Fatalf("brace = %q", got)
	}
	if got := expandEnvRefs("host-$POD_NAME"); got != "host-tsdnsproxy-0" {
		t.Fatalf("bare = %q", got)
	}
	if got := expandEnvRefs("kube:tsdnsproxy-state"); got != "kube:tsdnsproxy-state" {
		t.Fatalf("plain = %q", got)
	}
	if got := expandEnvRefs("$$(POD_NAME)"); got != "$(POD_NAME)" {
		t.Fatalf("escaped = %q", got)
	}
	if got := expandEnvRefs("kube:tsdnsproxy-state-$(MISSING)"); got != "kube:tsdnsproxy-state-$(MISSING)" {
		t.Fatalf("missing = %q", got)
	}
}
