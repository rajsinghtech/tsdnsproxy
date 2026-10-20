package config

import (
	"strings"
	"testing"
	"time"
)

func TestParseDefaults(t *testing.T) {
	cfg, err := Parse(nil, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "tsdnsproxy" || cfg.Dial != "tailnet" || cfg.LogLevel != "info" {
		t.Fatalf("%+v", cfg)
	}
	if cfg.CacheTTL != 5*time.Minute || cfg.MaxInflight != 100 || cfg.MaxUDPBytes != 1232 {
		t.Fatalf("defaults %+v", cfg)
	}
	if cfg.HTTPAddr != ":8080" || cfg.RateLimit != 0 || cfg.DialSet {
		t.Fatalf("%+v", cfg)
	}
	if !cfg.DNSCache || cfg.AnswerCacheSize != 4096 || cfg.AnswerMinTTL != 5*time.Second || cfg.AnswerMaxTTL != time.Hour {
		t.Fatalf("answer cache defaults %+v", cfg)
	}
	if cfg.UIAddr != ":80" || cfg.UIHistory != 1000 || cfg.UICap != "" || cfg.UIAuditCap != "" {
		t.Fatalf("ui defaults %+v", cfg)
	}
	if cfg.UIUserHeader != "Tailscale-User-Login" || cfg.UINameHeader != "Tailscale-User-Name" || cfg.UIGroupsHeader != "X-Tailscale-Groups" {
		t.Fatalf("header defaults %+v", cfg)
	}
	if cfg.UITrustedProxyTags != nil || cfg.UIGroups != nil || cfg.UIAuditGroups != nil {
		t.Fatalf("proxy defaults %+v", cfg)
	}
}

func TestParseEnvAndFlags(t *testing.T) {
	env := map[string]string{
		"TS_AUTHKEY":            "tskey-auth-example",
		"TSDNSPROXY_LOG_LEVEL":  "debug",
		"TSDNSPROXY_CACHE_TTL":  "1m",
		"TSDNSPROXY_RATE_LIMIT": "10",
		"TSDNSPROXY_DIAL":       "direct",
	}
	cfg, err := Parse([]string{"-hostname", "dns", "-dial", "tailnet", "-max-inflight", "8"}, func(k string) string {
		return env[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthKey != "tskey-auth-example" || cfg.Hostname != "dns" || cfg.Dial != "tailnet" || !cfg.DialSet {
		t.Fatalf("%+v", cfg)
	}
	if cfg.LogLevel != "debug" || cfg.CacheTTL != time.Minute || cfg.RateLimit != 10 || cfg.MaxInflight != 8 {
		t.Fatalf("%+v", cfg)
	}
}

func TestParseRejectsBadValues(t *testing.T) {
	cases := [][]string{
		{"-cache-ttl", "0"},
		{"-query-timeout", "-1s"},
		{"-max-inflight", "0"},
		{"-max-message-bytes", "11"},
		{"-max-udp-bytes", "100"},
		{"-rate-limit", "-1"},
		{"-rate-burst", "0"},
		{"-log-level", "loud"},
		{"-http-addr", "not an address"},
		{"-rules-only"},
		{"-cache-size", "-1"},
		{"-cache-min-ttl", "-1s"},
		{"-cache-max-ttl", "0"},
		{"-cache-min-ttl", "2h", "-cache-max-ttl", "1h"},
		{"-ui-history", "-1"},
		{"-ui-addr", "not an address"},
		{"-ui-user-header", ""},
		{"-ui-user-header", "Bad Header"},
		{"-ui-groups", "dns admins"},
		{"-ui-trusted-proxy-tags", "tag proxy"},
	}
	for _, args := range cases {
		if _, err := Parse(args, nil); err == nil {
			t.Fatalf("args %s was accepted", strings.Join(args, " "))
		}
	}
}

func TestParseDNSCacheDisabled(t *testing.T) {
	cfg, err := Parse(nil, func(k string) string {
		if k == "TSDNSPROXY_DNS_CACHE" {
			return "false"
		}
		if k == "TSDNSPROXY_CACHE_SIZE" {
			return "0"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNSCache || cfg.AnswerCacheSize != 0 {
		t.Fatalf("%+v", cfg)
	}
	off, err := Parse([]string{"-dns-cache=false", "-cache-size", "10"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if off.DNSCache || off.AnswerCacheSize != 10 {
		t.Fatalf("%+v", off)
	}
	uiOff, err := Parse([]string{"-ui-addr", "-"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if uiOff.UIAddr != "" {
		t.Fatalf("ui addr %q", uiOff.UIAddr)
	}
}

func TestParseUIProxyFlags(t *testing.T) {
	cfg, err := Parse(nil, func(k string) string {
		switch k {
		case "TSDNSPROXY_UI_TRUSTED_PROXY_TAGS":
			return "tag:proxy, tag:proxy"
		case "TSDNSPROXY_UI_GROUPS":
			return "dns-admins, dns-readers"
		case "TSDNSPROXY_UI_AUDIT_GROUPS":
			return "dns-auditors"
		case "TSDNSPROXY_UI_USER_HEADER":
			return "X-User"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.UITrustedProxyTags, ",") != "tag:proxy" {
		t.Fatalf("tags %v", cfg.UITrustedProxyTags)
	}
	if strings.Join(cfg.UIGroups, ",") != "dns-admins,dns-readers" || strings.Join(cfg.UIAuditGroups, ",") != "dns-auditors" {
		t.Fatalf("groups %+v", cfg)
	}
	if cfg.UIUserHeader != "X-User" || cfg.UINameHeader != "Tailscale-User-Name" {
		t.Fatalf("headers %+v", cfg)
	}
	flagged, err := Parse([]string{"-ui-groups", "dns-admins", "-ui-trusted-proxy-tags", "tag:edge"}, func(k string) string {
		if k == "TSDNSPROXY_UI_GROUPS" {
			return "dns-readers"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(flagged.UIGroups, ",") != "dns-admins" || strings.Join(flagged.UITrustedProxyTags, ",") != "tag:edge" {
		t.Fatalf("flags did not override env: %+v", flagged)
	}
}

func TestParseLogLevel(t *testing.T) {
	if _, err := ParseLogLevel("warn"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseLogLevel("nope"); err == nil {
		t.Fatal("expected error")
	}
}
