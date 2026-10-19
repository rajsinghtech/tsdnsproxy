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

func TestParseLogLevel(t *testing.T) {
	if _, err := ParseLogLevel("warn"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseLogLevel("nope"); err == nil {
		t.Fatal("expected error")
	}
}
