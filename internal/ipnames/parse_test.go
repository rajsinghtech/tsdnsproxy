package ipnames

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseDashedIPv4(t *testing.T) {
	tests := []struct {
		name    string
		label   string
		want    string
		wantErr bool
	}{
		{name: "simple", label: "10-0-0-1", want: "10.0.0.1"},
		{name: "zeros", label: "0-0-0-0", want: "0.0.0.0"},
		{name: "max", label: "255-255-255-255", want: "255.255.255.255"},
		{name: "shared range", label: "100-64-1-5", want: "100.64.1.5"},
		{name: "octet too big", label: "256-0-0-1", wantErr: true},
		{name: "leading zero", label: "010-0-0-1", wantErr: true},
		{name: "all leading zeros", label: "00-0-0-1", wantErr: true},
		{name: "three parts", label: "10-0-1", wantErr: true},
		{name: "five parts", label: "10-0-0-1-2", wantErr: true},
		{name: "empty part", label: "10--0-1", wantErr: true},
		{name: "leading dash", label: "-10-0-0-1", wantErr: true},
		{name: "trailing dash", label: "10-0-0-1-", wantErr: true},
		{name: "letters", label: "10-0-0-a", wantErr: true},
		{name: "hex", label: "a-0-0-1", wantErr: true},
		{name: "double dash compression", label: "10--1", wantErr: true},
		{name: "empty", label: "", wantErr: true},
		{name: "spaces", label: "10-0-0- 1", wantErr: true},
		{name: "plus", label: "+10-0-0-1", wantErr: true},
		{name: "fullwidth digits", label: "１０-0-0-1", wantErr: true},
		{name: "uppercase hex", label: "A-0-0-1", wantErr: true},
		{name: "dotted", label: "10.0.0.1", wantErr: true},
		{name: "ipv6 dashes", label: "2001-db8--1", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDashedIPv4(tc.label)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) = %v, want error", tc.label, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.label, err)
			}
			if got.String() != tc.want {
				t.Fatalf("Parse(%q) = %s, want %s", tc.label, got, tc.want)
			}
			formatted, err := FormatDashedIPv4(got)
			if err != nil || formatted != tc.label {
				t.Fatalf("format = %q, %v", formatted, err)
			}
		})
	}
}

func TestParseRejectsLongLabel(t *testing.T) {
	label := strings.Repeat("1-", 32) + "1" // longer than 63
	if len(label) <= 63 {
		t.Fatalf("fixture length %d", len(label))
	}
	if _, err := ParseDashedIPv4(label); err == nil {
		t.Fatal("expected error")
	}
	// 63 characters that are not four octets
	exact := strings.Repeat("1", 63)
	if len(exact) != 63 {
		t.Fatal(len(exact))
	}
	if _, err := ParseDashedIPv4(exact); err == nil {
		t.Fatal("expected error for max-length non-address")
	}
}

func TestFormatRejectsIPv6(t *testing.T) {
	if _, err := FormatDashedIPv4(netip.MustParseAddr("2001:db8::1")); err == nil {
		t.Fatal("expected error")
	}
}

func FuzzParseDashedIPv4(f *testing.F) {
	f.Add("10-0-0-1")
	f.Add("0-0-0-0")
	f.Add("255-255-255-255")
	f.Add("010-0-0-1")
	f.Add("10--0-1")
	f.Add("")
	f.Fuzz(func(t *testing.T, label string) {
		ip, err := ParseDashedIPv4(label)
		if err != nil {
			return
		}
		formatted, err := FormatDashedIPv4(ip)
		if err != nil {
			t.Fatalf("format %v: %v", ip, err)
		}
		if formatted != label {
			t.Fatalf("canonical form %q != input %q", formatted, label)
		}
		again, err := ParseDashedIPv4(formatted)
		if err != nil || again != ip {
			t.Fatalf("round trip %q -> %v -> %v (%v)", label, ip, again, err)
		}
		dotted := strings.ReplaceAll(formatted, "-", ".")
		parsed, err := netip.ParseAddr(dotted)
		if err != nil || parsed != ip {
			t.Fatalf("netip %q = %v, %v; want %v", dotted, parsed, err, ip)
		}
	})
}
