// Package ipnames parses IPv4 addresses encoded as a single DNS label.
package ipnames

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"
)

const maxLabelLen = 63

// ErrLabel is returned when a label is not a strict dashed IPv4 address.
var ErrLabel = errors.New("invalid dashed ipv4 label")

// ParseDashedIPv4 parses a label of the form d-d-d-d.
// Each part is 1 to 3 ASCII digits, with no leading zero, and is at most 255.
// The result must agree with netip.ParseAddr on the dotted form.
func ParseDashedIPv4(label string) (netip.Addr, error) {
	if label == "" || len(label) > maxLabelLen || !utf8.ValidString(label) {
		return netip.Addr{}, ErrLabel
	}
	for i := 0; i < len(label); i++ {
		if label[i] > 127 {
			return netip.Addr{}, ErrLabel
		}
	}
	parts := strings.Split(label, "-")
	if len(parts) != 4 {
		return netip.Addr{}, ErrLabel
	}
	var octets [4]byte
	dotted := make([]byte, 0, 15)
	for i, part := range parts {
		if part == "" || len(part) > 3 {
			return netip.Addr{}, ErrLabel
		}
		if len(part) > 1 && part[0] == '0' {
			return netip.Addr{}, ErrLabel
		}
		n := 0
		for j := 0; j < len(part); j++ {
			c := part[j]
			if c < '0' || c > '9' {
				return netip.Addr{}, ErrLabel
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return netip.Addr{}, ErrLabel
		}
		octets[i] = byte(n)
		if i > 0 {
			dotted = append(dotted, '.')
		}
		dotted = append(dotted, part...)
	}
	ip, err := netip.ParseAddr(string(dotted))
	if err != nil || !ip.Is4() || ip.As4() != octets {
		return netip.Addr{}, fmt.Errorf("%w", ErrLabel)
	}
	return ip, nil
}

// FormatDashedIPv4 renders ip as d-d-d-d with no leading zeros.
func FormatDashedIPv4(ip netip.Addr) (string, error) {
	if !ip.Is4() {
		return "", ErrLabel
	}
	b := ip.As4()
	return fmt.Sprintf("%d-%d-%d-%d", b[0], b[1], b[2], b[3]), nil
}
