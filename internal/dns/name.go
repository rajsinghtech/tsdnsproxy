package dns

import (
	"fmt"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// validateQueryName rejects names that are not safe to log or forward.
// Labels may contain ASCII letters, digits, hyphen, and underscore.
// A single "*" label is allowed. The root name is allowed.
func validateQueryName(name dnsmessage.Name) error {
	s := name.String()
	if s == "." || s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, ".")
	if len(s) > 253 {
		return fmt.Errorf("name is %d bytes", len(s))
	}
	for _, label := range strings.Split(s, ".") {
		if err := validateLabel(label); err != nil {
			return fmt.Errorf("name %q: %w", name.String(), err)
		}
	}
	return nil
}

func validateLabel(label string) error {
	if label == "*" {
		return nil
	}
	if label == "" || len(label) > 63 {
		return fmt.Errorf("label %q has invalid length", label)
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return fmt.Errorf("label %q has invalid character", label)
		}
	}
	return nil
}
