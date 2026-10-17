package grants

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// DefaultCapName is the capability read when -cap-name and
// TSDNSPROXY_CAP_NAME are unset.
const DefaultCapName = "rajsingh.info/cap/tsdnsproxy"

// ValidateCapName reports whether name is a non-empty capability of the
// form domain/path, for example example.com/cap/dns. An optional http or
// https scheme is allowed. Surrounding whitespace is rejected.
func ValidateCapName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("capability name is empty")
	}
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("capability name %q must not have surrounding whitespace", name)
	}
	if !plausibleCapName(name) {
		return fmt.Errorf("capability name %q must look like a domain and path, for example example.com/cap/dns", name)
	}
	return nil
}

func plausibleCapName(name string) bool {
	rest, ok := capNameWithoutScheme(name)
	if !ok || rest == "" {
		return false
	}
	host, path, found := strings.Cut(rest, "/")
	if !found || host == "" || path == "" {
		return false
	}
	if !plausibleCapHost(host) {
		return false
	}
	return plausibleCapPath(path)
}

func capNameWithoutScheme(name string) (string, bool) {
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, "https://"):
		return name[len("https://"):], true
	case strings.HasPrefix(lower, "http://"):
		return name[len("http://"):], true
	case strings.Contains(name, "://"):
		return "", false
	default:
		return name, true
	}
}

func plausibleCapHost(hostport string) bool {
	host := hostport
	if strings.Contains(hostport, ":") {
		h, port, err := net.SplitHostPort(hostport)
		if err != nil {
			return false
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
		host = h
	}
	if host == "" {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsValid() {
		return false
	}
	return plausibleDomain(host)
}

func plausibleDomain(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.Contains(host, "..") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !plausibleLabel(label) {
			return false
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	for _, r := range tld {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

func plausibleLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return true
}

func plausibleCapPath(path string) bool {
	if path == "" || strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
		return false
	}
	if strings.ContainsAny(path, "?#\\ @") {
		return false
	}
	for _, seg := range strings.Split(path, "/") {
		if !plausiblePathSegment(seg) {
			return false
		}
	}
	return true
}

func plausiblePathSegment(seg string) bool {
	if seg == "" || seg == "." || seg == ".." || len(seg) > 255 {
		return false
	}
	alnum := false
	for _, r := range seg {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			alnum = true
		case r == '.' || r == '_' || r == '~' || r == '+' || r == '-':
		default:
			return false
		}
	}
	return alnum
}
