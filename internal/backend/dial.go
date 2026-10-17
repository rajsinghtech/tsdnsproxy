package backend

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
)

// DialMode selects how a backend address is dialed.
// Direct uses the host network. Tailnet uses the tsnet dialer.
type DialMode string

const (
	// DialDirect dials through the host network.
	DialDirect DialMode = "direct"
	// DialTailnet dials through the tailnet, including subnet routes.
	DialTailnet DialMode = "tailnet"
)

// Endpoint is one upstream DNS server and the network used to reach it.
// Explicit is true when the address named its mode with direct:// or tailnet://.
type Endpoint struct {
	Addr     string
	Mode     DialMode
	Explicit bool
}

// Dialers holds the host and tailnet dialers plus the mode for a bare address.
// TailnetRoutes is used only for an explicit tailnet:// address, so a bare
// address under a tailnet default does not turn on subnet routes.
type Dialers struct {
	Direct        DNSDialer
	Tailnet       DNSDialer
	TailnetRoutes DNSDialer
	Default       DialMode
}

// ParseDialMode accepts direct or tailnet. An empty string is direct.
func ParseDialMode(raw string) (DialMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(DialDirect):
		return DialDirect, nil
	case string(DialTailnet):
		return DialTailnet, nil
	default:
		return "", fmt.Errorf("dial mode %q is not direct or tailnet", raw)
	}
}

// ParseEndpoint reads one backend address.
// tailnet:// and direct:// select the mode. A bare address uses def.
// A missing port becomes 53.
func ParseEndpoint(raw string, def DialMode) (Endpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Endpoint{}, fmt.Errorf("empty backend address")
	}
	if def == "" {
		def = DialDirect
	}
	mode := def
	explicit := false
	addr := raw
	if scheme, rest, ok := strings.Cut(raw, "://"); ok {
		switch strings.ToLower(scheme) {
		case string(DialTailnet):
			mode = DialTailnet
		case string(DialDirect):
			mode = DialDirect
		default:
			return Endpoint{}, fmt.Errorf("unknown backend scheme %q", scheme)
		}
		explicit = true
		addr = strings.TrimSpace(rest)
		if addr == "" || strings.Contains(addr, "://") {
			return Endpoint{}, fmt.Errorf("invalid backend address %q", raw)
		}
	}
	normalized, err := normalizeAddr(addr)
	if err != nil {
		return Endpoint{}, fmt.Errorf("backend %q: %w", raw, err)
	}
	return Endpoint{Addr: normalized, Mode: mode, Explicit: explicit}, nil
}

// ExplicitTailnet reports whether any address uses the tailnet:// scheme.
// A bare address does not count, even when the default dial mode is tailnet.
func ExplicitTailnet(servers []string) (bool, error) {
	for _, raw := range servers {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		ep, err := ParseEndpoint(raw, DialDirect)
		if err != nil {
			return false, err
		}
		if ep.Explicit && ep.Mode == DialTailnet {
			return true, nil
		}
	}
	return false, nil
}

func normalizeAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		addr = net.JoinHostPort(addr, "53")
		host, port, err = net.SplitHostPort(addr)
		if err != nil {
			return "", err
		}
	}
	if host == "" || port == "" {
		return "", fmt.Errorf("missing host or port")
	}
	return net.JoinHostPort(host, port), nil
}

// HostDialer dials through the host network.
func HostDialer() DNSDialer {
	return netDialer{}
}

// NewEnsuringDialer runs ensure before the first successful dial.
// Later dials skip ensure. A failed ensure is tried again on the next dial.
func NewEnsuringDialer(inner DNSDialer, ensure func(context.Context) error) DNSDialer {
	return &ensureDialer{inner: inner, ensure: ensure}
}

type ensureDialer struct {
	inner  DNSDialer
	ensure func(context.Context) error
	mu     sync.Mutex
	ready  bool
}

func (d *ensureDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if err := d.prepare(ctx); err != nil {
		return nil, err
	}
	if d.inner == nil {
		return nil, fmt.Errorf("tailnet dialer is not configured")
	}
	return d.inner.Dial(ctx, network, address)
}

func (d *ensureDialer) prepare(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ready {
		return nil
	}
	if d.ensure != nil {
		if err := d.ensure(ctx); err != nil {
			return err
		}
	}
	d.ready = true
	return nil
}
