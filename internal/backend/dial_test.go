package backend

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
)

func TestParseDialMode(t *testing.T) {
	direct, err := ParseDialMode("")
	if err != nil || direct != DialDirect {
		t.Fatalf("empty = %q %v", direct, err)
	}
	direct, err = ParseDialMode(" DIRECT ")
	if err != nil || direct != DialDirect {
		t.Fatalf("direct = %q %v", direct, err)
	}
	tailnet, err := ParseDialMode("tailnet")
	if err != nil || tailnet != DialTailnet {
		t.Fatalf("tailnet = %q %v", tailnet, err)
	}
	if _, err := ParseDialMode("udp"); err == nil {
		t.Fatal("expected error for udp")
	}
}

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		def     DialMode
		want    Endpoint
		wantErr string
	}{
		{
			name: "bare uses direct default and adds port",
			raw:  "10.0.0.53",
			def:  DialDirect,
			want: Endpoint{Addr: "10.0.0.53:53", Mode: DialDirect},
		},
		{
			name: "bare uses tailnet default",
			raw:  "10.0.0.53:53",
			def:  DialTailnet,
			want: Endpoint{Addr: "10.0.0.53:53", Mode: DialTailnet},
		},
		{
			name: "tailnet prefix overrides direct default",
			raw:  "tailnet://10.0.0.53:53",
			def:  DialDirect,
			want: Endpoint{Addr: "10.0.0.53:53", Mode: DialTailnet, Explicit: true},
		},
		{
			name: "tailnet prefix adds port",
			raw:  "Tailnet://10.0.0.53",
			def:  DialDirect,
			want: Endpoint{Addr: "10.0.0.53:53", Mode: DialTailnet, Explicit: true},
		},
		{
			name: "direct prefix overrides tailnet default",
			raw:  "direct://10.0.0.53:53",
			def:  DialTailnet,
			want: Endpoint{Addr: "10.0.0.53:53", Mode: DialDirect, Explicit: true},
		},
		{
			name: "ipv6 bare",
			raw:  "2001:db8::53",
			def:  DialDirect,
			want: Endpoint{Addr: "[2001:db8::53]:53", Mode: DialDirect},
		},
		{
			name: "ipv6 with port",
			raw:  "tailnet://[2001:db8::53]:53",
			def:  DialDirect,
			want: Endpoint{Addr: "[2001:db8::53]:53", Mode: DialTailnet, Explicit: true},
		},
		{name: "empty", raw: "  ", def: DialDirect, wantErr: "empty"},
		{name: "unknown scheme", raw: "ftp://10.0.0.53:53", def: DialDirect, wantErr: "scheme"},
		{name: "empty tailnet host", raw: "tailnet://", def: DialDirect, wantErr: "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEndpoint(tt.raw, tt.def)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestExplicitTailnet(t *testing.T) {
	no, err := ExplicitTailnet(nil)
	if err != nil || no {
		t.Fatalf("empty = %v %v", no, err)
	}
	no, err = ExplicitTailnet([]string{"10.0.0.53:53", "direct://10.0.0.53:53"})
	if err != nil || no {
		t.Fatalf("bare and direct = %v %v", no, err)
	}
	yes, err := ExplicitTailnet([]string{"10.0.0.53:53", "tailnet://10.0.0.53:53"})
	if err != nil || !yes {
		t.Fatalf("prefix = %v %v", yes, err)
	}
	if _, err := ExplicitTailnet([]string{"nope://10.0.0.53"}); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestDialSelectionUsesTCPAndUDP(t *testing.T) {
	direct := &recordDialer{}
	tailnet := &recordDialer{}
	m, err := NewManager(nil, Dialers{Direct: direct, Tailnet: tailnet, Default: DialDirect}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	backends, err := m.CreateBackends([]string{"10.0.0.53:53", "tailnet://10.0.0.53:53", "direct://10.0.0.54:53"})
	if err != nil {
		t.Fatal(err)
	}
	if len(backends) != 3 {
		t.Fatalf("backends = %d", len(backends))
	}
	if backends[0].String() != "10.0.0.53:53" {
		t.Fatalf("bare label = %s", backends[0].String())
	}
	if backends[1].String() != "tailnet://10.0.0.53:53" {
		t.Fatalf("tailnet label = %s", backends[1].String())
	}

	ctx := context.Background()
	if _, err := backends[0].Query(ctx, []byte{0}); err == nil {
		t.Fatal("expected dial error")
	}
	if _, err := backends[1].Query(ctx, []byte{0}); err == nil {
		t.Fatal("expected dial error")
	}
	if _, err := backends[2].Query(ctx, []byte{0}); err == nil {
		t.Fatal("expected dial error")
	}

	if got := direct.calls(); !sameCalls(got, []string{"tcp 10.0.0.53:53", "udp 10.0.0.53:53", "tcp 10.0.0.54:53", "udp 10.0.0.54:53"}) {
		t.Fatalf("direct calls = %v", got)
	}
	if got := tailnet.calls(); !sameCalls(got, []string{"tcp 10.0.0.53:53", "udp 10.0.0.53:53"}) {
		t.Fatalf("tailnet calls = %v", got)
	}
}

func TestDefaultTailnetDialSelection(t *testing.T) {
	direct := &recordDialer{}
	tailnet := &recordDialer{}
	m, err := NewManager([]string{"10.0.0.53"}, Dialers{Direct: direct, Tailnet: tailnet, Default: DialTailnet}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if len(m.defaultBackends) != 1 || m.defaultBackends[0].String() != "10.0.0.53:53" {
		t.Fatalf("default backend = %v", m.defaultBackends)
	}
	if _, err := m.Query(context.Background(), nil, []byte{0}); err == nil {
		t.Fatal("expected dial error")
	}
	if len(direct.calls()) != 0 {
		t.Fatalf("direct was used: %v", direct.calls())
	}
	if got := tailnet.calls(); !sameCalls(got, []string{"tcp 10.0.0.53:53", "udp 10.0.0.53:53"}) {
		t.Fatalf("tailnet calls = %v", got)
	}
}

func TestEnsuringDialerRetriesUntilReady(t *testing.T) {
	inner := &recordDialer{}
	var calls int
	d := NewEnsuringDialer(inner, func(context.Context) error {
		calls++
		if calls == 1 {
			return errors.New("routes down")
		}
		return nil
	})
	if _, err := d.Dial(context.Background(), "tcp", "10.0.0.53:53"); err == nil || !strings.Contains(err.Error(), "routes down") {
		t.Fatalf("first dial = %v", err)
	}
	if len(inner.calls()) != 0 {
		t.Fatalf("inner dialed before routes were ready: %v", inner.calls())
	}
	conn, err := d.Dial(context.Background(), "udp", "10.0.0.53:53")
	if err == nil || conn != nil {
		t.Fatal("inner dialer is configured to fail")
	}
	if calls != 2 {
		t.Fatalf("ensure calls = %d", calls)
	}
	if _, err := d.Dial(context.Background(), "tcp", "10.0.0.53:53"); err == nil {
		t.Fatal("expected inner failure")
	}
	if calls != 2 {
		t.Fatalf("ensure ran again after success: %d", calls)
	}
	if got := inner.calls(); !sameCalls(got, []string{"udp 10.0.0.53:53", "tcp 10.0.0.53:53"}) {
		t.Fatalf("inner calls = %v", got)
	}
}

func TestExplicitTailnetUsesRouteDialer(t *testing.T) {
	plain := &recordDialer{}
	routes := &recordDialer{}
	m, err := NewManager(nil, Dialers{
		Direct:        &recordDialer{},
		Tailnet:       plain,
		TailnetRoutes: routes,
		Default:       DialTailnet,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	backends, err := m.CreateBackends([]string{"10.0.0.53:53", "tailnet://10.0.0.53:53"})
	if err != nil {
		t.Fatal(err)
	}
	if backends[0].String() != "10.0.0.53:53" || backends[1].String() != "tailnet://10.0.0.53:53" {
		t.Fatalf("labels = %s %s", backends[0].String(), backends[1].String())
	}
	ctx := context.Background()
	if _, err := backends[0].Query(ctx, []byte{0}); err == nil {
		t.Fatal("expected dial error")
	}
	if _, err := backends[1].Query(ctx, []byte{0}); err == nil {
		t.Fatal("expected dial error")
	}
	if got := plain.calls(); !sameCalls(got, []string{"tcp 10.0.0.53:53", "udp 10.0.0.53:53"}) {
		t.Fatalf("plain tailnet calls = %v", got)
	}
	if got := routes.calls(); !sameCalls(got, []string{"tcp 10.0.0.53:53", "udp 10.0.0.53:53"}) {
		t.Fatalf("route dialer calls = %v", got)
	}
}

func TestCreateBackendsRejectsBadScheme(t *testing.T) {
	m, err := NewManager(nil, Dialers{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := m.CreateBackends([]string{"ftp://10.0.0.53:53"}); err == nil {
		t.Fatal("expected error")
	}
}

func FuzzParseEndpoint(f *testing.F) {
	f.Add("10.0.0.53:53")
	f.Add("tailnet://10.0.0.53")
	f.Add("direct://[2001:db8::53]:53")
	f.Add("")
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 256 {
			t.Skip()
		}
		for _, def := range []DialMode{DialDirect, DialTailnet} {
			ep, err := ParseEndpoint(raw, def)
			if err != nil {
				continue
			}
			if ep.Mode != DialDirect && ep.Mode != DialTailnet {
				t.Fatalf("mode %q", ep.Mode)
			}
			host, port, err := net.SplitHostPort(ep.Addr)
			if err != nil || host == "" || port == "" {
				t.Fatalf("addr %q: %v", ep.Addr, err)
			}
		}
	})
}

type recordDialer struct {
	mu  sync.Mutex
	log []string
}

func (d *recordDialer) Dial(_ context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.log = append(d.log, network+" "+address)
	d.mu.Unlock()
	return nil, errors.New("dial failed")
}

func (d *recordDialer) calls() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, len(d.log))
	copy(out, d.log)
	return out
}

func sameCalls(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
