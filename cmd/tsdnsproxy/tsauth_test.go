package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rajsinghtech/tsdnsproxy/internal/config"
	"github.com/rajsinghtech/tsdnsproxy/internal/wif"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
)

const testClientID = "Tabc-kdef?ephemeral=false&preauthorized=true"

func wifConfig(t *testing.T) config.Config {
	t.Helper()
	return config.Config{
		ClientID:    testClientID,
		SPIFFEAgent: "spiffe-agent.example.com:443",
		StateDir:    t.TempDir(),
	}
}

type tokenCalls struct {
	n   int
	src wif.Source
}

func (c *tokenCalls) fetch(tok string, err error) idTokenFunc {
	return func(_ context.Context, src wif.Source) (string, error) {
		c.n++
		c.src = src
		return tok, err
	}
}

func storeWithNode(t *testing.T) ipn.StateStore {
	t.Helper()
	st := new(mem.Store)
	if err := st.WriteState(ipn.CurrentProfileStateKey, []byte("profile-1")); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestResolveTSNetAuthNodeStateSkipsWIF(t *testing.T) {
	var calls tokenCalls
	auth, err := resolveTSNetAuth(context.Background(), wifConfig(t), storeWithNode(t), calls.fetch("id-token", nil))
	if err != nil {
		t.Fatal(err)
	}
	if auth != (tsnetAuth{}) {
		t.Fatalf("auth = %+v, want no credentials", auth)
	}
	if calls.n != 0 {
		t.Fatalf("ID token fetched %d times with node state present", calls.n)
	}
}

func TestResolveTSNetAuthFileStateSkipsWIF(t *testing.T) {
	cfg := wifConfig(t)
	if err := os.WriteFile(filepath.Join(cfg.StateDir, "tailscaled.state"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls tokenCalls
	auth, err := resolveTSNetAuth(context.Background(), cfg, nil, calls.fetch("id-token", nil))
	if err != nil {
		t.Fatal(err)
	}
	if auth != (tsnetAuth{}) || calls.n != 0 {
		t.Fatalf("auth = %+v, fetches = %d", auth, calls.n)
	}
}

func TestResolveTSNetAuthEmptyStateUsesWIF(t *testing.T) {
	for _, st := range []ipn.StateStore{new(mem.Store), nil} {
		var calls tokenCalls
		cfg := wifConfig(t)
		auth, err := resolveTSNetAuth(context.Background(), cfg, st, calls.fetch("id-token", nil))
		if err != nil {
			t.Fatal(err)
		}
		want := tsnetAuth{ClientID: testClientID, IDToken: "id-token"}
		if auth != want {
			t.Fatalf("auth = %+v, want %+v", auth, want)
		}
		if calls.n != 1 {
			t.Fatalf("ID token fetched %d times, want 1", calls.n)
		}
		if calls.src.Agent != cfg.SPIFFEAgent || calls.src.Audience != "api.tailscale.com/Tabc-kdef" {
			t.Fatalf("token source = %+v", calls.src)
		}
	}
}

func TestResolveTSNetAuthTokenError(t *testing.T) {
	var calls tokenCalls
	_, err := resolveTSNetAuth(context.Background(), wifConfig(t), new(mem.Store), calls.fetch("", errors.New("agent down")))
	if err == nil || !strings.Contains(err.Error(), "agent down") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveTSNetAuthAuthKey(t *testing.T) {
	var calls tokenCalls
	cfg := config.Config{AuthKey: "tskey-auth-example", StateDir: t.TempDir()}
	for _, st := range []ipn.StateStore{new(mem.Store), storeWithNode(t)} {
		auth, err := resolveTSNetAuth(context.Background(), cfg, st, calls.fetch("id-token", nil))
		if err != nil {
			t.Fatal(err)
		}
		if auth != (tsnetAuth{AuthKey: "tskey-auth-example"}) {
			t.Fatalf("auth = %+v", auth)
		}
	}
	if calls.n != 0 {
		t.Fatalf("ID token fetched %d times for an auth key", calls.n)
	}
}

func TestTSNetAuthApplyClearsFields(t *testing.T) {
	s := &tsnet.Server{
		AuthKey:      "tskey-auth-example",
		ClientSecret: "tskey-client-example",
		ClientID:     testClientID,
		IDToken:      "stale",
		Audience:     "api.tailscale.com/Tabc-kdef",
	}
	tsnetAuth{}.apply(s)
	if s.AuthKey != "" || s.ClientSecret != "" || s.ClientID != "" || s.IDToken != "" || s.Audience != "" {
		t.Fatalf("credentials left on server: %+v", s)
	}
}

func setTSNetAuthEnv(t *testing.T) {
	t.Helper()
	for _, key := range tsnetAuthEnv {
		t.Setenv(key, "")
	}
	t.Setenv("TS_CLIENT_ID", testClientID)
	t.Setenv("TS_AUTHKEY", "tskey-auth-example")
}

func TestClearTSNetAuthEnv(t *testing.T) {
	setTSNetAuthEnv(t)
	if err := clearTSNetAuthEnv(); err != nil {
		t.Fatal(err)
	}
	for _, key := range tsnetAuthEnv {
		if v, ok := os.LookupEnv(key); ok {
			t.Errorf("%s still set to %q", key, v)
		}
	}
}

// TestTSNetStartIgnoresClientIDEnv runs tsnet's own Start with node state
// present and TS_CLIENT_ID in the environment, as on a pod restart.
func TestTSNetStartIgnoresClientIDEnv(t *testing.T) {
	start := func(t *testing.T, clearEnv bool) error {
		t.Setenv("TS_CLIENT_ID", testClientID)
		t.Setenv("TS_AUTHKEY", "")
		t.Setenv("TS_ID_TOKEN", "")
		t.Setenv("TS_AUDIENCE", "")
		cfg := wifConfig(t)
		st, err := store.NewFileStore(t.Logf, filepath.Join(cfg.StateDir, "tailscaled.state"))
		if err != nil {
			t.Fatal(err)
		}
		if err := st.WriteState(ipn.CurrentProfileStateKey, []byte("profile-1")); err != nil {
			t.Fatal(err)
		}
		s := &tsnet.Server{
			Dir:        cfg.StateDir,
			Hostname:   "tsdnsproxy-test",
			Store:      st,
			ControlURL: "http://127.0.0.1:1",
			Logf:       func(string, ...any) {},
		}
		var calls tokenCalls
		auth, err := resolveTSNetAuth(context.Background(), cfg, s.Store, calls.fetch("id-token", nil))
		if err != nil {
			t.Fatal(err)
		}
		auth.apply(s)
		if clearEnv {
			if err := clearTSNetAuthEnv(); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(func() { _ = s.Close() })
		return s.Start()
	}

	t.Run("env left set", func(t *testing.T) {
		err := start(t, false)
		if err == nil || !strings.Contains(err.Error(), "ID token and audience are empty") {
			t.Fatalf("Start err = %v, want the workload identity error", err)
		}
	})
	t.Run("env cleared", func(t *testing.T) {
		if err := start(t, true); err != nil {
			t.Fatalf("Start: %v", err)
		}
	})
}
