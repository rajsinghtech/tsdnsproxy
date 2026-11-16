package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/rajsinghtech/tsdnsproxy/internal/config"
	"github.com/rajsinghtech/tsdnsproxy/internal/wif"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

// tsnetAuthEnv lists the variables tsnet falls back to at Start when the
// matching Server field is empty. tsdnsproxy reads its own settings into
// config, so these are cleared and tsnet sees only what tsnetAuth sets. A
// leftover TS_CLIENT_ID with no ID token makes tsnet.Server.Start fail.
var tsnetAuthEnv = []string{
	"TS_AUTHKEY",
	"TS_AUTH_KEY",
	"TS_CLIENT_SECRET",
	"TS_CLIENT_ID",
	"TS_ID_TOKEN",
	"TS_AUDIENCE",
}

// tsnetAuth is the set of credentials handed to tsnet.
type tsnetAuth struct {
	AuthKey  string
	ClientID string
	IDToken  string
}

// idTokenFunc returns an ID token for workload identity federation.
type idTokenFunc func(context.Context, wif.Source) (string, error)

// resolveTSNetAuth decides what tsnet logs in with. With a client ID the ID
// token is fetched only when st holds no node yet: once the node key is
// stored, tsnet starts from it with no credentials, and restarts no longer
// depend on the token source.
func resolveTSNetAuth(ctx context.Context, cfg config.Config, st ipn.StateStore, idToken idTokenFunc) (tsnetAuth, error) {
	if cfg.ClientID == "" {
		return tsnetAuth{AuthKey: cfg.AuthKey}, nil
	}
	enrolled, err := hasNodeState(st, cfg.StateDir)
	if err != nil {
		return tsnetAuth{}, err
	}
	if enrolled {
		log.Printf("node state found; skipping workload identity login")
		return tsnetAuth{}, nil
	}
	tok, err := idToken(ctx, wif.Source{
		Token:      cfg.IDToken,
		File:       cfg.IDTokenFile,
		Agent:      cfg.SPIFFEAgent,
		AgentCA:    cfg.SPIFFEAgentCA,
		AgentToken: cfg.SPIFFEAgentToken,
		Audience:   cfg.Audience(),
	})
	if err != nil {
		return tsnetAuth{}, err
	}
	log.Print("no node state: first login via workload identity")
	return tsnetAuth{ClientID: cfg.ClientID, IDToken: tok}, nil
}

// apply sets the credential fields of s, clearing any it does not use.
func (a tsnetAuth) apply(s *tsnet.Server) {
	s.AuthKey = a.AuthKey
	s.ClientSecret = ""
	s.ClientID = a.ClientID
	s.IDToken = a.IDToken
	s.Audience = ""
}

// clearTSNetAuthEnv removes tsnetAuthEnv from the process environment.
func clearTSNetAuthEnv() error {
	for _, key := range tsnetAuthEnv {
		if err := os.Unsetenv(key); err != nil {
			return fmt.Errorf("unset %s: %w", key, err)
		}
	}
	return nil
}

// hasNodeState reports whether a node profile is already stored, in st when
// set or else in tsnet's file store under dir.
func hasNodeState(st ipn.StateStore, dir string) (bool, error) {
	if st == nil {
		_, err := os.Stat(filepath.Join(dir, "tailscaled.state"))
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return err == nil, err
	}
	_, err := st.ReadState(ipn.CurrentProfileStateKey)
	if errors.Is(err, ipn.ErrStateNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read state: %w", err)
	}
	return true, nil
}
