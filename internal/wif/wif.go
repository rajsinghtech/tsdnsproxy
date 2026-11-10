// Package wif obtains the ID token that tsnet exchanges for an auth key with
// Tailscale workload identity federation. The token is needed only for the
// node's first login; once the node key is in the state store, restarts log in
// with it.
package wif

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// FetchLimit bounds one JWT-SVID request.
const FetchLimit = 15 * time.Second

// Source describes where the ID token comes from. Exactly one of Token, File,
// and Agent is set.
type Source struct {
	Token string
	File  string

	// Agent is a SPIFFE Workload API address served over TLS, such as an
	// identity-server agent. The caller authenticates with the bearer token in
	// AgentToken (a projected ServiceAccount token) and trusts AgentCA.
	Agent      string
	AgentCA    string
	AgentToken string
	Audience   string
}

// Token returns the ID token from src.
func Token(ctx context.Context, src Source) (string, error) {
	switch {
	case src.Token != "":
		return strings.TrimSpace(src.Token), nil
	case src.File != "":
		b, err := os.ReadFile(src.File)
		if err != nil {
			return "", fmt.Errorf("id token file: %w", err)
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return "", fmt.Errorf("id token file %s is empty", src.File)
		}
		return tok, nil
	case src.Agent != "":
		return FetchJWTSVID(ctx, src.Agent, src.AgentCA, src.AgentToken, src.Audience)
	default:
		return "", errors.New("no id token source")
	}
}

// FetchJWTSVID asks a SPIFFE Workload API server reached over TLS for a
// JWT-SVID with the given audience.
func FetchJWTSVID(ctx context.Context, addr, caFile, tokenFile, audience string) (string, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return "", fmt.Errorf("spiffe agent CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return "", fmt.Errorf("spiffe agent CA %s: no certificates", caFile)
	}
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("spiffe agent token: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, FetchLimit)
	defer cancel()
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})),
		grpc.WithPerRPCCredentials(bearer(strings.TrimSpace(string(token)))),
	)
	if err != nil {
		return "", fmt.Errorf("spiffe agent %s: %w", addr, err)
	}
	defer conn.Close()

	// The Workload API requires this header on every call.
	ctx = metadata.AppendToOutgoingContext(ctx, "workload.spiffe.io", "true")
	resp, err := workload.NewSpiffeWorkloadAPIClient(conn).FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{audience}})
	if err != nil {
		return "", fmt.Errorf("spiffe agent %s: FetchJWTSVID: %w", addr, err)
	}
	if len(resp.Svids) == 0 || resp.Svids[0].Svid == "" {
		return "", fmt.Errorf("spiffe agent %s: empty JWT-SVID response", addr)
	}
	return resp.Svids[0].Svid, nil
}

// bearer sends the token as "authorization: Bearer <token>".
type bearer string

func (t bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + string(t)}, nil
}

func (bearer) RequireTransportSecurity() bool { return true }
