package wif

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestTokenInline(t *testing.T) {
	got, err := Token(context.Background(), Source{Token: " abc \n"})
	if err != nil || got != "abc" {
		t.Fatalf("Token = %q, %v", got, err)
	}
}

func TestTokenFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(p, []byte("jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Token(context.Background(), Source{File: p})
	if err != nil || got != "jwt" {
		t.Fatalf("Token = %q, %v", got, err)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Token(context.Background(), Source{File: empty}); err == nil {
		t.Fatal("empty token file accepted")
	}
}

func TestTokenNoSource(t *testing.T) {
	if _, err := Token(context.Background(), Source{}); err == nil {
		t.Fatal("no source accepted")
	}
}

func TestFetchJWTSVIDMissingCA(t *testing.T) {
	_, err := FetchJWTSVID(context.Background(), "127.0.0.1:1", filepath.Join(t.TempDir(), "none"), "x", "aud")
	if err == nil {
		t.Fatal("missing CA accepted")
	}
}
