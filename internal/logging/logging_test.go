package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactHandlerHidesAuthKeys(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewHandler(&buf, slog.LevelDebug))
	logger.Info("starting", slog.String("authkey", "tskey-auth-abcDEF_123"))
	logger.Debug("literal tskey-auth-zzzz in the message")
	got := buf.String()
	if strings.Contains(got, "abcDEF") || strings.Contains(got, "zzzz") {
		t.Fatalf("secret leaked: %s", got)
	}
	if strings.Count(got, "tskey-redacted") < 2 {
		t.Fatalf("redaction missing: %s", got)
	}
}
