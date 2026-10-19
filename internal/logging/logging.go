// Package logging writes slog records as JSON and strips credential-shaped text.
package logging

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"strings"
)

var secretPattern = regexp.MustCompile(`tskey-[A-Za-z0-9_-]+`)

// NewHandler returns a JSON slog handler that redacts Tailscale auth keys.
func NewHandler(w io.Writer, level slog.Level) slog.Handler {
	return redactHandler{Handler: slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})}
}

type redactHandler struct {
	slog.Handler
}

func (h redactHandler) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, redact(rec.Message), rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(redactAttr(a))
		return true
	})
	return h.Handler.Handle(ctx, out)
}

func redactAttr(a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindString {
		a.Value = slog.StringValue(redact(a.Value.String()))
	}
	return a
}

// Redact replaces Tailscale auth key material with a fixed placeholder.
func Redact(s string) string {
	return secretPattern.ReplaceAllString(s, "tskey-redacted")
}

func redact(s string) string {
	return Redact(s)
}

// Writer sends standard-library log lines to slog at level.
func Writer(level slog.Level) io.Writer {
	return lineWriter{level: level}
}

type lineWriter struct {
	level slog.Level
}

func (w lineWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		slog.Log(context.Background(), w.level, msg)
	}
	return len(p), nil
}
