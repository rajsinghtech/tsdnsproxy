package ui

import "github.com/rajsinghtech/tsdnsproxy/internal/logging"

// Redact hides Tailscale auth key material.
func Redact(s string) string {
	return logging.Redact(s)
}
