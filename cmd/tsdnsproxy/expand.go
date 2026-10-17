package main

import (
	"os"
	"strings"
)

// expandEnvRefs replaces $VAR, ${VAR}, and $(VAR) from the environment.
// An undefined name is left unchanged. $$ becomes $.
// Kubernetes expands $(POD_NAME) before the process starts when POD_NAME is
// an earlier env var. This also expands the same text if it reaches the process.
func expandEnvRefs(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '$' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case '$':
			b.WriteByte('$')
			i++
		case '{', '(':
			closer := byte('}')
			if s[i+1] == '(' {
				closer = ')'
			}
			end := strings.IndexByte(s[i+2:], closer)
			if end < 0 {
				b.WriteByte(s[i])
				continue
			}
			name := s[i+2 : i+2+end]
			b.WriteString(envOrLiteral(name, s[i:i+3+end]))
			i += 2 + end
		default:
			j := i + 1
			for j < len(s) && isEnvNameByte(s[j]) {
				j++
			}
			if j == i+1 {
				b.WriteByte('$')
				continue
			}
			name := s[i+1 : j]
			b.WriteString(envOrLiteral(name, s[i:j]))
			i = j - 1
		}
	}
	return b.String()
}

func envOrLiteral(name, literal string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return literal
}

func isEnvNameByte(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}
