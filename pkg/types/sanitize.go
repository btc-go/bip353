package types

import (
	"strings"
	"unicode"
)

// SanitizeText replaces control and invisible formatting characters (ANSI
// escapes, CR/LF, bidi overrides, ...) with '?' so attacker-controlled strings
// from DNS records can't forge or overwrite terminal output.
func SanitizeText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return '?'
		}
		return r
	}, s)
}
