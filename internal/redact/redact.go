// Package redact provides helpers for keeping secrets out of logs. wisp handles
// bearer tokens (exporter auth headers, receiver API keys); their values must
// never be logged - only their presence or key names.
package redact

import (
	"maps"
	"slices"
)

// Value masks a secret for logging: any non-empty value renders as "***".
func Value(s string) string {
	if s == "" {
		return ""
	}
	return "***"
}

// Keys returns the (sorted) key names of a header/secret map without any values,
// so logs can show what is configured without leaking the secrets themselves.
func Keys(m map[string]string) []string {
	return slices.Sorted(maps.Keys(m))
}
