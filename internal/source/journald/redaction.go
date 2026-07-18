package journald

import (
	"fmt"
	"regexp"
	"unicode"
	"unicode/utf8"

	"github.com/yaop-labs/wisp/internal/selfobs"
)

const (
	maxRedactionRules       = 16
	maxRedactionPattern     = 1024
	maxRedactionReplacement = 256
)

type RedactionConfig struct {
	Patterns    []string
	Replacement string
}

type contentRedactor struct {
	patterns    []*regexp.Regexp
	replacement []byte
	maxBytes    int
}

func newContentRedactor(
	cfg *RedactionConfig,
	maxBytes int,
) (*contentRedactor, error) {
	if cfg == nil {
		return nil, nil
	}
	if len(cfg.Patterns) == 0 || len(cfg.Patterns) > maxRedactionRules {
		return nil, fmt.Errorf(
			"journald: redaction requires between 1 and %d patterns",
			maxRedactionRules,
		)
	}
	replacement := cfg.Replacement
	if replacement == "" {
		replacement = "[REDACTED]"
	}
	if len(replacement) > maxRedactionReplacement ||
		!utf8.ValidString(replacement) {
		return nil, fmt.Errorf("journald: invalid redaction replacement")
	}
	for _, value := range replacement {
		if unicode.IsControl(value) {
			return nil, fmt.Errorf("journald: invalid redaction replacement")
		}
	}
	redactor := &contentRedactor{
		replacement: []byte(replacement),
		maxBytes:    maxBytes,
	}
	for index, pattern := range cfg.Patterns {
		if len(pattern) == 0 || len(pattern) > maxRedactionPattern {
			return nil, fmt.Errorf(
				"journald: redaction pattern %d has invalid length",
				index,
			)
		}
		compiled, err := regexp.Compile(pattern)
		if err != nil || compiled.MatchString("") {
			return nil, fmt.Errorf(
				"journald: redaction pattern %d is invalid",
				index,
			)
		}
		redactor.patterns = append(redactor.patterns, compiled)
	}
	return redactor, nil
}

func (r *contentRedactor) apply(value []byte) ([]byte, bool) {
	if r == nil {
		return append([]byte(nil), value...), true
	}
	current := append([]byte(nil), value...)
	for _, pattern := range r.patterns {
		remaining := current
		output := make([]byte, 0, len(current))
		matches := 0
		for len(remaining) > 0 {
			match := pattern.FindIndex(remaining)
			if match == nil {
				break
			}
			matches++
			if len(output)+match[0]+len(r.replacement) > r.maxBytes {
				selfobs.JournaldRedactionMatches.Add(uint64(matches))
				selfobs.JournaldRedactionDropped.Inc()
				return nil, false
			}
			output = append(output, remaining[:match[0]]...)
			output = append(output, r.replacement...)
			remaining = remaining[match[1]:]
		}
		if matches == 0 {
			continue
		}
		selfobs.JournaldRedactionMatches.Add(uint64(matches))
		if len(output)+len(remaining) > r.maxBytes {
			selfobs.JournaldRedactionDropped.Inc()
			return nil, false
		}
		output = append(output, remaining...)
		current = output
	}
	return current, true
}
