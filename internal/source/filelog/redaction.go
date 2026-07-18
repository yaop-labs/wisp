package filelog

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/yaop-labs/wisp/internal/selfobs"
)

const (
	defaultRedactionReplacement = "[REDACTED]"
	maxRedactionRules           = 16
	maxRedactionPatternBytes    = 1024
	maxRedactionReplacement     = 256
)

type contentRedactor struct {
	rules       []*regexp.Regexp
	replacement []byte
	limit       int
}

func newContentRedactor(config *RedactionConfig, limit int) (*contentRedactor, error) {
	if config == nil {
		return nil, nil
	}
	if len(config.Patterns) == 0 || len(config.Patterns) > maxRedactionRules {
		return nil, fmt.Errorf("filelog: redaction requires between 1 and %d patterns", maxRedactionRules)
	}
	replacement := config.Replacement
	if replacement == "" {
		replacement = defaultRedactionReplacement
	}
	if len(replacement) > maxRedactionReplacement ||
		!utf8.ValidString(replacement) ||
		strings.IndexFunc(replacement, unicode.IsControl) >= 0 {
		return nil, fmt.Errorf("filelog: redaction replacement must be valid printable UTF-8 up to %d bytes", maxRedactionReplacement)
	}
	redactor := &contentRedactor{
		rules:       make([]*regexp.Regexp, 0, len(config.Patterns)),
		replacement: []byte(replacement),
		limit:       limit,
	}
	for index, pattern := range config.Patterns {
		if pattern == "" || len(pattern) > maxRedactionPatternBytes {
			return nil, fmt.Errorf(
				"filelog: redaction pattern %d must contain between 1 and %d bytes",
				index,
				maxRedactionPatternBytes,
			)
		}
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("filelog: redaction pattern %d is not a valid regular expression", index)
		}
		if compiled.MatchString("") {
			return nil, fmt.Errorf("filelog: redaction pattern %d must not match empty input", index)
		}
		redactor.rules = append(redactor.rules, compiled)
	}
	return redactor, nil
}

func (s *Source) redactLogBody(body []byte) ([]byte, bool) {
	if s.redactor == nil {
		return body, true
	}
	redacted, matches, ok := s.redactor.apply(body)
	if matches > 0 {
		selfobs.FileLogRedactionMatches.Add(uint64(matches))
	}
	if !ok {
		selfobs.FileLogRedactionDropped.Inc()
	}
	return redacted, ok
}

func (r *contentRedactor) apply(input []byte) ([]byte, int, bool) {
	current := input
	totalMatches := 0
	for _, rule := range r.rules {
		indices := rule.FindAllIndex(current, -1)
		if len(indices) == 0 {
			continue
		}
		totalMatches += len(indices)
		size := len(current)
		for _, index := range indices {
			size += len(r.replacement) - (index[1] - index[0])
			if size > r.limit {
				return nil, totalMatches, false
			}
		}
		output := make([]byte, 0, size)
		previous := 0
		for _, index := range indices {
			output = append(output, current[previous:index[0]]...)
			output = append(output, r.replacement...)
			previous = index[1]
		}
		output = append(output, current[previous:]...)
		current = output
	}
	return current, totalMatches, true
}
