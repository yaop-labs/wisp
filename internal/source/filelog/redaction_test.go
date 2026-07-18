package filelog

import (
	"strings"
	"testing"
)

func TestContentRedactorAppliesOrderedLiteralReplacement(t *testing.T) {
	redactor, err := newContentRedactor(&RedactionConfig{
		Patterns: []string{
			`(?i)bearer\s+[a-z0-9._-]+`,
			`card=\d+`,
		},
	}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	got, matches, ok := redactor.apply(
		[]byte("auth=Bearer abc.def card=4111111111111111"),
	)
	if !ok {
		t.Fatal("bounded redaction unexpectedly failed")
	}
	if want := "auth=[REDACTED] [REDACTED]"; string(got) != want {
		t.Fatalf("redacted=%q, want %q", got, want)
	}
	if matches != 2 {
		t.Fatalf("matches=%d, want 2", matches)
	}

	literal, err := newContentRedactor(&RedactionConfig{
		Patterns:    []string{`secret`},
		Replacement: "$1",
	}, 64)
	if err != nil {
		t.Fatal(err)
	}
	got, _, ok = literal.apply([]byte("secret"))
	if !ok || string(got) != "$1" {
		t.Fatalf("replacement was interpreted as expansion: %q ok=%v", got, ok)
	}
}

func TestContentRedactorRejectsExpansionAboveBoundBeforeBuilding(t *testing.T) {
	redactor, err := newContentRedactor(&RedactionConfig{
		Patterns:    []string{`a`},
		Replacement: "1234",
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	got, matches, ok := redactor.apply([]byte("aaaa"))
	if ok || got != nil || matches != 4 {
		t.Fatalf("redaction result=%q matches=%d ok=%v", got, matches, ok)
	}
}

func TestContentRedactorValidatesRules(t *testing.T) {
	tests := []RedactionConfig{
		{},
		{Patterns: []string{"["}},
		{Patterns: []string{`a*`}},
		{Patterns: []string{strings.Repeat("x", maxRedactionPatternBytes+1)}},
		{Patterns: []string{"secret"}, Replacement: "bad\nreplacement"},
	}
	for index := range tests {
		if _, err := newContentRedactor(&tests[index], 1024); err == nil {
			t.Fatalf("invalid redaction config %d accepted", index)
		}
	}
}
