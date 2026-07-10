// Package relabel applies a practical subset of Prometheus relabeling to series
// at the edge: keep/drop (filter whole series), replace (set/rename a label,
// including the metric name via __name__), and labeldrop/labelkeep (prune the
// label set). Regexes are fully anchored, matching Prometheus semantics.
package relabel

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/yaop-labs/wisp/internal/model"
)

const nameLabel = "__name__"

// Rule is one relabeling step (the YAML-facing shape lives in config).
type Rule struct {
	SourceLabels []string
	Separator    string
	Regex        string
	TargetLabel  string
	Replacement  string
	Action       string
}

type compiledRule struct {
	source      []string
	sep         string
	re          *regexp.Regexp
	target      string
	replacement string
	action      string
	// targetLiteral/replLiteral record that the template has no "$" reference, so
	// apply can skip the ExpandString (and its allocation) for the common case of
	// a fixed label name / literal replacement.
	targetLiteral bool
	replLiteral   bool
}

// Processor applies an ordered list of relabel rules.
type Processor struct {
	rules []compiledRule
}

func New(rules []Rule) (*Processor, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for i, r := range rules {
		sep := r.Separator
		if sep == "" {
			sep = ";"
		}
		reStr := r.Regex
		if reStr == "" {
			reStr = "(.*)"
		}
		re, err := regexp.Compile("^(?:" + reStr + ")$")
		if err != nil {
			return nil, fmt.Errorf("relabel rule %d: bad regex %q: %w", i, r.Regex, err)
		}
		repl := r.Replacement
		if repl == "" {
			repl = "$1"
		}
		action := r.Action
		if action == "" {
			action = "replace"
		}
		switch action {
		case "keep", "drop", "replace", "labeldrop", "labelkeep":
		default:
			return nil, fmt.Errorf("relabel rule %d: unsupported action %q", i, action)
		}
		compiled = append(compiled, compiledRule{
			source: r.SourceLabels, sep: sep, re: re, target: r.TargetLabel, replacement: repl, action: action,
			targetLiteral: !strings.Contains(r.TargetLabel, "$"),
			replLiteral:   !strings.Contains(repl, "$"),
		})
	}
	return &Processor{rules: compiled}, nil
}

func (p *Processor) Process(_ context.Context, b model.Batch) (model.Batch, error) {
	out := make([]model.Series, 0, len(b.Series))
	for i := range b.Series {
		s := b.Series[i]
		if p.apply(&s) {
			out = append(out, s)
		}
	}
	return model.Batch{Series: out}, nil
}

func (p *Processor) Close() error { return nil }

// apply runs every rule against s; returns false to drop the series.
func (p *Processor) apply(s *model.Series) bool {
	for _, r := range p.rules {
		switch r.action {
		case "keep":
			if !r.re.MatchString(p.concat(s, r)) {
				return false
			}
		case "drop":
			if r.re.MatchString(p.concat(s, r)) {
				return false
			}
		case "replace":
			v := p.concat(s, r)
			idx := r.re.FindStringSubmatchIndex(v)
			if idx == nil {
				continue
			}
			target := r.target
			if !r.targetLiteral {
				target = string(r.re.ExpandString(nil, r.target, v, idx))
			}
			if target == "" {
				continue
			}
			repl := r.replacement
			if !r.replLiteral {
				repl = string(r.re.ExpandString(nil, r.replacement, v, idx))
			}
			if repl == "" {
				removeLabel(s, target)
				continue
			}
			setLabel(s, target, repl)
		case "labeldrop":
			s.Attrs = s.Attrs.Filter(func(name string) bool { return !r.re.MatchString(name) })
		case "labelkeep":
			s.Attrs = s.Attrs.Filter(func(name string) bool { return r.re.MatchString(name) })
		}
	}
	return true
}

func (p *Processor) concat(s *model.Series, r compiledRule) string {
	// Most rules have a single source label; skip the slice + Join allocation.
	switch len(r.source) {
	case 0:
		return ""
	case 1:
		return getLabel(s, r.source[0])
	}
	parts := make([]string, len(r.source))
	for i, name := range r.source {
		parts[i] = getLabel(s, name)
	}
	return strings.Join(parts, r.sep)
}

func getLabel(s *model.Series, name string) string {
	if name == nameLabel {
		return s.Name
	}
	if v, ok := s.Attrs.Get(name); ok {
		return v
	}
	if v, ok := s.Resource.Get(name); ok {
		return v
	}
	return ""
}

func setLabel(s *model.Series, name, value string) {
	if name == nameLabel {
		s.Name = value
		return
	}
	for i := range s.Attrs {
		if s.Attrs[i].Name == name {
			// Copy-on-write: Process only shallow-copies each Series, so s.Attrs
			// can share its backing array with sibling series (e.g. host.go emits
			// one device slice for both receive and transmit). Mutating in place
			// would rewrite the sibling's label too, so clone before overwriting.
			attrs := append(model.Labels(nil), s.Attrs...)
			attrs[i].Value = value
			s.Attrs = attrs
			return
		}
	}
	s.Attrs = append(append(model.Labels(nil), s.Attrs...), model.Label{Name: name, Value: value})
}

func removeLabel(s *model.Series, name string) {
	if name == nameLabel {
		return
	}
	s.Attrs = s.Attrs.Filter(func(n string) bool { return n != name })
}
