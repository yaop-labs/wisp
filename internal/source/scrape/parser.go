package scrape

import (
	"math"
	"strconv"
	"strings"

	"github.com/yaop-labs/wisp/internal/model"
)

// parse turns a Prometheus/OpenMetrics text exposition into series. Scalar
// metrics (counter/gauge/summary components) become one series per sample line.
// Classic histogram families (a metric with `# TYPE x histogram` plus its
// x_bucket/x_count/x_sum lines) are reassembled per label set and converted to
// a single exponential-histogram series for amber's histogram engine.
//
// NaN and +/-Inf samples are dropped: amber rejects them as unencodable in the
// int64 value model (see the wisp/coral/amber metric contract). defaultTS (unix nanos) is used when
// a line omits a timestamp.
func parse(text string, defaultTS uint64) []model.Series {
	types := make(map[string]string)
	var scalars []model.Series
	hist := make(map[string]*histAccum)

	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line[0] == '#' {
			f := strings.Fields(line)
			if len(f) >= 4 && f[1] == "TYPE" {
				types[f[2]] = f[3]
			}
			continue
		}
		name, attrs, value, ts, ok := parseLine(line, defaultTS)
		if !ok {
			continue
		}
		if base, comp, isHist := histComponent(name, types); isHist {
			accumulateHist(hist, base, comp, attrs, value, ts)
			continue
		}
		scalars = append(scalars, scalarFromLine(name, attrs, value, ts, types))
	}

	out := scalars
	for _, h := range hist {
		out = append(out, h.series())
	}
	return out
}

// parseLine extracts the raw components of one sample line without deciding its
// type. ok is false for malformed lines and for NaN/+/-Inf values.
func parseLine(line string, defaultTS uint64) (name string, attrs model.Labels, value float64, ts uint64, ok bool) {
	var rest string
	if i := strings.IndexByte(line, '{'); i >= 0 {
		name = strings.TrimSpace(line[:i])
		// Find the closing brace that is outside any quoted label value, so a
		// value like path="/a}b" doesn't terminate the label block early.
		closeIdx := matchingBrace(line, i)
		if closeIdx < 0 {
			return "", nil, 0, 0, false
		}
		attrs = parseLabels(line[i+1 : closeIdx])
		rest = strings.TrimSpace(line[closeIdx+1:])
	} else {
		before, after, ok := strings.Cut(line, " ")
		if !ok {
			return "", nil, 0, 0, false
		}
		name = strings.TrimSpace(before)
		rest = strings.TrimSpace(after)
	}
	if name == "" {
		return "", nil, 0, 0, false
	}
	f := strings.Fields(rest)
	if len(f) == 0 {
		return "", nil, 0, 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return "", nil, 0, 0, false
	}
	ts = defaultTS
	if len(f) >= 2 {
		if ms, err := strconv.ParseInt(f[1], 10, 64); err == nil {
			ts = uint64(ms) * 1_000_000
		}
	}
	return name, attrs, v, ts, true
}

// matchingBrace returns the index of the '}' that closes the label block opened
// at index open, ignoring '}' that appears inside a quoted label value (with \
// escapes). Returns -1 if no closing brace is found.
func matchingBrace(s string, open int) int {
	inQuote := false
	for j := open + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			if inQuote {
				j++ // skip escaped character
			}
		case '"':
			inQuote = !inQuote
		case '}':
			if !inQuote {
				return j
			}
		}
	}
	return -1
}

// scalarFromLine builds a scalar series, shipping integral values as exact int64.
func scalarFromLine(name string, attrs model.Labels, v float64, ts uint64, types map[string]string) model.Series {
	typ, monotonic := sampleType(name, types)
	p := model.Point{TimeUnixNano: ts}
	if v == math.Trunc(v) && math.Abs(v) < 9.2e18 {
		p.IntValue = int64(v)
	} else {
		p.FloatValue = v
		p.IsFloat = true
	}
	return model.Series{Name: name, Type: typ, Monotonic: monotonic, Attrs: attrs, Points: []model.Point{p}}
}

// sampleType maps a non-histogram metric line to its storage type via # TYPE.
func sampleType(name string, types map[string]string) (model.MetricType, bool) {
	switch types[name] {
	case "counter":
		return model.MetricSum, true
	case "gauge", "untyped", "summary": // summary's quantile lines are gauges
		return model.MetricGauge, false
	}
	// Summary _count/_sum components are monotonic counters.
	for _, suf := range []string{"_count", "_sum"} {
		if base := strings.TrimSuffix(name, suf); base != name {
			if types[base] == "summary" {
				return model.MetricSum, true
			}
		}
	}
	return model.MetricGauge, false
}

// histComponent reports whether name is a component of a histogram-typed family
// and returns the base metric name and component ("bucket"/"count"/"sum").
func histComponent(name string, types map[string]string) (base, comp string, ok bool) {
	for _, suf := range []string{"_bucket", "_count", "_sum"} {
		if b, ok := strings.CutSuffix(name, suf); ok {
			if types[b] == "histogram" {
				return b, strings.TrimPrefix(suf, "_"), true
			}
		}
	}
	return "", "", false
}

func accumulateHist(hist map[string]*histAccum, base, comp string, attrs model.Labels, v float64, ts uint64) {
	noLe := labelsWithoutLe(attrs)
	key := base + "\x00" + model.CanonicalKey(noLe)
	h := hist[key]
	if h == nil {
		h = newHistAccum(base, noLe)
		hist[key] = h
	}
	h.ts = ts
	switch comp {
	case "bucket":
		le := math.Inf(1)
		if s, ok := labelGet(attrs, "le"); ok {
			if parsed, err := strconv.ParseFloat(s, 64); err == nil {
				le = parsed
			}
		}
		if v >= 0 {
			h.buckets[le] = uint64(v)
		}
	case "count":
		if v >= 0 {
			h.count = uint64(v)
		}
	case "sum":
		h.sum = v
	}
}

// parseLabels parses `a="x",b="y"` honoring \\, \" and \n escapes. The common
// (no-escape) value is sliced from s directly to avoid a per-value allocation;
// only escaped values are rebuilt. out is pre-sized from the '=' count.
func parseLabels(s string) model.Labels {
	out := make(model.Labels, 0, strings.Count(s, "="))
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == ',') {
			i++
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			break
		}
		name := strings.TrimSpace(s[i : i+eq])
		i += eq + 1
		if i >= len(s) || s[i] != '"' {
			break
		}
		i++
		valStart := i
		escaped := false
		for i < len(s) {
			c := s[i]
			if c == '\\' && i+1 < len(s) {
				escaped = true
				i += 2
				continue
			}
			if c == '"' {
				break
			}
			i++
		}
		raw := s[valStart:i]
		if i < len(s) {
			i++ // consume closing quote
		}
		if name == "" {
			continue
		}
		value := raw
		if escaped {
			value = unescapeLabelValue(raw)
		}
		out = append(out, model.Label{Name: name, Value: value})
	}
	return out
}

// unescapeLabelValue resolves \\, \" and \n in a label value (slow path; only
// called when the value actually contains a backslash).
func unescapeLabelValue(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				b.WriteByte('\n')
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			default:
				b.WriteByte(s[i+1])
			}
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func labelsWithoutLe(attrs model.Labels) model.Labels {
	out := make(model.Labels, 0, len(attrs))
	for _, l := range attrs {
		if l.Name != "le" {
			out = append(out, l)
		}
	}
	return out
}

func labelGet(attrs model.Labels, name string) (string, bool) {
	for _, l := range attrs {
		if l.Name == name {
			return l.Value, true
		}
	}
	return "", false
}
