package scrape

import (
	"testing"

	"github.com/yaop-labs/wisp/internal/model"
)

const sample = `
# HELP http_requests_total The total number of HTTP requests.
# TYPE http_requests_total counter
http_requests_total{method="post",code="200"} 1027
http_requests_total{method="post",code="400"} 3
# TYPE temperature_celsius gauge
temperature_celsius 23.5
# TYPE rpc_duration_seconds summary
rpc_duration_seconds{quantile="0.5"} 0.012
rpc_duration_seconds_count 2693
rpc_duration_seconds_sum 17.6
# a stray comment
nan_dropped{a="b"} NaN
inf_dropped +Inf
`

func find(series []model.Series, name string, attrs map[string]string) *model.Series {
	for i := range series {
		if series[i].Name != name {
			continue
		}
		ok := true
		for k, v := range attrs {
			val, has := "", false
			for _, l := range series[i].Attrs {
				if l.Name == k {
					val, has = l.Value, true
				}
			}
			if !has || val != v {
				ok = false
				break
			}
		}
		if ok {
			return &series[i]
		}
	}
	return nil
}

func TestParseLabelValueWithBrace(t *testing.T) {
	// A label value containing '}' must not terminate the label block early.
	series := parse(`http_requests_total{path="/a}b",code="200"} 5`, 1)
	if len(series) != 1 {
		t.Fatalf("parsed %d series, want 1", len(series))
	}
	s := series[0]
	if s.Name != "http_requests_total" {
		t.Errorf("name = %q", s.Name)
	}
	if labelValue(s.Attrs, "path") != "/a}b" {
		t.Errorf("path = %q, want /a}b", labelValue(s.Attrs, "path"))
	}
	if labelValue(s.Attrs, "code") != "200" {
		t.Errorf("code = %q, want 200", labelValue(s.Attrs, "code"))
	}
	if len(s.Points) != 1 || s.Points[0].IntValue != 5 {
		t.Errorf("value not parsed after braced label: %+v", s.Points)
	}
}

func TestParseTabSeparatedLabelless(t *testing.T) {
	// A label-less sample separated by a tab (valid Prometheus) must parse, not
	// be silently dropped.
	series := parse("go_goroutines\t42", 1)
	s := find(series, "go_goroutines", nil)
	if s == nil {
		t.Fatal("tab-separated label-less line was dropped")
	}
	if len(s.Points) != 1 || s.Points[0].IntValue != 42 {
		t.Errorf("value not parsed: %+v", s.Points)
	}
}

func TestParseTwoHistogramSeries(t *testing.T) {
	// Two families of the same metric with different labels, interleaved by the
	// caching accumulator: they must not be merged into one series.
	text := `# TYPE http_latency histogram
http_latency_bucket{path="/a",le="0.1"} 1
http_latency_bucket{path="/a",le="+Inf"} 3
http_latency_count{path="/a"} 3
http_latency_bucket{path="/b",le="0.1"} 5
http_latency_bucket{path="/b",le="+Inf"} 9
http_latency_count{path="/b"} 9`
	series := parse(text, 1)

	var a, b *model.Series
	for i := range series {
		if series[i].Type != model.MetricExponentialHistogram {
			continue
		}
		switch labelValue(series[i].Attrs, "path") {
		case "/a":
			a = &series[i]
		case "/b":
			b = &series[i]
		}
	}
	if a == nil || b == nil {
		t.Fatalf("want 2 histogram series (/a,/b), got %d: %+v", len(series), series)
	}
	if a.Points[0].Hist.Count != 3 {
		t.Errorf("/a count = %d, want 3", a.Points[0].Hist.Count)
	}
	if b.Points[0].Hist.Count != 9 {
		t.Errorf("/b count = %d, want 9 (cache must not merge families)", b.Points[0].Hist.Count)
	}
}

func TestMatchingBrace(t *testing.T) {
	cases := []struct {
		line string
		want int
	}{
		{`x{a="1"} 5`, 7},
		{`x{a="}"} 5`, 7},  // '}' inside quotes ignored
		{`x{a="\""} 5`, 8}, // escaped quote inside value
		{`x{a="1"`, -1},    // unterminated
	}
	for _, c := range cases {
		open := 1 // position of '{' in each case
		if got := matchingBrace(c.line, open); got != c.want {
			t.Errorf("matchingBrace(%q) = %d, want %d", c.line, got, c.want)
		}
	}
}

func TestParse(t *testing.T) {
	series := parse(sample, 42)

	// NaN and +Inf lines are dropped.
	if find(series, "nan_dropped", nil) != nil || find(series, "inf_dropped", nil) != nil {
		t.Error("NaN/Inf samples should be dropped")
	}

	// Counter, integral -> int, monotonic sum.
	c := find(series, "http_requests_total", map[string]string{"method": "post", "code": "200"})
	if c == nil {
		t.Fatal("missing http_requests_total{200}")
	}
	if c.Type != model.MetricSum || !c.Monotonic {
		t.Error("counter should be a monotonic sum")
	}
	if c.Points[0].IsFloat || c.Points[0].IntValue != 1027 {
		t.Errorf("counter should be int 1027, got float=%v val=%d", c.Points[0].IsFloat, c.Points[0].IntValue)
	}
	if c.Points[0].TimeUnixNano != 42 {
		t.Errorf("default timestamp not applied: %d", c.Points[0].TimeUnixNano)
	}

	// Gauge, fractional -> float.
	g := find(series, "temperature_celsius", nil)
	if g == nil || g.Type != model.MetricGauge {
		t.Fatal("temperature_celsius should be a gauge")
	}
	if !g.Points[0].IsFloat || g.Points[0].FloatValue != 23.5 {
		t.Errorf("gauge should be float 23.5")
	}

	// Summary: quantile line is a gauge; _count/_sum are monotonic sums.
	q := find(series, "rpc_duration_seconds", map[string]string{"quantile": "0.5"})
	if q == nil || q.Type != model.MetricGauge {
		t.Error("summary quantile line should be a gauge")
	}
	if sc := find(series, "rpc_duration_seconds_count", nil); sc == nil || sc.Type != model.MetricSum {
		t.Error("summary _count should be a monotonic sum")
	}
}

const histExposition = `
# TYPE request_duration_seconds histogram
request_duration_seconds_bucket{method="get",le="0.1"} 2
request_duration_seconds_bucket{method="get",le="0.5"} 5
request_duration_seconds_bucket{method="get",le="1"} 9
request_duration_seconds_bucket{method="get",le="+Inf"} 10
request_duration_seconds_count{method="get"} 10
request_duration_seconds_sum{method="get"} 4.2
`

func TestParseReassemblesHistogram(t *testing.T) {
	series := parse(histExposition, 7)

	// The _bucket/_count/_sum lines must NOT appear as scalar series.
	for _, s := range series {
		switch s.Name {
		case "request_duration_seconds_bucket", "request_duration_seconds_count", "request_duration_seconds_sum":
			t.Errorf("classic component %q leaked as a scalar series", s.Name)
		}
	}

	h := find(series, "request_duration_seconds", map[string]string{"method": "get"})
	if h == nil {
		t.Fatal("expected reassembled exponential-histogram series")
	}
	if h.Type != model.MetricExponentialHistogram {
		t.Fatalf("type = %v, want exponential_histogram", h.Type)
	}
	if len(h.Points) != 1 || h.Points[0].Hist == nil {
		t.Fatal("histogram point/payload missing")
	}
	eh := h.Points[0].Hist
	if eh.Count != 10 || eh.Sum != 4.2 {
		t.Errorf("count/sum = %d/%v, want 10/4.2", eh.Count, eh.Sum)
	}
	if h.Points[0].TimeUnixNano != 7 {
		t.Errorf("timestamp = %d, want 7", h.Points[0].TimeUnixNano)
	}
	// "le" must not survive as a label on the reassembled series.
	for _, l := range h.Attrs {
		if l.Name == "le" {
			t.Error("le label should be stripped from the histogram series")
		}
	}
}
