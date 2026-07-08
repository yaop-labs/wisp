package model

import "testing"

func TestBatchLenCountsPoints(t *testing.T) {
	b := Batch{Series: []Series{
		{Name: "a", Points: []Point{{}, {}}},
		{Name: "b", Points: []Point{{}}},
		{Name: "c"}, // no points
	}}
	if got := b.Len(); got != 3 {
		t.Fatalf("Len = %d, want 3 (points, not series)", got)
	}
	if got := (Batch{}).Len(); got != 0 {
		t.Fatalf("empty batch Len = %d, want 0", got)
	}
}

func TestMetricTypeString(t *testing.T) {
	cases := map[MetricType]string{
		MetricGauge:                "gauge",
		MetricSum:                  "sum",
		MetricHistogram:            "histogram",
		MetricExponentialHistogram: "exponential_histogram",
		MetricType(0):              "unknown",
		MetricType(99):             "unknown",
	}
	for typ, want := range cases {
		if got := typ.String(); got != want {
			t.Errorf("MetricType(%d).String() = %q, want %q", typ, got, want)
		}
	}
}
