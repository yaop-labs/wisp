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

func TestCanonicalKeyOrderIndependentAndInjectionSafe(t *testing.T) {
	// Order-independent: reordering labels yields the same key.
	x := Labels{{Name: "a", Value: "1"}, {Name: "b", Value: "2"}}
	y := Labels{{Name: "b", Value: "2"}, {Name: "a", Value: "1"}}
	if CanonicalKey(x) != CanonicalKey(y) {
		t.Error("CanonicalKey should be independent of label order")
	}

	// Injection-safe: two distinct label sets that collide under a naive
	// name=value\x00 encoding must produce different keys.
	a := Labels{{Name: "a", Value: "b"}, {Name: "c", Value: "d"}}
	b := Labels{{Name: "a", Value: "b\x00c=d"}}
	if CanonicalKey(a) == CanonicalKey(b) {
		t.Error("distinct label sets collided in CanonicalKey (delimiter injection)")
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
