package scrape

import (
	"math"
	"testing"
)

func sumCounts(c []uint64) uint64 {
	var s uint64
	for _, v := range c {
		s += v
	}
	return s
}

func TestToExpHistogramConservesCount(t *testing.T) {
	// Cumulative le-buckets; deltas are 2,3,4 then +Inf overflow 1 -> total 10.
	buckets := map[float64]uint64{
		0.1:         2,
		0.5:         5,
		1:           9,
		math.Inf(1): 10,
	}
	eh := toExpHistogram(buckets, 4.2, 10, 3)

	if eh.Scale != 3 {
		t.Errorf("scale = %d, want 3", eh.Scale)
	}
	if eh.Sum != 4.2 || eh.Count != 10 {
		t.Errorf("sum/count = %v/%d, want 4.2/10", eh.Sum, eh.Count)
	}
	if got := eh.ZeroCount + sumCounts(eh.PositiveCounts); got != 10 {
		t.Errorf("observations conserved? zero+positive = %d, want 10", got)
	}
	if eh.ZeroCount != 0 {
		t.Errorf("zero count = %d, want 0", eh.ZeroCount)
	}
}

func TestToExpHistogramInfWithEmptyFiniteBuckets(t *testing.T) {
	// Every finite bucket is empty and all mass is at +Inf: the overflow must
	// fold into the top finite bucket instead of vanishing (else Count would
	// exceed the summed buckets - an internally inconsistent point for amber).
	buckets := map[float64]uint64{
		0.1:         0,
		math.Inf(1): 42,
	}
	eh := toExpHistogram(buckets, 100, 42, 3)
	if got := eh.ZeroCount + sumCounts(eh.PositiveCounts); got != 42 {
		t.Errorf("observations conserved? zero+positive = %d, want 42", got)
	}
	if eh.Count != 42 {
		t.Errorf("count = %d, want 42", eh.Count)
	}
}

func TestToExpHistogramRespectsScale(t *testing.T) {
	// The conversion is parameterized by scale; observations are conserved at any
	// density (buckets merge as the scale coarsens, but nothing is lost).
	buckets := map[float64]uint64{0.5: 3, 2: 7, math.Inf(1): 7}
	for _, scale := range []int32{0, 2, 5} {
		eh := toExpHistogram(buckets, 1.0, 7, scale)
		if eh.Scale != scale {
			t.Errorf("scale %d: eh.Scale = %d", scale, eh.Scale)
		}
		if got := eh.ZeroCount + sumCounts(eh.PositiveCounts); got != 7 {
			t.Errorf("scale %d: conserved = %d, want 7", scale, got)
		}
	}
}

func TestToExpHistogramZeroBucket(t *testing.T) {
	// le<=0 observations go to ZeroCount.
	buckets := map[float64]uint64{
		0:           1, // cum 1 <= 0
		1:           3, // delta 2
		math.Inf(1): 3, // delta 0
	}
	eh := toExpHistogram(buckets, 1.0, 3, 3)
	if eh.ZeroCount != 1 {
		t.Errorf("zero count = %d, want 1", eh.ZeroCount)
	}
	if got := eh.ZeroCount + sumCounts(eh.PositiveCounts); got != 3 {
		t.Errorf("total = %d, want 3", got)
	}
}
