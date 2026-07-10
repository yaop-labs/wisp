package scrape

import (
	"math"
	"sort"

	"github.com/yaop-labs/wisp/internal/model"
)

// defaultExpScale gives base = 2^(2^-3) ~= 1.09 (~4.5% relative error), the
// default bucket density for latency/size distributions.
const defaultExpScale int32 = 3

// histAccum reassembles one classic Prometheus histogram series (a group of
// _bucket/_count/_sum lines sharing the same labels, minus le) before it is
// converted to an exponential histogram.
type histAccum struct {
	name    string
	attrs   model.Labels // labels without "le"
	ts      uint64
	buckets map[float64]uint64 // le -> cumulative count
	count   uint64
	sum     float64
}

func newHistAccum(name string, attrs model.Labels) *histAccum {
	return &histAccum{name: name, attrs: attrs, buckets: make(map[float64]uint64)}
}

// series converts the accumulated classic histogram into an exponential-histogram
// series.
func (h *histAccum) series() model.Series {
	eh := toExpHistogram(h.buckets, h.sum, h.count, defaultExpScale)
	return model.Series{
		Name:   h.name,
		Type:   model.MetricExponentialHistogram,
		Attrs:  h.attrs,
		Points: []model.Point{{TimeUnixNano: h.ts, Hist: &eh}},
	}
}

// expIndex returns the OTLP exponential bucket index for a positive value: the
// bucket i covers (base^i, base^(i+1)] with base = 2^(2^-scale).
func expIndex(v float64, scale int32) int32 {
	return int32(math.Ceil(math.Log2(v)*math.Exp2(float64(scale)))) - 1
}

// toExpHistogram converts classic cumulative le-buckets into an exponential
// histogram. The mapping is approximate by construction (bucket boundaries
// differ): each classic bucket's observation count is placed at the exponential
// bucket of its finite upper bound; the +Inf overflow folds into the top finite
// bucket; le<=0 counts go to ZeroCount.
func toExpHistogram(buckets map[float64]uint64, sum float64, count uint64, scale int32) model.ExpHistogram {
	les := make([]float64, 0, len(buckets))
	for le := range buckets {
		les = append(les, le)
	}
	sort.Float64s(les)

	idxCounts := make(map[int32]uint64)
	var (
		zero           uint64
		prev           uint64
		infDelta       uint64
		haveFinite     bool
		topFiniteIdx   int32 // exp index of the largest finite le boundary seen
		haveTopFinite  bool
		minIdx, maxIdx int32
	)
	for _, le := range les {
		cum := buckets[le]
		var delta uint64
		if cum > prev {
			delta = cum - prev
		}
		prev = cum
		switch {
		case math.IsInf(le, 1):
			infDelta = delta // folded in after the loop
		case le <= 0:
			zero += delta
		default:
			// les are sorted ascending, so the last finite le is the largest.
			topFiniteIdx = expIndex(le, scale)
			haveTopFinite = true
			if delta == 0 {
				continue
			}
			idx := topFiniteIdx
			idxCounts[idx] += delta
			if !haveFinite || idx < minIdx {
				minIdx = idx
			}
			if !haveFinite || idx > maxIdx {
				maxIdx = idx
			}
			haveFinite = true
		}
	}
	// Fold the +Inf overflow into the top finite bucket. Done after the loop so it
	// lands even when every finite bucket's delta was zero (all mass sits at or
	// above the largest bound) - otherwise those observations would vanish from
	// the buckets while still counted in Count.
	if infDelta > 0 && haveTopFinite {
		idxCounts[topFiniteIdx] += infDelta
		if !haveFinite || topFiniteIdx < minIdx {
			minIdx = topFiniteIdx
		}
		if !haveFinite || topFiniteIdx > maxIdx {
			maxIdx = topFiniteIdx
		}
		haveFinite = true
	}

	eh := model.ExpHistogram{Scale: scale, ZeroCount: zero, Sum: sum, Count: count}
	if haveFinite {
		eh.PositiveOffset = minIdx
		eh.PositiveCounts = make([]uint64, maxIdx-minIdx+1)
		for idx, c := range idxCounts {
			eh.PositiveCounts[idx-minIdx] = c
		}
	}
	return eh
}
