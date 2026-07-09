// Package model defines wisp's internal metric representation. It is the
// producer-side mirror of amber's metric model and maps 1:1 onto OTLP at
// export time (see the wisp/coral/amber metric contract): four metric types, label sets that
// become resource.*/scope.*/point attributes downstream, and a scalar value
// that is either an exact int64 or a float bounded by the scaled-int64 model.
package model

import (
	"encoding/binary"
	"math"
	"sort"
	"strings"
)

// MetricType is the instrument kind of a series. Values match the OTLP->amber
// mapping in the wisp/coral/amber metric contract.
type MetricType uint8

const (
	// MetricGauge is an instantaneous value (OTLP Gauge -> amber gauge).
	MetricGauge MetricType = iota + 1
	// MetricSum is a counter (OTLP Sum -> amber counter). v0 is cumulative;
	// monotonicity is carried by Series.Monotonic.
	MetricSum
	// MetricHistogram is an explicit-bounds histogram.
	MetricHistogram
	// MetricExponentialHistogram is the preferred histogram shape: amber's
	// engine is built around it.
	MetricExponentialHistogram
)

func (t MetricType) String() string {
	switch t {
	case MetricGauge:
		return "gauge"
	case MetricSum:
		return "sum"
	case MetricHistogram:
		return "histogram"
	case MetricExponentialHistogram:
		return "exponential_histogram"
	default:
		return "unknown"
	}
}

// Label is a single name/value pair.
type Label struct {
	Name  string
	Value string
}

// Labels is an unordered set of labels; canonicalization happens at export.
type Labels []Label

// Get returns the value of the first label named name, if present.
func (ls Labels) Get(name string) (string, bool) {
	for _, l := range ls {
		if l.Name == name {
			return l.Value, true
		}
	}
	return "", false
}

// Filter returns the labels whose names satisfy keep, as a new slice (keep is
// evaluated once per label).
func (ls Labels) Filter(keep func(name string) bool) Labels {
	out := make(Labels, 0, len(ls))
	for _, l := range ls {
		if keep(l.Name) {
			out = append(out, l)
		}
	}
	return out
}

// ExpHistogram is a base-2 exponential histogram payload, mirroring OTLP's
// ExponentialHistogramDataPoint. wisp produces these (including from classic
// Prometheus histograms) because amber's histogram engine is built around them.
type ExpHistogram struct {
	Scale          int32
	ZeroCount      uint64
	PositiveOffset int32
	PositiveCounts []uint64
	Sum            float64
	Count          uint64
}

// Point is one data point. For gauges/counters the scalar fields apply: counters
// and gauges prefer IsFloat=false so they survive amber's int64 value model
// exactly; floats carry 3 decimal digits (scale 1000). For an exponential
// histogram series, Hist is set instead and the scalar fields are unused.
type Point struct {
	TimeUnixNano uint64
	IntValue     int64
	FloatValue   float64
	IsFloat      bool
	Hist         *ExpHistogram
}

// Value returns the point's scalar as a float64, regardless of the int/float
// storage path.
func (p Point) Value() float64 {
	if p.IsFloat {
		return p.FloatValue
	}
	return float64(p.IntValue)
}

// SetValue writes a fresh scalar, keeping the exact int64 path when v is integral
// and within range (amber stores integer counters/gauges without a scale factor;
// see the type doc). Callers that must preserve an existing float point should
// guard on IsFloat before calling.
func (p *Point) SetValue(v float64) {
	if v == math.Trunc(v) && math.Abs(v) < 9.2e18 {
		p.IntValue = int64(v)
		p.FloatValue = 0
		p.IsFloat = false
		return
	}
	p.FloatValue = v
	p.IntValue = 0
	p.IsFloat = true
}

// Series is a metric identity (name + resource + point attributes) plus its
// points. Resource attributes become resource.* labels in amber; Attrs become
// unprefixed point labels.
type Series struct {
	Name      string
	Unit      string
	Type      MetricType
	Monotonic bool
	Resource  Labels
	Attrs     Labels
	Points    []Point
}

// Batch is the unit that flows through the pipeline.
type Batch struct {
	Series []Series
}

// Len reports the number of data points in the batch (not series), the unit
// most rate/throughput accounting cares about.
func (b Batch) Len() int {
	n := 0
	for i := range b.Series {
		n += len(b.Series[i].Points)
	}
	return n
}

// CanonicalKey renders a label set as a stable string key, independent of input
// order: labels are sorted by name (then value) and each name/value is written
// length-prefixed. The length prefixes make the encoding injective, so no
// attribute value (even one containing '=' or NUL from an untrusted OTLP client)
// can forge a delimiter and collide with a different label set. Used wherever a
// label set needs a map key or identity (series fingerprints, resource grouping).
func CanonicalKey(labels Labels) string {
	sorted := append(Labels(nil), labels...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Name == sorted[j].Name {
			return sorted[i].Value < sorted[j].Value
		}
		return sorted[i].Name < sorted[j].Name
	})
	var b strings.Builder
	var num [binary.MaxVarintLen64]byte
	writeLenPrefixed := func(s string) {
		n := binary.PutUvarint(num[:], uint64(len(s)))
		b.Write(num[:n])
		b.WriteString(s)
	}
	for _, l := range sorted {
		writeLenPrefixed(l.Name)
		writeLenPrefixed(l.Value)
	}
	return b.String()
}
