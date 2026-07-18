package otlp

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/yaop-labs/wisp/internal/otlpwire"
)

const (
	TraceSamplingHashSeed = "hash_seed"

	traceSamplingHashBuckets = uint32(1 << 14)
	fnv32OffsetBasis         = uint32(2166136261)
	fnv32Prime               = uint32(16777619)
)

// traceSampling is a stateless whole-trace admission gate. Its selection
// calculation matches the OpenTelemetry Collector hash_seed mode, while Wisp
// applies the decision once per complete trace unit instead of per span.
type traceSampling struct {
	enabled   bool
	hashSeed  uint32
	threshold uint32
}

func newTraceSampling(options TraceOptions) (traceSampling, error) {
	configured := options.SamplingMode != "" ||
		options.SamplingPercentage != nil ||
		options.SamplingHashSeed != 0
	if !configured {
		return traceSampling{}, nil
	}
	if options.SamplingMode != TraceSamplingHashSeed {
		return traceSampling{}, fmt.Errorf(
			"otlp traces: sampling mode must be hash_seed",
		)
	}
	if options.SamplingPercentage == nil {
		return traceSampling{}, fmt.Errorf(
			"otlp traces: sampling percentage is required",
		)
	}
	percentage := *options.SamplingPercentage
	if math.IsNaN(float64(percentage)) ||
		math.IsInf(float64(percentage), 0) ||
		percentage < 0 ||
		percentage > 100 {
		return traceSampling{}, fmt.Errorf(
			"otlp traces: sampling percentage must be between 0 and 100",
		)
	}
	threshold := uint32(
		percentage *
			(float32(traceSamplingHashBuckets) / 100),
	)
	if percentage > 0 && threshold == 0 {
		return traceSampling{}, fmt.Errorf(
			"otlp traces: sampling percentage is below hash_seed resolution",
		)
	}
	return traceSampling{
		enabled:   true,
		hashSeed:  options.SamplingHashSeed,
		threshold: threshold,
	}, nil
}

func (s traceSampling) selectTrace(
	unit otlpwire.TraceSelectionUnit,
) bool {
	if s.threshold == 0 {
		return false
	}
	if s.threshold >= traceSamplingHashBuckets {
		return true
	}
	return traceSamplingHash(unit.TraceID, s.hashSeed)&
		(traceSamplingHashBuckets-1) < s.threshold
}

func traceSamplingHash(traceID [16]byte, seed uint32) uint32 {
	hash := fnv32OffsetBasis
	var seedBytes [4]byte
	binary.LittleEndian.PutUint32(seedBytes[:], seed)
	for _, value := range seedBytes {
		hash ^= uint32(value)
		hash *= fnv32Prime
	}
	for _, value := range traceID {
		hash ^= uint32(value)
		hash *= fnv32Prime
	}
	return hash
}
