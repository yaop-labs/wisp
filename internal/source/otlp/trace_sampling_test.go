package otlp

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/fnv"
	"math"
	"testing"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/yaop-labs/wisp/internal/otlpwire"
	"github.com/yaop-labs/wisp/internal/selfobs"
	"github.com/yaop-labs/wisp/internal/signal"
)

func TestTraceSamplingHashMatchesCollectorHashSeedAlgorithm(
	t *testing.T,
) {
	for _, seed := range []uint32{0, 1, 42, math.MaxUint32} {
		for _, fill := range []byte{0, 1, 0x7f, 0xff} {
			var traceID [16]byte
			for index := range traceID {
				traceID[index] = fill + byte(index)
			}
			hash := fnv.New32a()
			var seedBytes [4]byte
			binary.LittleEndian.PutUint32(seedBytes[:], seed)
			_, _ = hash.Write(seedBytes[:])
			_, _ = hash.Write(traceID[:])
			if got, want := traceSamplingHash(
				traceID,
				seed,
			), hash.Sum32(); got != want {
				t.Fatalf(
					"seed=%d trace=%x hash=%08x want=%08x",
					seed,
					traceID,
					got,
					want,
				)
			}
		}
	}
}

func TestTraceSamplingDecisionsAreNestedAndDeterministic(
	t *testing.T,
) {
	ten := mustTraceSampling(t, 10, 73)
	fifty := mustTraceSampling(t, 50, 73)
	zero := mustTraceSampling(t, 0, 73)
	all := mustTraceSampling(t, 100, 73)
	tenKept := 0
	fiftyKept := 0
	for index := range 1 << 16 {
		var traceID [16]byte
		binary.BigEndian.PutUint64(
			traceID[8:],
			uint64(index+1),
		)
		unit := otlpwire.TraceSelectionUnit{
			TraceID: traceID,
			Spans:   1,
		}
		first := ten.selectTrace(unit)
		if first != ten.selectTrace(unit) {
			t.Fatal("same trace ID received different decisions")
		}
		if first {
			tenKept++
			if !fifty.selectTrace(unit) {
				t.Fatal("10% selection was not a subset of 50%")
			}
		}
		if fifty.selectTrace(unit) {
			fiftyKept++
		}
		if zero.selectTrace(unit) {
			t.Fatal("zero percent selected a trace")
		}
		if !all.selectTrace(unit) {
			t.Fatal("100 percent excluded a trace")
		}
	}
	if tenKept < 6000 || tenKept > 7100 ||
		fiftyKept < 32000 || fiftyKept > 33500 {
		t.Fatalf(
			"unexpected deterministic distribution: "+
				"10%%=%d 50%%=%d",
			tenKept,
			fiftyKept,
		)
	}
}

func TestTraceSamplingDropsCompleteTraceWithoutPartialSuccess(
	t *testing.T,
) {
	percentage := float32(0)
	processing := mustTraceProcessing(t, TraceOptions{
		SamplingMode:       TraceSamplingHashSeed,
		SamplingPercentage: &percentage,
		SamplingHashSeed:   9,
	})
	request := receiverTraceBatch(2, 64)
	before := proto.Clone(request)
	emitted := 0
	receiver := &Receiver{
		traceProcessing:      processing,
		maxTraceRequestBytes: 64,
		tracesEmit: func(
			context.Context,
			signal.Envelope,
		) error {
			emitted++
			return nil
		},
	}
	droppedBefore := selfobs.OTLPTraceSamplingDroppedSpans.Get()
	response, err := (&grpcTracesService{r: receiver}).Export(
		context.Background(),
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if response.GetPartialSuccess() != nil {
		t.Fatalf("sampling reported partial success: %v", response)
	}
	if emitted != 0 {
		t.Fatalf("emitted envelopes=%d", emitted)
	}
	if delta := selfobs.OTLPTraceSamplingDroppedSpans.Get() -
		droppedBefore; delta != 2 {
		t.Fatalf("sampled-out span delta=%d", delta)
	}
	if !proto.Equal(request, before) {
		t.Fatal("sampling mutated the input request")
	}
}

func TestTraceSamplingPreservesInvalidTraceIDsFailOpen(
	t *testing.T,
) {
	percentage := float32(0)
	processing := mustTraceProcessing(t, TraceOptions{
		Validation:         TraceValidationReport,
		SamplingMode:       TraceSamplingHashSeed,
		SamplingPercentage: &percentage,
	})
	request := receiverTraceBatch(1, 8)
	request.ResourceSpans[0].ScopeSpans[0].Spans[0].
		TraceId = make([]byte, 16)
	var emitted coltracepb.ExportTraceServiceRequest
	receiver := &Receiver{
		traceProcessing: processing,
		tracesEmit: func(
			_ context.Context,
			envelope signal.Envelope,
		) error {
			return proto.Unmarshal(
				envelope.Payload,
				&emitted,
			)
		},
	}
	result, err := receiver.ingestTracesResult(
		context.Background(),
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.rejectedSpans != 0 ||
		len(emitted.ResourceSpans) != 1 ||
		!bytes.Equal(
			emitted.ResourceSpans[0].ScopeSpans[0].
				Spans[0].TraceId,
			make([]byte, 16),
		) {
		t.Fatalf(
			"result=%+v emitted=%v",
			result,
			&emitted,
		)
	}
}

func TestTraceSamplingSelectionKeepsAllFragmentsOfChosenTrace(
	t *testing.T,
) {
	percentage := float32(50)
	processing := mustTraceProcessing(t, TraceOptions{
		SamplingMode:       TraceSamplingHashSeed,
		SamplingPercentage: &percentage,
		SamplingHashSeed:   17,
	})
	keptID, droppedID := samplingIDs(t, processing.sampling)
	request := &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{
			samplingTraceResource("scope-a", []*tracepb.Span{
				receiverTraceSpan(droppedID[:], 1, 8),
				receiverTraceSpan(keptID[:], 2, 8),
			}),
			samplingTraceResource("scope-b", []*tracepb.Span{
				receiverTraceSpan(droppedID[:], 3, 8),
				receiverTraceSpan(keptID[:], 4, 8),
			}),
		},
	}
	var envelopes []signal.Envelope
	receiver := &Receiver{
		traceProcessing: processing,
		tracesEmit: func(
			_ context.Context,
			envelope signal.Envelope,
		) error {
			envelopes = append(envelopes, envelope)
			return nil
		},
	}
	if err := receiver.ingestTraces(
		context.Background(),
		request,
	); err != nil {
		t.Fatal(err)
	}
	if len(envelopes) != 1 {
		t.Fatalf("envelopes=%d", len(envelopes))
	}
	var output coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(
		envelopes[0].Payload,
		&output,
	); err != nil {
		t.Fatal(err)
	}
	if got := otlpwire.TraceSpanCount(&output); got != 2 {
		t.Fatalf("output spans=%d", got)
	}
	for _, resource := range output.ResourceSpans {
		for _, scope := range resource.ScopeSpans {
			for _, span := range scope.Spans {
				if !bytes.Equal(span.TraceId, keptID[:]) {
					t.Fatalf(
						"unexpected trace emitted: %x",
						span.TraceId,
					)
				}
			}
		}
	}
}

func samplingTraceResource(
	scope string,
	spans []*tracepb.Span,
) *tracepb.ResourceSpans {
	return &tracepb.ResourceSpans{
		ScopeSpans: []*tracepb.ScopeSpans{{
			SchemaUrl: scope,
			Spans:     spans,
		}},
	}
}

func mustTraceSampling(
	t *testing.T,
	percentage float32,
	seed uint32,
) traceSampling {
	t.Helper()
	sampling, err := newTraceSampling(TraceOptions{
		SamplingMode:       TraceSamplingHashSeed,
		SamplingPercentage: &percentage,
		SamplingHashSeed:   seed,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sampling
}

func samplingIDs(
	t *testing.T,
	sampling traceSampling,
) (kept [16]byte, dropped [16]byte) {
	t.Helper()
	for value := uint64(1); value < 1<<20; value++ {
		var traceID [16]byte
		binary.BigEndian.PutUint64(traceID[8:], value)
		if sampling.selectTrace(otlpwire.TraceSelectionUnit{
			TraceID: traceID,
			Spans:   1,
		}) {
			if kept == [16]byte{} {
				kept = traceID
			}
		} else if dropped == [16]byte{} {
			dropped = traceID
		}
		if kept != [16]byte{} && dropped != [16]byte{} {
			return kept, dropped
		}
	}
	t.Fatal("could not find deterministic sampling decisions")
	return kept, dropped
}
