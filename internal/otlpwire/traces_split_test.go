package otlpwire

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

func TestForEachTracesChunkKeepsCompleteTracesAndMetadata(t *testing.T) {
	firstTrace := bytes.Repeat([]byte{0x11}, 16)
	secondTrace := bytes.Repeat([]byte{0x22}, 16)
	thirdTrace := bytes.Repeat([]byte{0x33}, 16)
	request := &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{
			traceResource("checkout", "http", []*tracepb.Span{
				traceSpan(firstTrace, 1, 180),
				traceSpan(secondTrace, 2, 180),
			}),
			traceResource("payments", "db", []*tracepb.Span{
				traceSpan(firstTrace, 3, 180),
				traceSpan(thirdTrace, 4, 180),
			}),
		},
	}
	request.ProtoReflect().SetUnknown([]byte{0x78, 0x01})
	request.ResourceSpans[0].ProtoReflect().
		SetUnknown([]byte{0x78, 0x02})
	request.ResourceSpans[0].ScopeSpans[0].ProtoReflect().
		SetUnknown([]byte{0x78, 0x03})
	before := proto.Clone(request)

	units := collectTraceUnits(request)
	maxUnit := 0
	for _, unit := range units {
		size := proto.Size(materializeTraceUnit(unit))
		if size > maxUnit {
			maxUnit = size
		}
	}
	limit := maxUnit + len(request.ProtoReflect().GetUnknown())
	var chunks []TracesChunk
	result, err := ForEachTracesChunk(
		request,
		limit,
		func(chunk TracesChunk) error {
			if size := proto.Size(chunk.Request); size > limit {
				t.Fatalf(
					"chunk=%d size=%d limit=%d",
					chunk.Index,
					size,
					limit,
				)
			}
			chunks = append(chunks, chunk)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.RejectedSpans != 0 ||
		result.RejectedTraces != 0 ||
		result.Chunks != len(chunks) ||
		len(chunks) < 2 {
		t.Fatalf("result=%+v chunks=%d", result, len(chunks))
	}

	traceChunk := make(map[string]int)
	var firstSeen []string
	unknownChunks := 0
	associations := make(map[string]map[string]struct{})
	for chunkIndex, chunk := range chunks {
		if len(chunk.Request.ProtoReflect().GetUnknown()) > 0 {
			unknownChunks++
		}
		for _, resource := range chunk.Request.ResourceSpans {
			service := resource.Resource.Attributes[0].Value.
				GetStringValue()
			scope := resource.ScopeSpans[0]
			if service == "checkout" {
				if !bytes.Equal(
					resource.ProtoReflect().GetUnknown(),
					[]byte{0x78, 0x02},
				) || !bytes.Equal(
					scope.ProtoReflect().GetUnknown(),
					[]byte{0x78, 0x03},
				) {
					t.Fatal("nested unknown fields were lost")
				}
			}
			for _, span := range scope.Spans {
				key := string(span.TraceId)
				previous, exists := traceChunk[key]
				if exists && previous != chunkIndex {
					t.Fatalf("trace split across chunks: %x", span.TraceId)
				}
				if !exists {
					traceChunk[key] = chunkIndex
					firstSeen = append(firstSeen, key)
				}
				if associations[key] == nil {
					associations[key] = make(map[string]struct{})
				}
				associations[key][service+"/"+scope.SchemaUrl] =
					struct{}{}
			}
		}
	}
	if unknownChunks != 1 {
		t.Fatalf("request unknown field chunks=%d", unknownChunks)
	}
	if len(firstSeen) != 3 ||
		firstSeen[0] != string(firstTrace) ||
		firstSeen[1] != string(secondTrace) ||
		firstSeen[2] != string(thirdTrace) {
		t.Fatalf("first-seen order=%x", firstSeen)
	}
	if len(associations[string(firstTrace)]) != 2 {
		t.Fatalf(
			"cross-resource trace associations=%v",
			associations[string(firstTrace)],
		)
	}
	if !proto.Equal(request, before) {
		t.Fatal("splitter mutated input")
	}
}

func TestForEachTracesChunkRejectsOversizedTraceWithoutBlockingOthers(
	t *testing.T,
) {
	largeID := bytes.Repeat([]byte{0x44}, 16)
	smallID := bytes.Repeat([]byte{0x55}, 16)
	largeSpans := make([]*tracepb.Span, 0, 4)
	for index := range 4 {
		largeSpans = append(
			largeSpans,
			traceSpan(largeID, byte(index+1), 512),
		)
	}
	request := &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{
			traceResource("large", "scope", largeSpans),
			traceResource("small", "scope", []*tracepb.Span{
				traceSpan(smallID, 9, 16),
			}),
		},
	}
	units := collectTraceUnits(request)
	largeSize := proto.Size(materializeTraceUnit(units[0]))
	smallSize := proto.Size(materializeTraceUnit(units[1]))
	if largeSize <= smallSize {
		t.Fatalf("large=%d small=%d", largeSize, smallSize)
	}
	limit := smallSize
	analysis, err := AnalyzeTraces(request, limit)
	if err != nil {
		t.Fatal(err)
	}
	if analysis.RejectedTraces != 1 ||
		analysis.RejectedSpans != 4 ||
		analysis.Chunks != 1 {
		t.Fatalf("analysis=%+v", analysis)
	}
	var emitted []TracesChunk
	result, err := ForEachTracesChunk(
		request,
		limit,
		func(chunk TracesChunk) error {
			emitted = append(emitted, chunk)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.RejectedTraces != 1 ||
		result.RejectedSpans != 4 ||
		result.Chunks != 1 ||
		len(emitted) != 1 {
		t.Fatalf("result=%+v emitted=%d", result, len(emitted))
	}
	gotSpan := emitted[0].Request.ResourceSpans[0].
		ScopeSpans[0].Spans[0]
	if !bytes.Equal(gotSpan.TraceId, smallID) {
		t.Fatalf("emitted trace=%x want=%x", gotSpan.TraceId, smallID)
	}
}

func TestForEachTracesChunkPlacesUnknownFieldsOnFittingTrace(
	t *testing.T,
) {
	largeID := bytes.Repeat([]byte{0x66}, 16)
	smallID := bytes.Repeat([]byte{0x77}, 16)
	request := &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{
			traceResource("large", "scope", []*tracepb.Span{
				traceSpan(largeID, 1, 300),
			}),
			traceResource("small", "scope", []*tracepb.Span{
				traceSpan(smallID, 2, 8),
			}),
		},
	}
	unknown := bytes.Repeat([]byte{0x78, 0x01}, 40)
	request.ProtoReflect().SetUnknown(unknown)
	units := collectTraceUnits(request)
	largeSize := proto.Size(materializeTraceUnit(units[0]))
	smallSize := proto.Size(materializeTraceUnit(units[1]))
	if smallSize+len(unknown) > largeSize ||
		largeSize+len(unknown) <= largeSize {
		t.Fatalf(
			"test sizes large=%d small=%d unknown=%d",
			largeSize,
			smallSize,
			len(unknown),
		)
	}

	var chunks []TracesChunk
	_, err := ForEachTracesChunk(
		request,
		largeSize,
		func(chunk TracesChunk) error {
			chunks = append(chunks, chunk)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 2 {
		t.Fatalf("chunks=%d", len(chunks))
	}
	if len(chunks[0].Request.ProtoReflect().GetUnknown()) != 0 ||
		!bytes.Equal(
			chunks[1].Request.ProtoReflect().GetUnknown(),
			unknown,
		) {
		t.Fatal("request unknown fields were not placed on the fitting chunk")
	}
}

func TestForEachTracesChunkRejectsUnplaceableRequestMetadataBeforeEmit(
	t *testing.T,
) {
	request := &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{
			traceResource("service", "scope", []*tracepb.Span{
				traceSpan(bytes.Repeat([]byte{0x88}, 16), 1, 16),
			}),
		},
	}
	request.ProtoReflect().SetUnknown(
		bytes.Repeat([]byte{0x78, 0x01}, 40),
	)
	unitSize := proto.Size(
		materializeTraceUnit(collectTraceUnits(request)[0]),
	)
	emitted := 0
	_, err := ForEachTracesChunk(
		request,
		unitSize,
		func(TracesChunk) error {
			emitted++
			return nil
		},
	)
	if !errors.Is(err, ErrTraceRequestMetadataTooLarge) {
		t.Fatalf("err=%v", err)
	}
	if emitted != 0 {
		t.Fatalf("emitted=%d", emitted)
	}
}

func TestForEachTracesChunkStopsAtEmitterFailure(t *testing.T) {
	request := traceBatchRequest(4, 128)
	units := collectTraceUnits(request)
	limit := proto.Size(materializeTraceUnit(units[0]))
	sentinel := errors.New("downstream")
	var indexes []int
	result, err := ForEachTracesChunk(
		request,
		limit,
		func(chunk TracesChunk) error {
			indexes = append(indexes, chunk.Index)
			if chunk.Index == 1 {
				return sentinel
			}
			return nil
		},
	)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
	if len(indexes) != 2 || result.Chunks != 1 {
		t.Fatalf("indexes=%v result=%+v", indexes, result)
	}
}

func TestForEachTracesChunkTreatsInvalidTraceIDsAsSeparateUnits(
	t *testing.T,
) {
	request := &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{
			traceResource("service", "scope", []*tracepb.Span{
				traceSpan(make([]byte, 16), 1, 8),
				traceSpan(make([]byte, 16), 2, 8),
			}),
		},
	}
	var got TracesChunk
	result, err := ForEachTracesChunk(
		request,
		MaxReceiverRequestBytes,
		func(chunk TracesChunk) error {
			got = chunk
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Chunks != 1 || got.Traces != 2 || got.Spans != 2 {
		t.Fatalf("result=%+v chunk=%+v", result, got)
	}
}

func TestForEachSelectedTracesChunkExcludesWholeTraceAndBypassesInvalid(
	t *testing.T,
) {
	keptID := bytes.Repeat([]byte{0x91}, 16)
	droppedID := bytes.Repeat([]byte{0x92}, 16)
	request := &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{
			traceResource("first", "scope-a", []*tracepb.Span{
				traceSpan(droppedID, 1, 8),
				traceSpan(keptID, 2, 8),
				traceSpan(make([]byte, 16), 3, 8),
			}),
			traceResource("second", "scope-b", []*tracepb.Span{
				traceSpan(droppedID, 4, 8),
				traceSpan(keptID, 5, 8),
			}),
		},
	}
	request.ProtoReflect().SetUnknown([]byte{0x78, 0x01})
	var selected []TraceSelectionUnit
	var chunks []TracesChunk
	result, err := ForEachSelectedTracesChunk(
		request,
		MaxReceiverRequestBytes,
		func(unit TraceSelectionUnit) bool {
			selected = append(selected, unit)
			return unit.TraceID == [16]byte{
				0x91, 0x91, 0x91, 0x91,
				0x91, 0x91, 0x91, 0x91,
				0x91, 0x91, 0x91, 0x91,
				0x91, 0x91, 0x91, 0x91,
			}
		},
		func(chunk TracesChunk) error {
			chunks = append(chunks, chunk)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 2 ||
		result.SelectedTraces != 1 ||
		result.SelectedSpans != 2 ||
		result.ExcludedTraces != 1 ||
		result.ExcludedSpans != 2 ||
		result.BypassedInvalidTraces != 1 ||
		result.BypassedInvalidSpans != 1 ||
		result.Chunks != 1 ||
		len(chunks) != 1 {
		t.Fatalf(
			"selected=%+v result=%+v chunks=%d",
			selected,
			result,
			len(chunks),
		)
	}
	if !bytes.Equal(
		chunks[0].Request.ProtoReflect().GetUnknown(),
		[]byte{0x78, 0x01},
	) {
		t.Fatal("request unknown fields were not retained")
	}
	for _, resource := range chunks[0].Request.ResourceSpans {
		for _, scope := range resource.ScopeSpans {
			for _, span := range scope.Spans {
				if bytes.Equal(span.TraceId, droppedID) {
					t.Fatal("excluded trace was emitted")
				}
			}
		}
	}
}

func TestForEachSelectedTracesChunkCanExcludeEverything(
	t *testing.T,
) {
	request := traceBatchRequest(2, 8)
	request.ProtoReflect().SetUnknown(
		bytes.Repeat([]byte{0x78, 0x01}, 40),
	)
	result, err := ForEachSelectedTracesChunk(
		request,
		64,
		func(TraceSelectionUnit) bool { return false },
		func(TracesChunk) error {
			t.Fatal("fully excluded request emitted")
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExcludedTraces != 2 ||
		result.ExcludedSpans != 2 ||
		result.Chunks != 0 {
		t.Fatalf("result=%+v", result)
	}
}

func FuzzForEachTracesChunk(f *testing.F) {
	seed, _ := proto.Marshal(traceBatchRequest(6, 64))
	f.Add(seed, uint16(512))
	f.Add([]byte{0x0a, 0x00}, uint16(128))
	f.Fuzz(func(t *testing.T, data []byte, rawLimit uint16) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		var request coltracepb.ExportTraceServiceRequest
		if err := proto.Unmarshal(data, &request); err != nil {
			return
		}
		limit := int(rawLimit%8192) + 64
		emittedSpans := 0
		traceChunks := make(map[string]int)
		result, err := ForEachTracesChunk(
			&request,
			limit,
			func(chunk TracesChunk) error {
				if size := proto.Size(chunk.Request); size > limit {
					t.Fatalf(
						"chunk size=%d limit=%d",
						size,
						limit,
					)
				}
				emittedSpans += chunk.Spans
				for _, resource := range chunk.Request.ResourceSpans {
					if resource == nil {
						continue
					}
					for _, scope := range resource.ScopeSpans {
						if scope == nil {
							continue
						}
						for _, span := range scope.Spans {
							if span == nil ||
								!validWireTraceID(span.TraceId) {
								continue
							}
							key := string(span.TraceId)
							if previous, exists := traceChunks[key]; exists && previous != chunk.Index {
								t.Fatal("trace split across chunks")
							}
							traceChunks[key] = chunk.Index
						}
					}
				}
				return nil
			},
		)
		if err == nil &&
			emittedSpans+result.RejectedSpans !=
				TraceSpanCount(&request) {
			t.Fatalf(
				"emitted=%d rejected=%d want=%d",
				emittedSpans,
				result.RejectedSpans,
				TraceSpanCount(&request),
			)
		}
		if err != nil &&
			!errors.Is(err, ErrTraceRequestMetadataTooLarge) {
			t.Fatalf("unexpected err=%v", err)
		}

		selectedEmittedSpans := 0
		selectedResult, selectedErr :=
			ForEachSelectedTracesChunk(
				&request,
				limit,
				func(unit TraceSelectionUnit) bool {
					return unit.TraceID[15]&1 == 0
				},
				func(chunk TracesChunk) error {
					if size := proto.Size(chunk.Request); size > limit {
						t.Fatalf(
							"selected chunk size=%d limit=%d",
							size,
							limit,
						)
					}
					selectedEmittedSpans += chunk.Spans
					return nil
				},
			)
		if selectedErr == nil &&
			selectedEmittedSpans+
				selectedResult.RejectedSpans+
				selectedResult.ExcludedSpans !=
				TraceSpanCount(&request) {
			t.Fatalf(
				"selected emitted=%d rejected=%d "+
					"excluded=%d want=%d",
				selectedEmittedSpans,
				selectedResult.RejectedSpans,
				selectedResult.ExcludedSpans,
				TraceSpanCount(&request),
			)
		}
		if selectedErr != nil &&
			!errors.Is(
				selectedErr,
				ErrTraceRequestMetadataTooLarge,
			) {
			t.Fatalf(
				"unexpected selected err=%v",
				selectedErr,
			)
		}
	})
}

func traceBatchRequest(traces, bodyBytes int) *coltracepb.ExportTraceServiceRequest {
	spans := make([]*tracepb.Span, 0, traces)
	for index := range traces {
		traceID := bytes.Repeat([]byte{byte(index + 1)}, 16)
		spans = append(
			spans,
			traceSpan(traceID, byte(index+1), bodyBytes),
		)
	}
	return &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{
			traceResource("service", "scope", spans),
		},
	}
}

func traceResource(
	service string,
	scope string,
	spans []*tracepb.Span,
) *tracepb.ResourceSpans {
	return &tracepb.ResourceSpans{
		Resource: &resourcepb.Resource{
			Attributes: []*commonpb.KeyValue{{
				Key: "service.name",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_StringValue{
						StringValue: service,
					},
				},
			}},
		},
		SchemaUrl: service + "-schema",
		ScopeSpans: []*tracepb.ScopeSpans{{
			Scope: &commonpb.InstrumentationScope{
				Name: scope,
			},
			SchemaUrl: scope,
			Spans:     spans,
		}},
	}
}

func traceSpan(
	traceID []byte,
	spanByte byte,
	bodyBytes int,
) *tracepb.Span {
	return &tracepb.Span{
		TraceId:           traceID,
		SpanId:            bytes.Repeat([]byte{spanByte}, 8),
		Name:              fmt.Sprintf("span-%d", spanByte),
		StartTimeUnixNano: 1,
		EndTimeUnixNano:   2,
		Attributes: []*commonpb.KeyValue{{
			Key: "payload",
			Value: &commonpb.AnyValue{
				Value: &commonpb.AnyValue_StringValue{
					StringValue: strings.Repeat("x", bodyBytes),
				},
			},
		}},
	}
}
