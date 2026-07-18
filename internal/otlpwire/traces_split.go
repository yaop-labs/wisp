package otlpwire

import (
	"bytes"
	"errors"
	"fmt"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// ErrTraceRequestMetadataTooLarge means request-level protobuf fields cannot be
// retained in any bounded trace chunk. No chunk is emitted in this case.
var ErrTraceRequestMetadataTooLarge = errors.New(
	"otlp traces: request metadata exceed the request limit",
)

// TracesChunk is one bounded request containing complete traces in first-seen
// order. One trace ID is never split across chunks.
type TracesChunk struct {
	Request *coltracepb.ExportTraceServiceRequest
	Index   int
	Traces  int
	Spans   int
}

// TracesSplitResult reports planned chunks from AnalyzeTraces or successfully
// emitted chunks from ForEachTracesChunk, plus traces that could not fit as an
// indivisible unit.
type TracesSplitResult struct {
	Chunks         int
	RejectedTraces int
	RejectedSpans  int
}

type traceSpanReference struct {
	resource      *tracepb.ResourceSpans
	scope         *tracepb.ScopeSpans
	span          *tracepb.Span
	resourceIndex int
	scopeIndex    int
}

type traceUnit struct {
	references []traceSpanReference
	spans      int
	size       int
}

type acceptedTraceUnit struct {
	index int
	size  int
	spans int
}

type tracesChunkPlan struct {
	units   []acceptedTraceUnit
	size    int
	spans   int
	unknown bool
}

type preparedTracesChunks struct {
	direct   *coltracepb.ExportTraceServiceRequest
	units    []traceUnit
	plans    []tracesChunkPlan
	unknown  []byte
	traces   int
	spans    int
	maxBytes int
	result   TracesSplitResult
}

// AnalyzeTraces reports the bounded split outcome without emitting anything.
// Exporters use this preflight to reject incompatible legacy envelopes before
// partially delivering their smaller traces.
func AnalyzeTraces(
	request *coltracepb.ExportTraceServiceRequest,
	maxBytes int,
) (TracesSplitResult, error) {
	prepared, err := prepareTracesChunks(request, maxBytes)
	if err != nil {
		return prepared.result, err
	}
	result := prepared.result
	if prepared.direct != nil {
		result.Chunks = 1
	} else {
		result.Chunks = len(prepared.plans)
	}
	return result, nil
}

// ForEachTracesChunk groups spans by trace ID across ResourceSpans and
// ScopeSpans boundaries, then emits bounded requests without splitting a
// trace. An invalid trace ID is treated as a separate indivisible unit so
// report-mode validation can remain lossless. Oversized units are skipped and
// counted in the result; request-level unknown fields are retained on exactly
// one chunk. The input is never mutated.
func ForEachTracesChunk(
	request *coltracepb.ExportTraceServiceRequest,
	maxBytes int,
	emit func(TracesChunk) error,
) (TracesSplitResult, error) {
	prepared, err := prepareTracesChunks(request, maxBytes)
	result := prepared.result
	if err != nil {
		return result, err
	}
	if prepared.direct != nil {
		err := emit(TracesChunk{
			Request: prepared.direct,
			Traces:  prepared.traces,
			Spans:   prepared.spans,
		})
		if err == nil {
			result.Chunks = 1
		}
		return result, err
	}
	for index, plan := range prepared.plans {
		chunkRequest := &coltracepb.ExportTraceServiceRequest{}
		if plan.unknown {
			chunkRequest.ProtoReflect().SetUnknown(prepared.unknown)
		}
		for _, plannedUnit := range plan.units {
			unitRequest := materializeTraceUnit(
				prepared.units[plannedUnit.index],
			)
			chunkRequest.ResourceSpans = append(
				chunkRequest.ResourceSpans,
				unitRequest.ResourceSpans...,
			)
		}
		if size := proto.Size(chunkRequest); size > prepared.maxBytes {
			return result, fmt.Errorf(
				"otlp traces: internal chunk bound violation: "+
					"chunk=%d size=%d limit=%d",
				index,
				size,
				prepared.maxBytes,
			)
		}
		if err := emit(TracesChunk{
			Request: chunkRequest,
			Index:   index,
			Traces:  len(plan.units),
			Spans:   plan.spans,
		}); err != nil {
			return result, err
		}
		result.Chunks++
	}
	return result, nil
}

func prepareTracesChunks(
	request *coltracepb.ExportTraceServiceRequest,
	maxBytes int,
) (preparedTracesChunks, error) {
	var prepared preparedTracesChunks
	if request == nil {
		return prepared, nil
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxRequestBytes
	}
	prepared.maxBytes = maxBytes
	prepared.units = collectTraceUnits(request)
	if len(prepared.units) == 0 {
		return prepared, nil
	}
	prepared.traces = len(prepared.units)
	prepared.spans = TraceSpanCount(request)
	if proto.Size(request) <= maxBytes {
		prepared.direct = request
		return prepared, nil
	}
	accepted := make(
		[]acceptedTraceUnit,
		0,
		len(prepared.units),
	)
	for index := range prepared.units {
		unitRequest := materializeTraceUnit(prepared.units[index])
		prepared.units[index].size = proto.Size(unitRequest)
		if prepared.units[index].size > maxBytes {
			prepared.result.RejectedTraces++
			prepared.result.RejectedSpans += prepared.units[index].spans
			continue
		}
		accepted = append(accepted, acceptedTraceUnit{
			index: index,
			size:  prepared.units[index].size,
			spans: prepared.units[index].spans,
		})
	}

	prepared.unknown = bytes.Clone(request.ProtoReflect().GetUnknown())
	unknownSize := len(prepared.unknown)
	if len(accepted) == 0 {
		if unknownSize > 0 {
			return prepared, fmt.Errorf(
				"%w: metadata=%d limit=%d",
				ErrTraceRequestMetadataTooLarge,
				unknownSize,
				maxBytes,
			)
		}
		return prepared, nil
	}

	unknownUnit := -1
	if unknownSize > 0 {
		for index, unit := range accepted {
			if unit.size+unknownSize <= maxBytes {
				unknownUnit = index
				break
			}
		}
		if unknownUnit < 0 {
			return prepared, fmt.Errorf(
				"%w: metadata=%d limit=%d",
				ErrTraceRequestMetadataTooLarge,
				unknownSize,
				maxBytes,
			)
		}
	}

	prepared.plans = planTraceChunks(
		accepted,
		maxBytes,
		unknownSize,
		unknownUnit,
	)
	return prepared, nil
}

func planTraceChunks(
	units []acceptedTraceUnit,
	maxBytes int,
	unknownSize int,
	unknownUnit int,
) []tracesChunkPlan {
	plans := make([]tracesChunkPlan, 0, len(units))
	var current *tracesChunkPlan
	capacity := maxBytes
	flush := func() {
		if current == nil {
			return
		}
		plans = append(plans, *current)
		current = nil
		capacity = maxBytes
	}
	for index, unit := range units {
		if index == unknownUnit {
			flush()
			current = &tracesChunkPlan{unknown: true}
			capacity = maxBytes - unknownSize
		}
		if current == nil {
			current = &tracesChunkPlan{}
		}
		if len(current.units) > 0 &&
			current.size+unit.size > capacity {
			flush()
			current = &tracesChunkPlan{}
		}
		current.units = append(current.units, unit)
		current.size += unit.size
		current.spans += unit.spans
	}
	flush()
	return plans
}

func collectTraceUnits(
	request *coltracepb.ExportTraceServiceRequest,
) []traceUnit {
	var units []traceUnit
	validUnits := make(map[string]int)
	for resourceIndex, resource := range request.ResourceSpans {
		if resource == nil {
			continue
		}
		for scopeIndex, scope := range resource.ScopeSpans {
			if scope == nil {
				continue
			}
			for _, span := range scope.Spans {
				var unitIndex int
				if span != nil && validWireTraceID(span.TraceId) {
					key := string(span.TraceId)
					var exists bool
					unitIndex, exists = validUnits[key]
					if !exists {
						unitIndex = len(units)
						validUnits[key] = unitIndex
						units = append(units, traceUnit{})
					}
				} else {
					unitIndex = len(units)
					units = append(units, traceUnit{})
				}
				units[unitIndex].references = append(
					units[unitIndex].references,
					traceSpanReference{
						resource:      resource,
						scope:         scope,
						span:          span,
						resourceIndex: resourceIndex,
						scopeIndex:    scopeIndex,
					},
				)
				units[unitIndex].spans++
			}
		}
	}
	return units
}

func materializeTraceUnit(
	unit traceUnit,
) *coltracepb.ExportTraceServiceRequest {
	request := &coltracepb.ExportTraceServiceRequest{}
	resourceIndex := -1
	scopeIndex := -1
	var resourceCopy *tracepb.ResourceSpans
	var scopeCopy *tracepb.ScopeSpans
	for _, reference := range unit.references {
		if reference.resourceIndex != resourceIndex {
			resourceCopy = cloneResourceSpansMetadata(
				reference.resource,
			)
			request.ResourceSpans = append(
				request.ResourceSpans,
				resourceCopy,
			)
			resourceIndex = reference.resourceIndex
			scopeIndex = -1
		}
		if reference.scopeIndex != scopeIndex {
			scopeCopy = cloneScopeSpansMetadata(reference.scope)
			resourceCopy.ScopeSpans = append(
				resourceCopy.ScopeSpans,
				scopeCopy,
			)
			scopeIndex = reference.scopeIndex
		}
		span := reference.span
		if span == nil {
			span = &tracepb.Span{}
		}
		scopeCopy.Spans = append(scopeCopy.Spans, span)
	}
	return request
}

func cloneResourceSpansMetadata(
	resource *tracepb.ResourceSpans,
) *tracepb.ResourceSpans {
	cloned := &tracepb.ResourceSpans{SchemaUrl: resource.SchemaUrl}
	cloned.ProtoReflect().SetUnknown(
		bytes.Clone(resource.ProtoReflect().GetUnknown()),
	)
	if resource.Resource != nil {
		cloned.Resource = proto.Clone(resource.Resource).(*resourcepb.Resource)
	}
	return cloned
}

func cloneScopeSpansMetadata(
	scope *tracepb.ScopeSpans,
) *tracepb.ScopeSpans {
	cloned := &tracepb.ScopeSpans{SchemaUrl: scope.SchemaUrl}
	cloned.ProtoReflect().SetUnknown(
		bytes.Clone(scope.ProtoReflect().GetUnknown()),
	)
	if scope.Scope != nil {
		cloned.Scope = proto.Clone(scope.Scope).(*commonpb.InstrumentationScope)
	}
	return cloned
}

func validWireTraceID(value []byte) bool {
	if len(value) != 16 {
		return false
	}
	for _, octet := range value {
		if octet != 0 {
			return true
		}
	}
	return false
}

// TraceSpanCount counts repeated span messages, including nil entries that
// protobuf encodes as empty span messages.
func TraceSpanCount(
	request *coltracepb.ExportTraceServiceRequest,
) int {
	if request == nil {
		return 0
	}
	count := 0
	for _, resource := range request.ResourceSpans {
		if resource == nil {
			continue
		}
		for _, scope := range resource.ScopeSpans {
			if scope != nil {
				count += len(scope.Spans)
			}
		}
	}
	return count
}
