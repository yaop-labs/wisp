package otlp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/yaop-labs/wisp/internal/otlpwire"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
	"github.com/yaop-labs/wisp/internal/signal"
)

func TestTraceCorrelationValidationFindsInvalidFields(t *testing.T) {
	request := sampleTracesRequest()
	span := request.ResourceSpans[0].ScopeSpans[0].Spans[0]
	span.TraceId = make([]byte, 16)
	span.SpanId = []byte{1}
	span.ParentSpanId = make([]byte, 8)
	span.Name = ""
	span.StartTimeUnixNano = 200
	span.EndTimeUnixNano = 100
	span.TraceState = "vendor=value,vendor=duplicate"
	span.Links = []*tracepb.Span_Link{{
		TraceId: bytes.Repeat([]byte{1}, 16),
		SpanId:  make([]byte, 8),
	}}

	report := validateTraceCorrelation(request)
	if report.spans != 1 ||
		report.invalidSpans != 1 ||
		report.invalidTraceIDs != 1 ||
		report.invalidSpanIDs != 1 ||
		report.invalidParentIDs != 1 ||
		report.invalidLinks != 1 ||
		report.invalidTraceStates != 1 ||
		report.missingNames != 1 ||
		report.invalidTimestamps != 1 {
		t.Fatalf("report=%+v", report)
	}
}

func TestTraceStateValidation(t *testing.T) {
	valid := []string{
		"",
		"rojo=00f067aa0ba902b7",
		"rojo=00f067aa0ba902b7, congo=t61rcWkgMzE",
		"tenant1@vendor=value",
		"\tfoo=bar\t,,vendor=a value",
	}
	for _, value := range valid {
		if !validTraceState(value) {
			t.Errorf("valid tracestate rejected: %q", value)
		}
	}

	tooMany := make([]string, 33)
	for index := range tooMany {
		tooMany[index] = "k" + strconv.Itoa(index) + "=v"
	}
	invalid := []string{
		"UPPER=value",
		"1simple=value",
		"tenant@1system=value",
		"vendor=",
		"vendor=bad=value",
		"vendor=value,vendor=duplicate",
		"vendor=bad\nvalue",
		strings.Join(tooMany, ","),
	}
	for _, value := range invalid {
		if validTraceState(value) {
			t.Errorf("invalid tracestate accepted: %q", value)
		}
	}
}

func TestTraceCorrelationValidationFindsDuplicatesAndCycles(t *testing.T) {
	traceID := bytes.Repeat([]byte{0x11}, 16)
	firstID := bytes.Repeat([]byte{0x21}, 8)
	secondID := bytes.Repeat([]byte{0x22}, 8)
	makeSpan := func(id, parent []byte) *tracepb.Span {
		return &tracepb.Span{
			TraceId: traceID, SpanId: id, ParentSpanId: parent,
			Name: "operation", StartTimeUnixNano: 1, EndTimeUnixNano: 2,
		}
	}
	request := &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			ScopeSpans: []*tracepb.ScopeSpans{{
				Spans: []*tracepb.Span{
					makeSpan(firstID, secondID),
					makeSpan(secondID, firstID),
				},
			}},
		}},
	}
	report := validateTraceCorrelation(request)
	if report.parentCycleSpans != 2 || report.invalidSpans != 2 {
		t.Fatalf("cycle report=%+v", report)
	}

	request.ResourceSpans[0].ScopeSpans[0].Spans = []*tracepb.Span{
		makeSpan(firstID, nil),
		makeSpan(firstID, nil),
	}
	report = validateTraceCorrelation(request)
	if report.duplicateSpanIDs != 1 || report.invalidSpans != 2 ||
		report.parentCycleSpans != 0 {
		t.Fatalf("duplicate report=%+v", report)
	}
}

func TestTraceCorrelationValidationAllowsUnresolvedParent(t *testing.T) {
	request := sampleTracesRequest()
	request.ResourceSpans[0].ScopeSpans[0].Spans[0].ParentSpanId =
		bytes.Repeat([]byte{0x99}, 8)
	if report := validateTraceCorrelation(request); report.invalid() {
		t.Fatalf("unresolved remote parent rejected: %+v", report)
	}
}

func TestTraceValidationReportPreservesAndRejectIsAtomic(t *testing.T) {
	request := sampleTracesRequest()
	request.ResourceSpans[0].ScopeSpans[0].Spans[0].TraceId =
		make([]byte, 16)

	for _, mode := range []string{
		TraceValidationReport,
		TraceValidationReject,
	} {
		t.Run(mode, func(t *testing.T) {
			processing, err := newTraceProcessing(TraceOptions{
				Validation: mode,
			})
			if err != nil {
				t.Fatal(err)
			}
			var got signal.Envelope
			emitted := false
			receiver := &Receiver{
				traceProcessing: processing,
				tracesEmit: func(
					_ context.Context,
					envelope signal.Envelope,
				) error {
					emitted = true
					got = envelope
					return nil
				},
			}
			failuresBefore := selfobs.OTLPTraceValidationFailures.Get()
			err = receiver.ingestTraces(context.Background(), request)
			if selfobs.OTLPTraceValidationFailures.Get() !=
				failuresBefore+1 {
				t.Fatal("validation failure metric not incremented")
			}
			if mode == TraceValidationReject {
				if !errors.Is(err, pipeline.ErrPermanent) || emitted {
					t.Fatalf("err=%v emitted=%v", err, emitted)
				}
				return
			}
			if err != nil || !emitted {
				t.Fatalf("err=%v emitted=%v", err, emitted)
			}
			var decoded coltracepb.ExportTraceServiceRequest
			if err := proto.Unmarshal(got.Payload, &decoded); err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(&decoded, request) {
				t.Fatal("report validation changed trace payload")
			}
		})
	}
}

func TestTraceValidationOffSkipsInspection(t *testing.T) {
	request := sampleTracesRequest()
	request.ResourceSpans[0].ScopeSpans[0].Spans[0].TraceId =
		make([]byte, 16)
	processing := mustTraceProcessing(t, TraceOptions{
		Validation: TraceValidationOff,
	})
	emitted := false
	receiver := &Receiver{
		traceProcessing: processing,
		tracesEmit: func(
			context.Context,
			signal.Envelope,
		) error {
			emitted = true
			return nil
		},
	}
	before := selfobs.OTLPTraceValidationRequests.Get()
	if err := receiver.ingestTraces(
		context.Background(),
		request,
	); err != nil {
		t.Fatal(err)
	}
	if !emitted ||
		selfobs.OTLPTraceValidationRequests.Get() != before {
		t.Fatalf(
			"emitted=%v validation_requests=%d want=%d",
			emitted,
			selfobs.OTLPTraceValidationRequests.Get(),
			before,
		)
	}
}

func TestTraceResourceEnrichmentPolicies(t *testing.T) {
	base := sampleTracesRequest()
	base.ResourceSpans[0].Resource.Attributes = append(
		base.ResourceSpans[0].Resource.Attributes,
		&commonpb.KeyValue{
			Key: "service.namespace",
			Value: &commonpb.AnyValue{
				Value: &commonpb.AnyValue_StringValue{
					StringValue: "original",
				},
			},
		},
	)
	base.ProtoReflect().SetUnknown([]byte{0x78, 0x01})
	base.ResourceSpans[0].Resource.ProtoReflect().
		SetUnknown([]byte{0x78, 0x02})

	t.Run("preserve", func(t *testing.T) {
		processing := mustTraceProcessing(t, TraceOptions{
			ResourceAttributes: map[string]string{
				"deployment.environment.name": "production",
				"service.namespace":           "enriched",
			},
			ResourceConflict: TraceResourcePreserve,
		})
		got, err := processing.enrich(base)
		if err != nil {
			t.Fatal(err)
		}
		if got == base {
			t.Fatal("resource enrichment mutated caller-owned request")
		}
		attributes := traceResourceStrings(got.ResourceSpans[0].Resource)
		if attributes["service.namespace"] != "original" ||
			attributes["deployment.environment.name"] != "production" {
			t.Fatalf("attributes=%v", attributes)
		}
		if traceResourceStrings(base.ResourceSpans[0].Resource)["deployment.environment.name"] != "" {
			t.Fatal("input request mutated")
		}
		if !bytes.Equal(
			got.ProtoReflect().GetUnknown(),
			[]byte{0x78, 0x01},
		) || !bytes.Equal(
			got.ResourceSpans[0].Resource.ProtoReflect().GetUnknown(),
			[]byte{0x78, 0x02},
		) {
			t.Fatal("protobuf unknown fields were not preserved")
		}
	})

	t.Run("replace", func(t *testing.T) {
		input := proto.Clone(base).(*coltracepb.ExportTraceServiceRequest)
		input.ResourceSpans[0].Resource.Attributes = append(
			input.ResourceSpans[0].Resource.Attributes,
			&commonpb.KeyValue{
				Key: "service.namespace",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_IntValue{IntValue: 7},
				},
			},
		)
		processing := mustTraceProcessing(t, TraceOptions{
			ResourceAttributes: map[string]string{
				"service.namespace": "enriched",
			},
			ResourceConflict: TraceResourceReplace,
		})
		got, err := processing.enrich(input)
		if err != nil {
			t.Fatal(err)
		}
		attributes := traceResourceStrings(got.ResourceSpans[0].Resource)
		if attributes["service.namespace"] != "enriched" {
			t.Fatalf("attributes=%v", attributes)
		}
		count := 0
		for _, attribute := range got.ResourceSpans[0].Resource.Attributes {
			if attribute != nil &&
				attribute.Key == "service.namespace" {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("service.namespace occurrences=%d", count)
		}
	})

	t.Run("reject", func(t *testing.T) {
		processing := mustTraceProcessing(t, TraceOptions{
			ResourceAttributes: map[string]string{
				"service.namespace": "enriched",
			},
			ResourceConflict: TraceResourceReject,
		})
		if _, err := processing.enrich(base); err == nil {
			t.Fatal("resource conflict accepted")
		}
	})

	t.Run("reject matching and missing", func(t *testing.T) {
		processing := mustTraceProcessing(t, TraceOptions{
			ResourceAttributes: map[string]string{
				"service.namespace":           "original",
				"deployment.environment.name": "production",
			},
			ResourceConflict: TraceResourceReject,
		})
		got, err := processing.enrich(base)
		if err != nil {
			t.Fatal(err)
		}
		attributes := traceResourceStrings(got.ResourceSpans[0].Resource)
		if attributes["service.namespace"] != "original" ||
			attributes["deployment.environment.name"] != "production" {
			t.Fatalf("attributes=%v", attributes)
		}
	})
}

func TestTraceResourceEnrichmentCreatesResourceAndIdentity(t *testing.T) {
	request := sampleTracesRequest()
	request.ResourceSpans[0].Resource = nil
	processing := mustTraceProcessing(t, TraceOptions{
		ResourceAttributes: map[string]string{
			"service.name":      "checkout",
			"service.namespace": "shop",
		},
	})
	var got signal.Envelope
	receiver := &Receiver{
		traceProcessing: processing,
		tracesEmit: func(
			_ context.Context,
			envelope signal.Envelope,
		) error {
			got = envelope
			return nil
		},
	}
	if err := receiver.ingestTraces(
		context.Background(),
		request,
	); err != nil {
		t.Fatal(err)
	}
	if got.Resource["service.name"] != "checkout" ||
		got.Resource["service.namespace"] != "shop" {
		t.Fatalf("identity=%v", got.Resource)
	}
	var decoded coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(got.Payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if attributes := traceResourceStrings(
		decoded.ResourceSpans[0].Resource,
	); attributes["service.name"] != "checkout" ||
		attributes["service.namespace"] != "shop" {
		t.Fatalf("attributes=%v", attributes)
	}
}

func TestTraceResourceRejectConflictIsPermanent(t *testing.T) {
	processing := mustTraceProcessing(t, TraceOptions{
		ResourceAttributes: map[string]string{
			"service.name": "other",
		},
		ResourceConflict: TraceResourceReject,
	})
	receiver := &Receiver{
		traceProcessing: processing,
		tracesEmit: func(context.Context, signal.Envelope) error {
			t.Fatal("conflicting request emitted")
			return nil
		},
	}
	if err := receiver.ingestTraces(
		context.Background(),
		sampleTracesRequest(),
	); !errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("err=%v", err)
	}
}

func TestTraceProcessingOptionsValidateAtReceiverConstruction(t *testing.T) {
	for _, options := range []TraceOptions{
		{Validation: "drop"},
		{ResourceConflict: TraceResourceReplace},
		{ResourceAttributes: map[string]string{"": "value"}},
	} {
		_, err := New(
			Options{Traces: options},
			slog.New(slog.NewTextHandler(io.Discard, nil)),
		)
		if err == nil {
			t.Fatalf("invalid direct trace options accepted: %+v", options)
		}
	}
	for _, limit := range []int{
		-1,
		otlpwire.MaxReceiverRequestBytes + 1,
	} {
		_, err := New(
			Options{MaxTraceRequestBytes: limit},
			slog.New(slog.NewTextHandler(io.Discard, nil)),
		)
		if err == nil {
			t.Fatalf("invalid direct trace limit accepted: %d", limit)
		}
	}
}

func mustTraceProcessing(
	t *testing.T,
	options TraceOptions,
) traceProcessing {
	t.Helper()
	processing, err := newTraceProcessing(options)
	if err != nil {
		t.Fatal(err)
	}
	return processing
}

func traceResourceStrings(resource *resourcepb.Resource) map[string]string {
	values := make(map[string]string)
	if resource == nil {
		return values
	}
	for _, attribute := range resource.Attributes {
		if attribute != nil && attribute.Value != nil {
			values[attribute.Key] = attribute.Value.GetStringValue()
		}
	}
	return values
}
