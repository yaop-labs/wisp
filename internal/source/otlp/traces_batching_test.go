package otlp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/yaop-labs/wisp/internal/otlpwire"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
	"github.com/yaop-labs/wisp/internal/signal"
)

func TestTracesIngestSplitsOnlyBetweenCompleteTraces(t *testing.T) {
	request := receiverTraceBatch(3, 256)
	single := receiverTraceBatch(1, 256)
	limit := proto.Size(single)
	if proto.Size(request) <= limit {
		t.Fatal("test request does not require splitting")
	}

	var envelopes []signal.Envelope
	receiver := &Receiver{
		maxTraceRequestBytes: limit,
		tracesEmit: func(
			_ context.Context,
			envelope signal.Envelope,
		) error {
			envelopes = append(envelopes, envelope)
			return nil
		},
	}
	result, err := receiver.ingestTracesResult(
		context.Background(),
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.rejectedSpans != 0 || len(envelopes) < 2 {
		t.Fatalf("result=%+v envelopes=%d", result, len(envelopes))
	}

	traceEnvelope := make(map[string]int)
	spans := 0
	for index, envelope := range envelopes {
		if len(envelope.Payload) > limit {
			t.Fatalf(
				"envelope=%d payload=%d limit=%d",
				index,
				len(envelope.Payload),
				limit,
			)
		}
		var chunk coltracepb.ExportTraceServiceRequest
		if err := proto.Unmarshal(envelope.Payload, &chunk); err != nil {
			t.Fatal(err)
		}
		for _, resource := range chunk.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				for _, span := range scope.Spans {
					spans++
					key := string(span.TraceId)
					if previous, exists := traceEnvelope[key]; exists && previous != index {
						t.Fatal("one trace was split across envelopes")
					}
					traceEnvelope[key] = index
				}
			}
		}
	}
	if spans != 3 || len(traceEnvelope) != 3 {
		t.Fatalf("spans=%d traces=%d", spans, len(traceEnvelope))
	}
}

func TestTracesGRPCReportsOversizedTracePartialSuccess(t *testing.T) {
	request, smallTraceID, limit := oversizedReceiverTraceRequest(t)
	var envelopes []signal.Envelope
	receiver := &Receiver{
		maxTraceRequestBytes: limit,
		tracesEmit: func(
			_ context.Context,
			envelope signal.Envelope,
		) error {
			envelopes = append(envelopes, envelope)
			return nil
		},
	}
	response, err := (&grpcTracesService{r: receiver}).Export(
		context.Background(),
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	partial := response.GetPartialSuccess()
	if partial == nil ||
		partial.RejectedSpans != 3 ||
		!strings.Contains(
			partial.ErrorMessage,
			"max_trace_request_bytes",
		) {
		t.Fatalf("partial success=%v", partial)
	}
	assertOnlyTraceEnvelope(
		t,
		envelopes,
		smallTraceID,
	)
}

func TestTracesHTTPReportsOversizedTracePartialSuccess(t *testing.T) {
	traceRequest, smallTraceID, limit :=
		oversizedReceiverTraceRequest(t)
	body, err := proto.Marshal(traceRequest)
	if err != nil {
		t.Fatal(err)
	}
	var envelopes []signal.Envelope
	receiver := &Receiver{
		maxTraceRequestBytes: limit,
		tracesEmit: func(
			_ context.Context,
			envelope signal.Envelope,
		) error {
			envelopes = append(envelopes, envelope)
			return nil
		},
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/traces",
		bytes.NewReader(body),
	)
	response := httptest.NewRecorder()
	receiver.handleTracesHTTP(response, request)
	if response.Code != http.StatusOK ||
		response.Header().Get("Content-Type") !=
			signal.OTLPProtobufEncoding {
		t.Fatalf(
			"status=%d content_type=%q",
			response.Code,
			response.Header().Get("Content-Type"),
		)
	}
	var decoded coltracepb.ExportTraceServiceResponse
	if err := proto.Unmarshal(
		response.Body.Bytes(),
		&decoded,
	); err != nil {
		t.Fatal(err)
	}
	if decoded.GetPartialSuccess().GetRejectedSpans() != 3 {
		t.Fatalf("response=%v", &decoded)
	}
	assertOnlyTraceEnvelope(
		t,
		envelopes,
		smallTraceID,
	)
}

func TestTracesAllOversizedReportsPartialSuccessWithoutEnvelope(
	t *testing.T,
) {
	request := receiverTraceBatch(1, 512)
	traceUnit := proto.Clone(request).(*coltracepb.ExportTraceServiceRequest)
	traceUnit.ResourceSpans[0].ScopeSpans[0].Spans[0].
		Attributes[0].Value = &commonpb.AnyValue{
		Value: &commonpb.AnyValue_StringValue{
			StringValue: "small",
		},
	}
	limit := proto.Size(traceUnit)
	if proto.Size(request) <= limit {
		t.Fatalf(
			"request=%d limit=%d",
			proto.Size(request),
			limit,
		)
	}
	receiver := &Receiver{
		maxTraceRequestBytes: limit,
		tracesEmit: func(
			context.Context,
			signal.Envelope,
		) error {
			t.Fatal("all-oversized request emitted an envelope")
			return nil
		},
	}
	response, err := (&grpcTracesService{r: receiver}).Export(
		context.Background(),
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := response.GetPartialSuccess().
		GetRejectedSpans(); got != 1 {
		t.Fatalf("rejected spans=%d", got)
	}
}

func TestTracesSplitAdmissionFailureStopsAndRetriesRequest(
	t *testing.T,
) {
	request := receiverTraceBatch(3, 256)
	limit := proto.Size(receiverTraceBatch(1, 256))
	sentinel := errors.New("durability unavailable")
	calls := 0
	receiver := &Receiver{
		maxTraceRequestBytes: limit,
		tracesEmit: func(
			context.Context,
			signal.Envelope,
		) error {
			calls++
			if calls == 2 {
				return sentinel
			}
			return nil
		},
	}
	requestsBefore := selfobs.OTLPTraceRequestsReceived.Get()
	err := receiver.ingestTraces(
		context.Background(),
		request,
	)
	if !errors.Is(err, sentinel) || calls != 2 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	if selfobs.OTLPTraceRequestsReceived.Get() != requestsBefore {
		t.Fatal("failed split request counted as completely processed")
	}
}

func TestTracesUnplaceableUnknownMetadataIsPermanentBeforeEmit(
	t *testing.T,
) {
	request := receiverTraceBatch(1, 16)
	request.ProtoReflect().SetUnknown(
		bytes.Repeat([]byte{0x78, 0x01}, 40),
	)
	clean := proto.Clone(request).(*coltracepb.ExportTraceServiceRequest)
	clean.ProtoReflect().SetUnknown(nil)
	receiver := &Receiver{
		maxTraceRequestBytes: proto.Size(clean),
		tracesEmit: func(
			context.Context,
			signal.Envelope,
		) error {
			t.Fatal("unplaceable request emitted")
			return nil
		},
	}
	err := receiver.ingestTraces(
		context.Background(),
		request,
	)
	if !errors.Is(err, pipeline.ErrPermanent) ||
		!errors.Is(
			err,
			otlpwire.ErrTraceRequestMetadataTooLarge,
		) {
		t.Fatalf("err=%v", err)
	}
}

func receiverTraceBatch(
	traces int,
	bodyBytes int,
) *coltracepb.ExportTraceServiceRequest {
	request := sampleTracesRequest()
	scope := request.ResourceSpans[0].ScopeSpans[0]
	scope.Spans = nil
	for index := range traces {
		traceID := bytes.Repeat(
			[]byte{byte(index + 1)},
			16,
		)
		scope.Spans = append(scope.Spans, receiverTraceSpan(
			traceID,
			byte(index+1),
			bodyBytes,
		))
	}
	return request
}

func receiverTraceSpan(
	traceID []byte,
	spanByte byte,
	bodyBytes int,
) *tracepb.Span {
	return &tracepb.Span{
		TraceId: traceID,
		SpanId: bytes.Repeat(
			[]byte{spanByte},
			8,
		),
		Name:              "operation",
		StartTimeUnixNano: 1,
		EndTimeUnixNano:   2,
		Attributes: []*commonpb.KeyValue{{
			Key: "payload",
			Value: &commonpb.AnyValue{
				Value: &commonpb.AnyValue_StringValue{
					StringValue: strings.Repeat(
						"x",
						bodyBytes,
					),
				},
			},
		}},
	}
}

func oversizedReceiverTraceRequest(
	t *testing.T,
) (
	*coltracepb.ExportTraceServiceRequest,
	[]byte,
	int,
) {
	t.Helper()
	largeTraceID := bytes.Repeat([]byte{0x44}, 16)
	smallTraceID := bytes.Repeat([]byte{0x55}, 16)
	request := sampleTracesRequest()
	scope := request.ResourceSpans[0].ScopeSpans[0]
	scope.Spans = []*tracepb.Span{
		receiverTraceSpan(largeTraceID, 1, 512),
		receiverTraceSpan(largeTraceID, 2, 512),
		receiverTraceSpan(largeTraceID, 3, 512),
		receiverTraceSpan(smallTraceID, 4, 8),
	}
	small := proto.Clone(request).(*coltracepb.ExportTraceServiceRequest)
	small.ResourceSpans[0].ScopeSpans[0].Spans =
		small.ResourceSpans[0].ScopeSpans[0].Spans[3:]
	limit := proto.Size(small)
	analysis, err := otlpwire.AnalyzeTraces(request, limit)
	if err != nil {
		t.Fatal(err)
	}
	if analysis.RejectedSpans != 3 || analysis.Chunks != 1 {
		t.Fatalf("analysis=%+v", analysis)
	}
	return request, smallTraceID, limit
}

func assertOnlyTraceEnvelope(
	t *testing.T,
	envelopes []signal.Envelope,
	traceID []byte,
) {
	t.Helper()
	if len(envelopes) != 1 {
		t.Fatalf("envelopes=%d", len(envelopes))
	}
	var request coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(
		envelopes[0].Payload,
		&request,
	); err != nil {
		t.Fatal(err)
	}
	spans := request.ResourceSpans[0].ScopeSpans[0].Spans
	if len(spans) != 1 ||
		!bytes.Equal(spans[0].TraceId, traceID) {
		t.Fatalf("spans=%v want trace=%x", spans, traceID)
	}
}
