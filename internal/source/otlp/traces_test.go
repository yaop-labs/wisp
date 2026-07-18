package otlp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	exp "github.com/yaop-labs/wisp/internal/exporter/otlp"
	"github.com/yaop-labs/wisp/internal/exporter/spool"
	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/signal"
)

func sampleTracesRequest() *coltracepb.ExportTraceServiceRequest {
	return &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
				Key: "service.name",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_StringValue{StringValue: "checkout"},
				},
			}}},
			ScopeSpans: []*tracepb.ScopeSpans{{
				Scope: &commonpb.InstrumentationScope{
					Name:    "checkout.http",
					Version: "1.2.3",
				},
				Spans: []*tracepb.Span{{
					TraceId:           bytes.Repeat([]byte{0x11}, 16),
					SpanId:            bytes.Repeat([]byte{0x22}, 8),
					Name:              "POST /checkout",
					Kind:              tracepb.Span_SPAN_KIND_SERVER,
					StartTimeUnixNano: 100,
					EndTimeUnixNano:   200,
					Attributes: []*commonpb.KeyValue{{
						Key: "http.request.method",
						Value: &commonpb.AnyValue{
							Value: &commonpb.AnyValue_StringValue{StringValue: "POST"},
						},
					}},
				}},
			}},
		}},
	}
}

func tracesEnvelope(t *testing.T, request *coltracepb.ExportTraceServiceRequest) signal.Envelope {
	t.Helper()
	payload, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signal.New(
		signal.Traces, signal.OTLPTracesSchema, signal.OTLPProtobufEncoding,
		payload, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestTracesRoundTripGRPCAndHTTP(t *testing.T) {
	for _, protocol := range []string{"grpc", "http"} {
		t.Run(protocol, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			options := Options{}
			if protocol == "grpc" {
				options.GRPCAddr = "127.0.0.1:0"
			} else {
				options.HTTPAddr = "127.0.0.1:0"
			}
			receiver := mustReceiver(t, options, logger)
			got := make(chan signal.Envelope, 1)
			receiver.SetTracesEmitter(func(_ context.Context, envelope signal.Envelope) error {
				got <- envelope
				return nil
			})
			go func() {
				_ = receiver.Start(t.Context(), func(context.Context, model.Batch) error {
					return nil
				})
			}()

			endpoint := receiver.GRPCAddr()
			if protocol == "http" {
				endpoint = receiver.HTTPAddr()
			}
			exporter, err := exp.NewTraces(exp.Config{
				Endpoint: endpoint, Protocol: protocol, Timeout: 3 * time.Second,
			}, logger)
			if err != nil {
				t.Fatal(err)
			}
			defer exporter.Close()

			request := sampleTracesRequest()
			if err := exporter.Send(context.Background(), tracesEnvelope(t, request)); err != nil {
				t.Fatalf("send: %v", err)
			}
			select {
			case envelope := <-got:
				if envelope.Kind != signal.Traces || envelope.Schema != signal.OTLPTracesSchema {
					t.Fatalf("envelope kind/schema = %q/%q", envelope.Kind, envelope.Schema)
				}
				if envelope.Resource["service.name"] != "checkout" {
					t.Fatalf("envelope resource = %v, want service.name identity", envelope.Resource)
				}
				var decoded coltracepb.ExportTraceServiceRequest
				if err := proto.Unmarshal(envelope.Payload, &decoded); err != nil {
					t.Fatal(err)
				}
				if !proto.Equal(&decoded, request) {
					t.Fatalf("traces changed across round trip: got=%v want=%v", &decoded, request)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for traces envelope")
			}
		})
	}
}

func TestTracesIngestIsAtomicAndLossless(t *testing.T) {
	request := sampleTracesRequest()
	request.ProtoReflect().SetUnknown([]byte{0x78, 0x01})
	request.ResourceSpans[0].ScopeSpans[0].Spans[0].
		ProtoReflect().SetUnknown([]byte{0x78, 0x02})
	request.ResourceSpans[0].ScopeSpans[0].Spans = append(
		request.ResourceSpans[0].ScopeSpans[0].Spans,
		&tracepb.Span{
			TraceId: bytes.Repeat([]byte{0x33}, 16),
			SpanId:  bytes.Repeat([]byte{0x44}, 8),
			Name:    "charge card",
		},
	)
	var envelopes []signal.Envelope
	receiver := &Receiver{
		tracesEmit: func(_ context.Context, envelope signal.Envelope) error {
			envelopes = append(envelopes, envelope)
			return nil
		},
	}
	if err := receiver.ingestTraces(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if len(envelopes) != 1 {
		t.Fatalf("envelopes=%d, want one atomic request", len(envelopes))
	}
	var decoded coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(envelopes[0].Payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(&decoded, request) {
		t.Fatalf("trace request changed: got=%v want=%v", &decoded, request)
	}
}

func TestTracesIngestEmptyRequestDoesNotEmit(t *testing.T) {
	receiver := &Receiver{
		tracesEmit: func(context.Context, signal.Envelope) error {
			t.Fatal("empty trace request emitted")
			return nil
		},
	}
	if err := receiver.ingestTraces(
		context.Background(), &coltracepb.ExportTraceServiceRequest{},
	); err != nil {
		t.Fatal(err)
	}
}

func TestTracesIngestOmitsDisagreeingCommonIdentity(t *testing.T) {
	request := sampleTracesRequest()
	second := proto.Clone(request.ResourceSpans[0]).(*tracepb.ResourceSpans)
	second.Resource.Attributes[0].Value = &commonpb.AnyValue{
		Value: &commonpb.AnyValue_StringValue{StringValue: "payments"},
	}
	request.ResourceSpans = append(request.ResourceSpans, second)
	var got signal.Envelope
	receiver := &Receiver{
		tracesEmit: func(_ context.Context, envelope signal.Envelope) error {
			got = envelope
			return nil
		},
	}
	if err := receiver.ingestTraces(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if len(got.Resource) != 0 {
		t.Fatalf("common resource=%v, want omitted identity", got.Resource)
	}
	var decoded coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(got.Payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(&decoded, request) {
		t.Fatal("disagreeing resource identity changed payload")
	}
}

func TestTracesIngestPropagatesDurabilityFailure(t *testing.T) {
	sentinel := errors.New("disk unavailable")
	receiver := &Receiver{
		tracesEmit: func(context.Context, signal.Envelope) error {
			return sentinel
		},
	}
	err := receiver.ingestTraces(context.Background(), sampleTracesRequest())
	if !errors.Is(err, sentinel) {
		t.Fatalf("error=%v, want durability failure", err)
	}
}

func TestTracesGRPCMapsBackpressure(t *testing.T) {
	service := &grpcTracesService{r: &Receiver{
		tracesEmit: func(context.Context, signal.Envelope) error {
			return pipeline.ErrBackpressure
		},
	}}
	_, err := service.Export(context.Background(), sampleTracesRequest())
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Fatalf("status=%s, want ResourceExhausted", got)
	}
}

func TestTracesGRPCMapsStrictValidationToInvalidArgument(t *testing.T) {
	request := sampleTracesRequest()
	request.ResourceSpans[0].ScopeSpans[0].Spans[0].TraceId =
		make([]byte, 16)
	service := &grpcTracesService{r: &Receiver{
		traceProcessing: mustTraceProcessing(t, TraceOptions{
			Validation: TraceValidationReject,
		}),
		tracesEmit: func(context.Context, signal.Envelope) error {
			t.Fatal("invalid traces reached emitter")
			return nil
		},
	}}
	_, err := service.Export(context.Background(), request)
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("status=%s, want InvalidArgument", got)
	}
}

func TestTracesHTTPMapsBackpressure(t *testing.T) {
	receiver := &Receiver{
		tracesEmit: func(context.Context, signal.Envelope) error {
			return pipeline.ErrBackpressure
		},
	}
	body, err := proto.Marshal(sampleTracesRequest())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/traces", bytes.NewReader(body))
	response := httptest.NewRecorder()
	receiver.handleTracesHTTP(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want 429", response.Code)
	}
	assertOTLPHTTPError(
		t,
		response,
		codes.ResourceExhausted,
	)
}

func TestTracesHTTPMapsStrictValidationToBadRequest(t *testing.T) {
	traceRequest := sampleTracesRequest()
	traceRequest.ResourceSpans[0].ScopeSpans[0].Spans[0].TraceId =
		make([]byte, 16)
	body, err := proto.Marshal(traceRequest)
	if err != nil {
		t.Fatal(err)
	}
	receiver := &Receiver{
		traceProcessing: mustTraceProcessing(t, TraceOptions{
			Validation: TraceValidationReject,
		}),
		tracesEmit: func(context.Context, signal.Envelope) error {
			t.Fatal("invalid traces reached emitter")
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
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", response.Code)
	}
	assertOTLPHTTPError(
		t,
		response,
		codes.InvalidArgument,
	)
}

func TestTracesHTTPRejectsOversizedBody(t *testing.T) {
	receiver := &Receiver{
		tracesEmit: func(context.Context, signal.Envelope) error {
			t.Fatal("oversized body reached emitter")
			return nil
		},
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/traces",
		bytes.NewReader(make([]byte, maxBodyBytes+1)),
	)
	response := httptest.NewRecorder()
	receiver.handleTracesHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d, want 413", response.Code)
	}
	assertOTLPHTTPError(
		t,
		response,
		codes.InvalidArgument,
	)
}

func assertOTLPHTTPError(
	t *testing.T,
	response *httptest.ResponseRecorder,
	want codes.Code,
) {
	t.Helper()
	if got := response.Header().Get("Content-Type"); got !=
		signal.OTLPProtobufEncoding {
		t.Fatalf("content type=%q", got)
	}
	var value statuspb.Status
	if err := proto.Unmarshal(response.Body.Bytes(), &value); err != nil {
		t.Fatalf("decode google.rpc.Status: %v", err)
	}
	if codes.Code(value.Code) != want || value.Message == "" {
		t.Fatalf("status body=%v", &value)
	}
}

func TestTracesSurviveQueueRestart(t *testing.T) {
	dir := t.TempDir()
	downstream := &durableLogsSender{down: true}
	queue1, err := spool.NewQueue(downstream, spool.Config{
		Dir: dir, MaxBytes: 1 << 20, DrainInterval: time.Hour,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	receiver := &Receiver{tracesEmit: queue1.Accept}
	request := sampleTracesRequest()
	if err := receiver.ingestTraces(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if got := queue1.SignalCount(signal.Traces); got != 1 {
		t.Fatalf("spooled traces=%d, want 1", got)
	}
	if err := queue1.Close(); err != nil {
		t.Fatal(err)
	}

	downstream.setDown(false)
	queue2, err := spool.NewQueue(downstream, spool.Config{
		Dir: dir, MaxBytes: 1 << 20, DrainInterval: time.Hour,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer queue2.Close()
	if got := queue2.SignalCount(signal.Traces); got != 1 {
		t.Fatalf("restart trace depth=%d, want 1", got)
	}
	if err := queue2.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if queue2.Count() != 0 {
		t.Fatalf("queue count after recovery=%d, want 0", queue2.Count())
	}

	delivered := downstream.snapshot()
	if len(delivered) != 1 || delivered[0].Kind != signal.Traces {
		t.Fatalf("delivered=%v, want one traces envelope", delivered)
	}
	var decoded coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(delivered[0].Payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(&decoded, request) {
		t.Fatal("recovered trace request changed")
	}
}
