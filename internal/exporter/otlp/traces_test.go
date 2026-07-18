package otlp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/yaop-labs/wisp/internal/otlpwire"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
	"github.com/yaop-labs/wisp/internal/signal"
)

type fakeTracesTransport struct {
	response *coltracepb.ExportTraceServiceResponse
	err      error
	failAt   int
	calls    int
	id       string
	request  *coltracepb.ExportTraceServiceRequest
	ids      []string
	requests []*coltracepb.ExportTraceServiceRequest
}

func (t *fakeTracesTransport) sendTraces(_ context.Context, request *coltracepb.ExportTraceServiceRequest, id string) (*coltracepb.ExportTraceServiceResponse, error) {
	t.calls++
	t.id = id
	t.request = request
	t.ids = append(t.ids, id)
	t.requests = append(t.requests, request)
	if t.err != nil && (t.failAt == 0 || t.calls == t.failAt) {
		return nil, t.err
	}
	return t.response, nil
}

func (*fakeTracesTransport) close() error { return nil }

func traceTestEnvelope(t *testing.T) signal.Envelope {
	t.Helper()
	request := &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			ScopeSpans: []*tracepb.ScopeSpans{{
				Spans: []*tracepb.Span{{
					TraceId: bytes.Repeat([]byte{0x11}, 16),
					SpanId:  bytes.Repeat([]byte{0x22}, 8),
					Name:    "checkout",
				}},
			}},
		}},
	}
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

func TestTracesExporterRejectsWrongCapabilityBeforeTransport(t *testing.T) {
	transport := &fakeTracesTransport{response: &coltracepb.ExportTraceServiceResponse{}}
	exporter := &TracesExporter{tr: transport, timeout: time.Second, logger: discardLog()}
	envelope := traceTestEnvelope(t)
	envelope.Kind = signal.Logs
	err := exporter.Send(context.Background(), envelope)
	if !errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("Send error=%v, want ErrPermanent", err)
	}
	if transport.calls != 0 {
		t.Fatalf("transport calls=%d, want 0", transport.calls)
	}
}

func TestTracesExporterRejectsMalformedPayloadPermanently(t *testing.T) {
	transport := &fakeTracesTransport{response: &coltracepb.ExportTraceServiceResponse{}}
	exporter := &TracesExporter{tr: transport, timeout: time.Second, logger: discardLog()}
	envelope := traceTestEnvelope(t)
	envelope.Payload = []byte{0xff}
	err := exporter.Send(context.Background(), envelope)
	if !errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("Send error=%v, want ErrPermanent", err)
	}
	if transport.calls != 0 {
		t.Fatalf("transport calls=%d, want 0", transport.calls)
	}
}

func TestNewTracesRejectsReservedDeliveryHeader(t *testing.T) {
	_, err := NewTraces(Config{
		Endpoint: "127.0.0.1:4317",
		Headers: map[string]string{
			"X-Wisp-Signal-Kind": "operator-value",
		},
	}, discardLog())
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("error=%v, want reserved-header rejection", err)
	}
}

func TestNewTracesRejectsInvalidRequestBound(t *testing.T) {
	for _, limit := range []int{
		-1,
		otlpwire.MaxReceiverRequestBytes + 1,
	} {
		_, err := NewTraces(Config{
			Endpoint:             "127.0.0.1:4317",
			MaxTraceRequestBytes: limit,
		}, discardLog())
		if err == nil {
			t.Fatalf("invalid trace request bound accepted: %d", limit)
		}
	}
}

func TestTracesExporterAccountsPartialSuccessWithoutRetryError(t *testing.T) {
	transport := &fakeTracesTransport{response: &coltracepb.ExportTraceServiceResponse{
		PartialSuccess: &coltracepb.ExportTracePartialSuccess{
			RejectedSpans: 2,
			ErrorMessage:  "policy",
		},
	}}
	exporter := &TracesExporter{tr: transport, timeout: time.Second, logger: discardLog()}
	before := selfobs.OTLPTraceSpansRejected.Get()
	envelope := traceTestEnvelope(t)
	if err := exporter.Send(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if delta := selfobs.OTLPTraceSpansRejected.Get() - before; delta != 2 {
		t.Fatalf("rejected delta=%d, want 2", delta)
	}
	if transport.id != envelope.ID {
		t.Fatalf("delivery ID=%q, want %q", transport.id, envelope.ID)
	}
}

func TestTracesExporterCompatibilitySplitsWithStableIDs(t *testing.T) {
	request := exporterTraceBatch(3, 256)
	limit := proto.Size(exporterTraceBatch(1, 256))
	envelope := tracesRequestEnvelope(t, request)
	transport := &fakeTracesTransport{
		response: &coltracepb.ExportTraceServiceResponse{},
	}
	exporter := &TracesExporter{
		tr: transport, timeout: time.Second, logger: discardLog(),
		maxRequestBytes: limit,
	}
	if err := exporter.Send(
		context.Background(),
		envelope,
	); err != nil {
		t.Fatal(err)
	}
	if transport.calls < 2 {
		t.Fatalf("transport calls=%d", transport.calls)
	}
	traceRequestIndex := make(map[string]int)
	for index, request := range transport.requests {
		if size := proto.Size(request); size > limit {
			t.Fatalf(
				"request=%d size=%d limit=%d",
				index,
				size,
				limit,
			)
		}
		if transport.ids[index] !=
			derivedChunkID(envelope.ID, index) {
			t.Fatalf(
				"delivery id[%d]=%q",
				index,
				transport.ids[index],
			)
		}
		for _, resource := range request.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				for _, span := range scope.Spans {
					key := string(span.TraceId)
					if previous, exists := traceRequestIndex[key]; exists && previous != index {
						t.Fatal("trace split across exports")
					}
					traceRequestIndex[key] = index
				}
			}
		}
	}
	if len(traceRequestIndex) != 3 {
		t.Fatalf("exported traces=%d", len(traceRequestIndex))
	}
}

func TestTracesExporterRejectsLegacyOversizedTraceBeforeTransport(
	t *testing.T,
) {
	largeID := bytes.Repeat([]byte{0x44}, 16)
	smallID := bytes.Repeat([]byte{0x55}, 16)
	request := &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			ScopeSpans: []*tracepb.ScopeSpans{{
				Spans: []*tracepb.Span{
					exporterTraceSpan(largeID, 1, 512),
					exporterTraceSpan(largeID, 2, 512),
					exporterTraceSpan(largeID, 3, 512),
					exporterTraceSpan(smallID, 4, 8),
				},
			}},
		}},
	}
	small := proto.Clone(request).(*coltracepb.ExportTraceServiceRequest)
	small.ResourceSpans[0].ScopeSpans[0].Spans =
		small.ResourceSpans[0].ScopeSpans[0].Spans[3:]
	transport := &fakeTracesTransport{
		response: &coltracepb.ExportTraceServiceResponse{},
	}
	exporter := &TracesExporter{
		tr: transport, timeout: time.Second, logger: discardLog(),
		maxRequestBytes: proto.Size(small),
	}
	err := exporter.Send(
		context.Background(),
		tracesRequestEnvelope(t, request),
	)
	if !errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("err=%v", err)
	}
	if transport.calls != 0 {
		t.Fatalf("partial legacy delivery calls=%d", transport.calls)
	}
}

func TestTracesExporterRejectsLegacyUnplaceableMetadataBeforeTransport(
	t *testing.T,
) {
	request := exporterTraceBatch(1, 16)
	request.ProtoReflect().SetUnknown(
		bytes.Repeat([]byte{0x78, 0x01}, 40),
	)
	clean := proto.Clone(request).(*coltracepb.ExportTraceServiceRequest)
	clean.ProtoReflect().SetUnknown(nil)
	transport := &fakeTracesTransport{
		response: &coltracepb.ExportTraceServiceResponse{},
	}
	exporter := &TracesExporter{
		tr: transport, timeout: time.Second, logger: discardLog(),
		maxRequestBytes: proto.Size(clean),
	}
	err := exporter.Send(
		context.Background(),
		tracesRequestEnvelope(t, request),
	)
	if !errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("err=%v", err)
	}
	if transport.calls != 0 {
		t.Fatalf("partial legacy delivery calls=%d", transport.calls)
	}
}

func TestTracesExporterSplitStopsAtTransportFailure(t *testing.T) {
	request := exporterTraceBatch(3, 256)
	limit := proto.Size(exporterTraceBatch(1, 256))
	sentinel := errors.New("downstream unavailable")
	transport := &fakeTracesTransport{
		response: &coltracepb.ExportTraceServiceResponse{},
		err:      sentinel, failAt: 2,
	}
	exporter := &TracesExporter{
		tr: transport, timeout: time.Second, logger: discardLog(),
		maxRequestBytes: limit,
	}
	err := exporter.Send(
		context.Background(),
		tracesRequestEnvelope(t, request),
	)
	if !errors.Is(err, sentinel) || transport.calls != 2 {
		t.Fatalf("err=%v calls=%d", err, transport.calls)
	}
}

func TestTracesExporterClassifiesTransportError(t *testing.T) {
	sentinel := errors.New("downstream")
	transport := &fakeTracesTransport{err: sentinel}
	exporter := &TracesExporter{tr: transport, timeout: time.Second, logger: discardLog()}
	err := exporter.Send(context.Background(), traceTestEnvelope(t))
	if !errors.Is(err, sentinel) || errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("error=%v, want transient sentinel", err)
	}
}

func exporterTraceBatch(
	traces int,
	nameBytes int,
) *coltracepb.ExportTraceServiceRequest {
	spans := make([]*tracepb.Span, 0, traces)
	for index := range traces {
		traceID := bytes.Repeat(
			[]byte{byte(index + 1)},
			16,
		)
		spans = append(
			spans,
			exporterTraceSpan(
				traceID,
				byte(index+1),
				nameBytes,
			),
		)
	}
	return &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			ScopeSpans: []*tracepb.ScopeSpans{{
				Spans: spans,
			}},
		}},
	}
}

func exporterTraceSpan(
	traceID []byte,
	spanByte byte,
	nameBytes int,
) *tracepb.Span {
	return &tracepb.Span{
		TraceId: traceID,
		SpanId: bytes.Repeat(
			[]byte{spanByte},
			8,
		),
		Name:              strings.Repeat("x", nameBytes),
		StartTimeUnixNano: 1,
		EndTimeUnixNano:   2,
	}
}

func tracesRequestEnvelope(
	t *testing.T,
	request *coltracepb.ExportTraceServiceRequest,
) signal.Envelope {
	t.Helper()
	payload, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signal.New(
		signal.Traces,
		signal.OTLPTracesSchema,
		signal.OTLPProtobufEncoding,
		payload,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestHTTPTracesTransportAddsDeliveryHeaders(t *testing.T) {
	var envelopeID, kind string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		envelopeID = request.Header.Get("X-Wisp-Envelope-Id")
		kind = request.Header.Get("X-Wisp-Signal-Kind")
		w.Header().Set("Content-Type", signal.OTLPProtobufEncoding)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &httpTracesTransport{url: server.URL, client: server.Client()}
	if _, err := transport.sendTraces(
		context.Background(),
		&coltracepb.ExportTraceServiceRequest{},
		"0123456789abcdef0123456789abcdef",
	); err != nil {
		t.Fatal(err)
	}
	if envelopeID != "0123456789abcdef0123456789abcdef" || kind != "traces" {
		t.Fatalf("delivery headers id=%q kind=%q", envelopeID, kind)
	}
}

func TestHTTPTracesTransportBoundsSuccessResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, maxOTLPResponseBytes+1))
	}))
	defer server.Close()

	transport := &httpTracesTransport{url: server.URL, client: server.Client()}
	_, err := transport.sendTraces(
		context.Background(),
		&coltracepb.ExportTraceServiceRequest{},
		"0123456789abcdef0123456789abcdef",
	)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error=%v, want bounded response rejection", err)
	}
}
