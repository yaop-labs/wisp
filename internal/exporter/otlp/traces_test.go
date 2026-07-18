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

	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
	"github.com/yaop-labs/wisp/internal/signal"
)

type fakeTracesTransport struct {
	response *coltracepb.ExportTraceServiceResponse
	err      error
	calls    int
	id       string
	request  *coltracepb.ExportTraceServiceRequest
}

func (t *fakeTracesTransport) sendTraces(_ context.Context, request *coltracepb.ExportTraceServiceRequest, id string) (*coltracepb.ExportTraceServiceResponse, error) {
	t.calls++
	t.id = id
	t.request = request
	return t.response, t.err
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

func TestTracesExporterClassifiesTransportError(t *testing.T) {
	sentinel := errors.New("downstream")
	transport := &fakeTracesTransport{err: sentinel}
	exporter := &TracesExporter{tr: transport, timeout: time.Second, logger: discardLog()}
	err := exporter.Send(context.Background(), traceTestEnvelope(t))
	if !errors.Is(err, sentinel) || errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("error=%v, want transient sentinel", err)
	}
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
