package otlp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"

	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
	"github.com/yaop-labs/wisp/internal/signal"
)

type fakeLogsTransport struct {
	response *collogspb.ExportLogsServiceResponse
	err      error
	calls    int
	ids      []string
	requests []*collogspb.ExportLogsServiceRequest
	failAt   int
}

func (t *fakeLogsTransport) sendLogs(_ context.Context, request *collogspb.ExportLogsServiceRequest, id string) (*collogspb.ExportLogsServiceResponse, error) {
	t.calls++
	t.ids = append(t.ids, id)
	t.requests = append(t.requests, request)
	if t.failAt > 0 && t.calls == t.failAt {
		return nil, errors.New("transient")
	}
	return t.response, t.err
}

func splitTestEnvelope(t *testing.T, records, bodyBytes int) signal.Envelope {
	t.Helper()
	request := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			ScopeLogs: []*logspb.ScopeLogs{{}},
		}},
	}
	for i := range records {
		request.ResourceLogs[0].ScopeLogs[0].LogRecords = append(
			request.ResourceLogs[0].ScopeLogs[0].LogRecords,
			&logspb.LogRecord{
				TimeUnixNano: uint64(i + 1),
				Body: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_StringValue{
						StringValue: strings.Repeat("x", bodyBytes),
					},
				},
			},
		)
	}
	payload, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signal.New(
		signal.Logs, signal.OTLPLogsSchema, signal.OTLPProtobufEncoding, payload, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}
func (*fakeLogsTransport) close() error { return nil }

func logsTestEnvelope(t *testing.T) signal.Envelope {
	t.Helper()
	payload, err := proto.Marshal(&collogspb.ExportLogsServiceRequest{})
	if err != nil {
		t.Fatal(err)
	}
	// An empty protobuf request encodes to zero bytes, while durable envelopes
	// intentionally reject empty payloads. Add an unknown field: the exporter
	// still validates protobuf framing and preserves it.
	if len(payload) == 0 {
		payload = []byte{0x78, 0x01}
	}
	envelope, err := signal.New(
		signal.Logs, signal.OTLPLogsSchema, signal.OTLPProtobufEncoding, payload, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestLogsExporterRejectsWrongCapabilityBeforeTransport(t *testing.T) {
	transport := &fakeLogsTransport{response: &collogspb.ExportLogsServiceResponse{}}
	exporter := &LogsExporter{tr: transport, timeout: time.Second, logger: discardLog()}
	envelope := logsTestEnvelope(t)
	envelope.Schema = "wrong"
	err := exporter.Send(context.Background(), envelope)
	if !errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("Send error = %v, want ErrPermanent", err)
	}
	if transport.calls != 0 {
		t.Fatalf("transport calls = %d, want 0", transport.calls)
	}
}

func TestNewLogsRejectsReservedDeliveryHeader(t *testing.T) {
	_, err := NewLogs(Config{
		Endpoint: "127.0.0.1:4317",
		Headers: map[string]string{
			"X-Wisp-Envelope-Id": "operator-value",
		},
	}, discardLog())
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("error=%v, want reserved-header rejection", err)
	}
}

func TestLogsExporterAccountsPartialSuccessWithoutRetryError(t *testing.T) {
	transport := &fakeLogsTransport{response: &collogspb.ExportLogsServiceResponse{
		PartialSuccess: &collogspb.ExportLogsPartialSuccess{
			RejectedLogRecords: 2,
			ErrorMessage:       "policy",
		},
	}}
	exporter := &LogsExporter{tr: transport, timeout: time.Second, logger: discardLog()}
	before := selfobs.OTLPLogsRejected.Get()
	if err := exporter.Send(context.Background(), splitTestEnvelope(t, 1, 16)); err != nil {
		t.Fatal(err)
	}
	if delta := selfobs.OTLPLogsRejected.Get() - before; delta != 2 {
		t.Fatalf("rejected delta = %d, want 2", delta)
	}
}

func TestLogsExporterFallbackSplitsWithStableDeliveryIDs(t *testing.T) {
	envelope := splitTestEnvelope(t, 10, 256)
	first := &fakeLogsTransport{
		response: &collogspb.ExportLogsServiceResponse{},
		failAt:   2,
	}
	exporter := &LogsExporter{
		tr: first, timeout: time.Second, logger: discardLog(), maxRequestBytes: 900,
	}
	if err := exporter.Send(context.Background(), envelope); err == nil ||
		errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("first Send error=%v, want transient", err)
	}
	if first.calls != 2 || first.ids[0] == first.ids[1] {
		t.Fatalf("calls=%d ids=%v, want two distinct chunks", first.calls, first.ids)
	}
	for i, request := range first.requests {
		if size := proto.Size(request); size > 900 {
			t.Fatalf("request %d size=%d > 900", i, size)
		}
	}

	second := &fakeLogsTransport{response: &collogspb.ExportLogsServiceResponse{}}
	retry := &LogsExporter{
		tr: second, timeout: time.Second, logger: discardLog(), maxRequestBytes: 900,
	}
	if err := retry.Send(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if len(second.ids) < 2 || first.ids[0] != second.ids[0] || first.ids[1] != second.ids[1] {
		t.Fatalf("delivery IDs changed across retry: first=%v second=%v", first.ids, second.ids)
	}
}

func TestLogsExporterRejectsSingleOversizedRecordPermanently(t *testing.T) {
	transport := &fakeLogsTransport{response: &collogspb.ExportLogsServiceResponse{}}
	exporter := &LogsExporter{
		tr: transport, timeout: time.Second, logger: discardLog(), maxRequestBytes: 512,
	}
	err := exporter.Send(context.Background(), splitTestEnvelope(t, 1, 2048))
	if !errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("error=%v, want ErrPermanent", err)
	}
	if transport.calls != 0 {
		t.Fatalf("transport calls=%d, want 0", transport.calls)
	}
}

func TestHTTPLogsTransportAddsDeliveryHeaders(t *testing.T) {
	var envelopeID, kind string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		envelopeID = request.Header.Get("X-Wisp-Envelope-Id")
		kind = request.Header.Get("X-Wisp-Signal-Kind")
		w.Header().Set("Content-Type", signal.OTLPProtobufEncoding)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &httpLogsTransport{url: server.URL, client: server.Client()}
	if _, err := transport.sendLogs(
		context.Background(),
		&collogspb.ExportLogsServiceRequest{},
		"0123456789abcdef0123456789abcdef",
	); err != nil {
		t.Fatal(err)
	}
	if envelopeID != "0123456789abcdef0123456789abcdef" || kind != "logs" {
		t.Fatalf("delivery headers id=%q kind=%q", envelopeID, kind)
	}
}
