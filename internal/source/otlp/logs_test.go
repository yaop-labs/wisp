package otlp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"

	exp "github.com/yaop-labs/wisp/internal/exporter/otlp"
	"github.com/yaop-labs/wisp/internal/exporter/spool"
	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/signal"
)

type durableLogsSender struct {
	mu   sync.Mutex
	down bool
	got  []signal.Envelope
}

func (s *durableLogsSender) Send(_ context.Context, envelope signal.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return errors.New("downstream unavailable")
	}
	s.got = append(s.got, envelope)
	return nil
}

func (*durableLogsSender) Close() error { return nil }

func (s *durableLogsSender) setDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

func (s *durableLogsSender) snapshot() []signal.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]signal.Envelope(nil), s.got...)
}

func sampleLogsRequest() *collogspb.ExportLogsServiceRequest {
	return &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
				Key: "service.name",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_StringValue{StringValue: "checkout"},
				},
			}}},
			ScopeLogs: []*logspb.ScopeLogs{{
				LogRecords: []*logspb.LogRecord{{
					TimeUnixNano: 123,
					SeverityText: "INFO",
					Body: &commonpb.AnyValue{
						Value: &commonpb.AnyValue_StringValue{StringValue: "paid"},
					},
				}},
			}},
		}},
	}
}

func manyLogsRequest(records, bodyBytes int) *collogspb.ExportLogsServiceRequest {
	request := sampleLogsRequest()
	scope := request.ResourceLogs[0].ScopeLogs[0]
	scope.LogRecords = nil
	for i := range records {
		scope.LogRecords = append(scope.LogRecords, &logspb.LogRecord{
			TimeUnixNano: uint64(i + 1),
			Body: &commonpb.AnyValue{
				Value: &commonpb.AnyValue_StringValue{
					StringValue: strings.Repeat("x", bodyBytes),
				},
			},
		})
	}
	return request
}

func logsEnvelope(t *testing.T, request *collogspb.ExportLogsServiceRequest) signal.Envelope {
	t.Helper()
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

func TestLogsRoundTripGRPCAndHTTP(t *testing.T) {
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
			receiver.SetLogsEmitter(func(_ context.Context, envelope signal.Envelope) error {
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
			exporter, err := exp.NewLogs(exp.Config{
				Endpoint: endpoint, Protocol: protocol, Timeout: 3 * time.Second,
			}, logger)
			if err != nil {
				t.Fatal(err)
			}
			defer exporter.Close()

			request := sampleLogsRequest()
			if err := exporter.Send(context.Background(), logsEnvelope(t, request)); err != nil {
				t.Fatalf("send: %v", err)
			}
			select {
			case envelope := <-got:
				if envelope.Kind != signal.Logs || envelope.Schema != signal.OTLPLogsSchema {
					t.Fatalf("envelope kind/schema = %q/%q", envelope.Kind, envelope.Schema)
				}
				if envelope.Resource["service.name"] != "checkout" {
					t.Fatalf("envelope resource = %v, want service.name identity", envelope.Resource)
				}
				var decoded collogspb.ExportLogsServiceRequest
				if err := proto.Unmarshal(envelope.Payload, &decoded); err != nil {
					t.Fatal(err)
				}
				if !proto.Equal(&decoded, request) {
					t.Fatalf("logs changed across round trip: got=%v want=%v", &decoded, request)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for logs envelope")
			}
		})
	}
}

func TestLogsIngestSplitsIntoIndependentDurableEnvelopes(t *testing.T) {
	receiver := &Receiver{
		logsEmit:           func(context.Context, signal.Envelope) error { return nil },
		maxLogRequestBytes: 900,
	}
	var envelopes []signal.Envelope
	receiver.logsEmit = func(_ context.Context, envelope signal.Envelope) error {
		envelopes = append(envelopes, envelope)
		return nil
	}
	if err := receiver.ingestLogs(context.Background(), manyLogsRequest(10, 256)); err != nil {
		t.Fatal(err)
	}
	if len(envelopes) < 2 {
		t.Fatalf("envelopes=%d, want splitting", len(envelopes))
	}
	ids := make(map[string]struct{}, len(envelopes))
	records := 0
	for i, envelope := range envelopes {
		if len(envelope.Payload) > 900 {
			t.Fatalf("envelope %d payload=%d > 900", i, len(envelope.Payload))
		}
		if _, duplicate := ids[envelope.ID]; duplicate {
			t.Fatalf("duplicate chunk ID %q", envelope.ID)
		}
		ids[envelope.ID] = struct{}{}
		var request collogspb.ExportLogsServiceRequest
		if err := proto.Unmarshal(envelope.Payload, &request); err != nil {
			t.Fatal(err)
		}
		records += len(request.ResourceLogs[0].ScopeLogs[0].LogRecords)
	}
	if records != 10 {
		t.Fatalf("records=%d, want 10", records)
	}
}

func TestLogsIngestReportsPartialAdmissionFailure(t *testing.T) {
	sentinel := errors.New("disk")
	calls := 0
	receiver := &Receiver{maxLogRequestBytes: 900}
	receiver.logsEmit = func(_ context.Context, _ signal.Envelope) error {
		calls++
		if calls == 2 {
			return sentinel
		}
		return nil
	}
	err := receiver.ingestLogs(context.Background(), manyLogsRequest(10, 256))
	if !errors.Is(err, sentinel) {
		t.Fatalf("error=%v, want sentinel", err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d, want stop at second chunk", calls)
	}
}

func TestLogsIngestRejectsSingleOversizedRecordPermanently(t *testing.T) {
	receiver := &Receiver{
		maxLogRequestBytes: 512,
		logsEmit: func(context.Context, signal.Envelope) error {
			t.Fatal("oversized record reached durability emitter")
			return nil
		},
	}
	err := receiver.ingestLogs(context.Background(), manyLogsRequest(1, 2048))
	if !errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("error=%v, want ErrPermanent", err)
	}
}

func TestLogsHTTPOversizedRecordReturns413(t *testing.T) {
	receiver := &Receiver{
		maxLogRequestBytes: 512,
		logsEmit: func(context.Context, signal.Envelope) error {
			t.Fatal("oversized record reached durability emitter")
			return nil
		},
	}
	body, err := proto.Marshal(manyLogsRequest(1, 2048))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "/v1/logs", bytes.NewReader(body),
	)
	response := httptest.NewRecorder()
	receiver.handleLogsHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d, want 413", response.Code)
	}
}

func TestSplitLogsSurviveQueueRestart(t *testing.T) {
	dir := t.TempDir()
	downstream := &durableLogsSender{down: true}
	queue1, err := spool.NewQueue(downstream, spool.Config{
		Dir: dir, MaxBytes: 1 << 20, DrainInterval: time.Hour,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	receiver := &Receiver{
		maxLogRequestBytes: 900,
		logsEmit:           queue1.Accept,
	}
	if err := receiver.ingestLogs(context.Background(), manyLogsRequest(10, 256)); err != nil {
		t.Fatal(err)
	}
	spooled := queue1.SignalCount(signal.Logs)
	if spooled < 2 {
		t.Fatalf("spooled chunks=%d, want split records", spooled)
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
	if queue2.SignalCount(signal.Logs) != spooled {
		t.Fatalf("restart depth=%d, want %d", queue2.SignalCount(signal.Logs), spooled)
	}
	if err := queue2.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if queue2.Count() != 0 {
		t.Fatalf("queue count after recovery=%d, want 0", queue2.Count())
	}

	var records int
	ids := make(map[string]struct{})
	for _, envelope := range downstream.snapshot() {
		if _, duplicate := ids[envelope.ID]; duplicate {
			t.Fatalf("duplicate delivery for chunk %q", envelope.ID)
		}
		ids[envelope.ID] = struct{}{}
		var request collogspb.ExportLogsServiceRequest
		if err := proto.Unmarshal(envelope.Payload, &request); err != nil {
			t.Fatal(err)
		}
		for _, resource := range request.ResourceLogs {
			for _, scope := range resource.ScopeLogs {
				records += len(scope.LogRecords)
			}
		}
	}
	if records != 10 {
		t.Fatalf("recovered records=%d, want 10", records)
	}
}
