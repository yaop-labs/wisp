package otlp

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"

	exp "github.com/yaop-labs/wisp/internal/exporter/otlp"
	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/signal"
)

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
