package app

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/yaop-labs/wisp/internal/config"
)

type logsCollector struct {
	collogspb.UnimplementedLogsServiceServer
	got chan *collogspb.ExportLogsServiceRequest
}

func (c *logsCollector) Export(_ context.Context, request *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	c.got <- request
	return &collogspb.ExportLogsServiceResponse{}, nil
}

func TestAppRoutesOTLPLogsThroughSharedSpool(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	collector := &logsCollector{got: make(chan *collogspb.ExportLogsServiceRequest, 1)}
	server := grpc.NewServer()
	collogspb.RegisterLogsServiceServer(server, collector)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	yaml := fmt.Sprintf(`
sources:
  otlp:
    grpc: "127.0.0.1:0"
exporter:
  otlp:
    endpoint: %q
    protocol: grpc
    retry:
      max_attempts: 1
  spool:
    dir: %q
    max_bytes: 1048576
    signal_limits:
      logs:
        max_bytes: 524288
resource:
  attributes:
    service.name: wisp-test
`, listener.Addr().String(), t.TempDir())
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	application, err := New(cfg, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := application.Start(runCtx); err != nil {
		t.Fatal(err)
	}

	connection, err := grpc.NewClient(
		application.otlpReceiver.GRPCAddr(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	request := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			ScopeLogs: []*logspb.ScopeLogs{{
				LogRecords: []*logspb.LogRecord{{
					TimeUnixNano: 1,
					Body: &commonpb.AnyValue{
						Value: &commonpb.AnyValue_StringValue{StringValue: "hello"},
					},
				}},
			}},
		}},
	}
	if _, err := collogspb.NewLogsServiceClient(connection).Export(t.Context(), request); err != nil {
		t.Fatalf("send logs to wisp: %v", err)
	}
	select {
	case got := <-collector.got:
		if got.ResourceLogs[0].ScopeLogs[0].LogRecords[0].Body.GetStringValue() != "hello" {
			t.Fatalf("collector got changed log: %v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for downstream logs")
	}

	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := application.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
}
