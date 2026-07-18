package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/yaop-labs/wisp/internal/config"
)

type tracesCollector struct {
	coltracepb.UnimplementedTraceServiceServer
	got   chan *coltracepb.ExportTraceServiceRequest
	ids   chan string
	kinds chan string
}

func (c *tracesCollector) Export(ctx context.Context, request *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	c.ids <- firstMetadataValue(md, "x-wisp-envelope-id")
	c.kinds <- firstMetadataValue(md, "x-wisp-signal-kind")
	c.got <- request
	return &coltracepb.ExportTraceServiceResponse{}, nil
}

func TestAppRoutesOTLPTracesThroughSharedSpool(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	collector := &tracesCollector{
		got:   make(chan *coltracepb.ExportTraceServiceRequest, 1),
		ids:   make(chan string, 1),
		kinds: make(chan string, 1),
	}
	server := grpc.NewServer()
	coltracepb.RegisterTraceServiceServer(server, collector)
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
      traces:
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
	if _, err := coltracepb.NewTraceServiceClient(connection).Export(t.Context(), request); err != nil {
		t.Fatalf("send traces to wisp: %v", err)
	}
	select {
	case got := <-collector.got:
		if got.ResourceSpans[0].ScopeSpans[0].Spans[0].Name != "checkout" {
			t.Fatalf("collector got changed span: %v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for downstream traces")
	}
	select {
	case id := <-collector.ids:
		if decoded, err := hex.DecodeString(id); err != nil || len(decoded) != 16 {
			t.Fatalf("delivery envelope id=%q, want 32 hex chars", id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for delivery metadata")
	}
	select {
	case kind := <-collector.kinds:
		if kind != "traces" {
			t.Fatalf("delivery signal kind=%q, want traces", kind)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for signal metadata")
	}

	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := application.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
}
