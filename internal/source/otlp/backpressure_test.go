package otlp

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/pipeline"
)

// onePointRequest is a minimal OTLP request with one supported (gauge) point so
// ingest reaches emit (it short-circuits on empty payloads).
func onePointRequest() *colmetricspb.ExportMetricsServiceRequest {
	return &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
				Key: "service.name", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "app"}},
			}}},
			ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
				Name: "g",
				Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{
					TimeUnixNano: 1, Value: &metricspb.NumberDataPoint_AsInt{AsInt: 1},
				}}}},
			}}}},
		}},
	}
}

// TestReceiverSignalsBackpressure: when emit returns ErrBackpressure, the gRPC
// service answers RESOURCE_EXHAUSTED and the HTTP endpoint answers 429.
func TestReceiverSignalsBackpressure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := New(Options{GRPCAddr: "127.0.0.1:0", HTTPAddr: "127.0.0.1:0"}, logger)
	ctx := t.Context()
	go func() {
		_ = r.Start(ctx, func(context.Context, model.Batch) error { return pipeline.ErrBackpressure })
	}()

	// gRPC -> ResourceExhausted
	conn, err := grpc.NewClient(r.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err = colmetricspb.NewMetricsServiceClient(conn).Export(cctx, onePointRequest())
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("grpc status = %v, want ResourceExhausted", status.Code(err))
	}

	// HTTP -> 429 Too Many Requests
	body, _ := proto.Marshal(onePointRequest())
	resp, err := http.Post("http://"+r.HTTPAddr()+"/v1/metrics", "application/x-protobuf", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("http status = %d, want 429", resp.StatusCode)
	}
}
