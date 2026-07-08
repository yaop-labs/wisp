package otlp

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"

	"github.com/yaop-labs/wisp/internal/model"
)

type sink struct {
	colmetricspb.UnimplementedMetricsServiceServer
	mu  sync.Mutex
	got *colmetricspb.ExportMetricsServiceRequest
}

func (s *sink) Export(_ context.Context, req *colmetricspb.ExportMetricsServiceRequest) (*colmetricspb.ExportMetricsServiceResponse, error) {
	s.mu.Lock()
	s.got = req
	s.mu.Unlock()
	return &colmetricspb.ExportMetricsServiceResponse{}, nil
}

func startSink(t *testing.T) (string, *sink) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	s := &sink{}
	colmetricspb.RegisterMetricsServiceServer(srv, s)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return ln.Addr().String(), s
}

func TestExporterShipsOTLP(t *testing.T) {
	addr, s := startSink(t)
	exp, err := New(Config{Endpoint: addr, Protocol: "grpc", Timeout: 5 * time.Second},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer exp.Close()

	resource := model.Labels{{Name: "service.name", Value: "wisp"}}
	batch := model.Batch{Series: []model.Series{
		{
			Name: "node_load1", Type: model.MetricGauge, Resource: resource,
			Points: []model.Point{{TimeUnixNano: 1, FloatValue: 1.5, IsFloat: true}},
		},
		{
			Name: "node_cpu_seconds_total", Type: model.MetricSum, Monotonic: true, Resource: resource,
			Attrs:  model.Labels{{Name: "cpu", Value: "0"}, {Name: "mode", Value: "user"}},
			Points: []model.Point{{TimeUnixNano: 1, IntValue: 42}},
		},
	}}

	if err := exp.Export(context.Background(), batch); err != nil {
		t.Fatalf("export: %v", err)
	}

	s.mu.Lock()
	got := s.got
	s.mu.Unlock()
	if got == nil {
		t.Fatal("sink received nothing")
	}

	// Both series share a resource -> one ResourceMetrics, one scope, two metrics.
	if len(got.ResourceMetrics) != 1 {
		t.Fatalf("ResourceMetrics = %d, want 1", len(got.ResourceMetrics))
	}
	rm := got.ResourceMetrics[0]
	if got := attrString(rm.Resource.GetAttributes(), "service.name"); got != "wisp" {
		t.Errorf("resource service.name = %q, want wisp", got)
	}
	if len(rm.ScopeMetrics) != 1 || rm.ScopeMetrics[0].Scope.GetName() != "wisp" {
		t.Fatalf("expected one scope named wisp")
	}
	metrics := rm.ScopeMetrics[0].Metrics
	if len(metrics) != 2 {
		t.Fatalf("metrics = %d, want 2", len(metrics))
	}

	byName := map[string]*metricspb.Metric{}
	for _, m := range metrics {
		byName[m.Name] = m
	}

	gauge := byName["node_load1"].GetGauge()
	if gauge == nil || len(gauge.DataPoints) != 1 || gauge.DataPoints[0].GetAsDouble() != 1.5 {
		t.Errorf("node_load1 should be a gauge with value 1.5")
	}

	sum := byName["node_cpu_seconds_total"].GetSum()
	if sum == nil {
		t.Fatal("node_cpu_seconds_total should be a sum")
	}
	if !sum.IsMonotonic {
		t.Error("cpu sum should be monotonic")
	}
	if sum.AggregationTemporality != metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE {
		t.Error("cpu sum should be cumulative")
	}
	dp := sum.DataPoints[0]
	if dp.GetAsInt() != 42 {
		t.Errorf("cpu value = %d, want 42", dp.GetAsInt())
	}
	if len(dp.Attributes) != 2 {
		t.Errorf("cpu datapoint attrs = %d, want 2 (cpu, mode)", len(dp.Attributes))
	}
}

func attrString(kvs []*commonpb.KeyValue, key string) string {
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Value.GetStringValue()
		}
	}
	return ""
}
