package otlp

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	exp "github.com/yaop-labs/wisp/internal/exporter/otlp"
	"github.com/yaop-labs/wisp/internal/model"
)

func mustReceiver(t *testing.T, opts Options, logger *slog.Logger) *Receiver {
	t.Helper()
	r, err := New(opts, logger)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestRoundTrip sends a batch through wisp's OTLP exporter into wisp's OTLP
// receiver and asserts the series survive the wire round-trip intact.
func TestRoundTrip(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := mustReceiver(t, Options{GRPCAddr: "127.0.0.1:0"}, logger)

	ctx := t.Context()
	got := make(chan model.Batch, 1)
	go func() {
		_ = r.Start(ctx, func(_ context.Context, b model.Batch) error {
			got <- b
			return nil
		})
	}()

	addr := r.GRPCAddr()
	if addr == "" {
		t.Fatal("receiver did not bind")
	}

	e, err := exp.New(exp.Config{Endpoint: addr, Protocol: "grpc", Timeout: 5 * time.Second}, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	resource := model.Labels{{Name: "service.name", Value: "app"}}
	sent := model.Batch{Series: []model.Series{
		{
			Name: "http_requests_total", Type: model.MetricSum, Monotonic: true, Resource: resource,
			Attrs:  model.Labels{{Name: "code", Value: "200"}},
			Points: []model.Point{{TimeUnixNano: 100, IntValue: 42}},
		},
		{
			Name: "temperature", Type: model.MetricGauge, Resource: resource,
			Points: []model.Point{{TimeUnixNano: 100, FloatValue: 21.5, IsFloat: true}},
		},
	}}
	if err := e.Export(context.Background(), sent); err != nil {
		t.Fatalf("export: %v", err)
	}

	select {
	case b := <-got:
		if b.Len() != 2 {
			t.Fatalf("received %d points, want 2", b.Len())
		}
		byName := map[string]model.Series{}
		for _, s := range b.Series {
			byName[s.Name] = s
		}
		c := byName["http_requests_total"]
		if c.Type != model.MetricSum || !c.Monotonic || c.Points[0].IsFloat || c.Points[0].IntValue != 42 {
			t.Errorf("counter not preserved: %+v", c)
		}
		if labelValue(c.Resource, "service.name") != "app" || labelValue(c.Attrs, "code") != "200" {
			t.Errorf("labels not preserved: resource=%v attrs=%v", c.Resource, c.Attrs)
		}
		g := byName["temperature"]
		if g.Type != model.MetricGauge || !g.Points[0].IsFloat || g.Points[0].FloatValue != 21.5 {
			t.Errorf("gauge not preserved: %+v", g)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for received batch")
	}
}

// TestRoundTripHistogram pushes an exponential-histogram series through the
// exporter into the receiver and asserts the payload survives the OTLP wire.
func TestRoundTripHistogram(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := mustReceiver(t, Options{GRPCAddr: "127.0.0.1:0"}, logger)
	ctx := t.Context()
	got := make(chan model.Batch, 1)
	go func() {
		_ = r.Start(ctx, func(_ context.Context, b model.Batch) error {
			got <- b
			return nil
		})
	}()

	e, err := exp.New(exp.Config{Endpoint: r.GRPCAddr(), Protocol: "grpc", Timeout: 5 * time.Second}, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	sent := model.Batch{Series: []model.Series{{
		Name:     "request_duration_seconds",
		Type:     model.MetricExponentialHistogram,
		Resource: model.Labels{{Name: "service.name", Value: "app"}},
		Points: []model.Point{{TimeUnixNano: 5, Hist: &model.ExpHistogram{
			Scale: 3, ZeroCount: 1, PositiveOffset: -4, PositiveCounts: []uint64{2, 3, 4}, Sum: 4.2, Count: 10,
		}}},
	}}}
	if err := e.Export(context.Background(), sent); err != nil {
		t.Fatalf("export: %v", err)
	}

	select {
	case b := <-got:
		if b.Len() != 1 || b.Series[0].Points[0].Hist == nil {
			t.Fatal("histogram not received")
		}
		eh := b.Series[0].Points[0].Hist
		if eh.Count != 10 || eh.Sum != 4.2 || eh.Scale != 3 || eh.ZeroCount != 1 || eh.PositiveOffset != -4 {
			t.Errorf("histogram fields not preserved: %+v", eh)
		}
		if len(eh.PositiveCounts) != 3 || eh.PositiveCounts[1] != 3 {
			t.Errorf("bucket counts not preserved: %v", eh.PositiveCounts)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for histogram")
	}
}

// TestGRPCStopHonorsContext: a stalled in-flight RPC must not let Stop outlast
// its context. GracefulStop alone would hang until the handler returns.
func TestGRPCStopHonorsContext(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := mustReceiver(t, Options{GRPCAddr: "127.0.0.1:0"}, logger)

	inHandler := make(chan struct{})
	block := make(chan struct{})
	defer close(block)
	go func() {
		_ = r.Start(t.Context(), func(hctx context.Context, _ model.Batch) error {
			close(inHandler)
			// Stall until either the test ends or Stop cancels the RPC context.
			// GracefulStop alone never cancels it, so the old Stop would hang here.
			select {
			case <-block:
			case <-hctx.Done():
			}
			return nil
		})
	}()

	e, err := exp.New(exp.Config{Endpoint: r.GRPCAddr(), Protocol: "grpc", Timeout: 30 * time.Second}, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	go func() {
		_ = e.Export(context.Background(), model.Batch{Series: []model.Series{{
			Name: "m", Type: model.MetricGauge,
			Resource: model.Labels{{Name: "service.name", Value: "app"}},
			Points:   []model.Point{{IntValue: 1}},
		}}})
	}()
	<-inHandler // an RPC is now stalled in the handler

	stopCtx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Stop(stopCtx) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop hung on a stalled in-flight RPC (GracefulStop ignored ctx)")
	}
}

func labelValue(ls model.Labels, name string) string {
	for _, l := range ls {
		if l.Name == name {
			return l.Value
		}
	}
	return ""
}
