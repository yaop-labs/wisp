package pipeline

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/selfobs"
)

// captureSource hands the pipeline's emit function back to the test.
type captureSource struct {
	emitCh chan func(context.Context, model.Batch) error
}

func (s *captureSource) Start(ctx context.Context, emit func(context.Context, model.Batch) error) error {
	s.emitCh <- emit
	<-ctx.Done()
	return nil
}
func (s *captureSource) Stop(context.Context) error { return nil }

// collectExporter records the batches that reach the exporter.
type collectExporter struct {
	mu  sync.Mutex
	got int
}

func (e *collectExporter) Export(_ context.Context, b model.Batch) error {
	e.mu.Lock()
	e.got += b.Len()
	e.mu.Unlock()
	return nil
}
func (e *collectExporter) Close() error { return nil }
func (e *collectExporter) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.got
}

var oneBatch = model.Batch{Series: []model.Series{{
	Name:   "x",
	Type:   model.MetricGauge,
	Points: []model.Point{{TimeUnixNano: 1, IntValue: 7}},
}}}

// floodSource emits as fast as it can until its context is cancelled, keeping a
// goroutine parked inside emit() to race Shutdown's close(p.in).
type floodSource struct{}

func (floodSource) Start(ctx context.Context, emit func(context.Context, model.Batch) error) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			// A fresh batch per emit, as real sources produce them — sharing one
			// Series slice across batches would race stripMetaLabels, not close().
			_ = emit(ctx, model.Batch{Series: []model.Series{{
				Name: "x", Type: model.MetricGauge,
				Points: []model.Point{{TimeUnixNano: 1, IntValue: 7}},
			}}})
		}
	}
}
func (floodSource) Stop(context.Context) error { return nil }

func TestShutdownNoPanicUnderActiveSend(t *testing.T) {
	// A source flooding emit() must not panic on shutdown: the pipeline has to
	// join source goroutines before close(p.in), else an in-flight send lands on
	// a closed channel. Run under -race to widen the window.
	p := New(Config{Workers: 2, QueueSize: 4}, logger())
	p.AddSource(floodSource{})
	p.AddExporter(&collectExporter{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // let the flood get going

	// Shutdown itself cancels the run context and joins sources; a clean return
	// (no panic) is the assertion.
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func TestStripMetaLabels(t *testing.T) {
	b := model.Batch{Series: []model.Series{{
		Name: "m",
		Resource: model.Labels{
			{Name: "service.name", Value: "app"},
			{Name: "__meta_dns_name", Value: "svc.local"},
		},
		Attrs: model.Labels{
			{Name: "route", Value: "/x"},
			{Name: "__meta_dns_srv_record_port", Value: "9100"},
		},
	}}}
	stripMetaLabels(&b)
	s := b.Series[0]
	if len(s.Resource) != 1 || s.Resource[0].Name != "service.name" {
		t.Errorf("resource not stripped of __meta_: %v", s.Resource)
	}
	if len(s.Attrs) != 1 || s.Attrs[0].Name != "route" {
		t.Errorf("attrs not stripped of __meta_: %v", s.Attrs)
	}
}

func TestEmitBackpressureSheds(t *testing.T) {
	src := &captureSource{emitCh: make(chan func(context.Context, model.Batch) error, 1)}
	exp := &collectExporter{}
	var pressure atomic.Bool

	p := New(Config{Workers: 1, QueueSize: 8}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.AddSource(src)
	p.AddExporter(exp)
	p.SetPressure(pressure.Load)

	ctx, cancel := context.WithCancel(context.Background())
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = p.Shutdown(context.Background()) }()

	emit := <-src.emitCh

	// Pressure off -> batch is admitted and reaches the exporter.
	if err := emit(ctx, oneBatch); err != nil {
		t.Fatalf("emit (no pressure) = %v, want nil", err)
	}

	// Pressure on -> batch is shed with ErrBackpressure, counter increments.
	pressure.Store(true)
	before := selfobs.BackpressureShed.Get()
	if err := emit(ctx, oneBatch); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("emit (pressure) = %v, want ErrBackpressure", err)
	}
	if got := selfobs.BackpressureShed.Get() - before; got != uint64(oneBatch.Len()) {
		t.Fatalf("BackpressureShed delta = %d, want %d", got, oneBatch.Len())
	}

	// Only the first (admitted) batch should have reached the exporter.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && exp.count() < oneBatch.Len() {
		time.Sleep(5 * time.Millisecond)
	}
	if exp.count() != oneBatch.Len() {
		t.Fatalf("exporter received %d points, want %d (shed batch must not pass)", exp.count(), oneBatch.Len())
	}
}
