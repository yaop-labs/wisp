package pipeline

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
)

// recordExporter records points and whether Close was called.
type recordExporter struct {
	mu     sync.Mutex
	points int
	closed bool
}

func (e *recordExporter) Export(_ context.Context, b model.Batch) error {
	e.mu.Lock()
	e.points += b.Len()
	e.mu.Unlock()
	return nil
}
func (e *recordExporter) Close() error {
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	return nil
}
func (e *recordExporter) snapshot() (int, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.points, e.closed
}

// dropProcessor drops everything; closed tracks Close.
type dropProcessor struct{ closed bool }

func (p *dropProcessor) Process(context.Context, model.Batch) (model.Batch, error) {
	return model.Batch{}, nil
}
func (p *dropProcessor) Close() error { p.closed = true; return nil }

// passProcessor passes batches through unchanged.
type passProcessor struct{}

func (passProcessor) Process(_ context.Context, b model.Batch) (model.Batch, error) { return b, nil }
func (passProcessor) Close() error                                                  { return nil }

func logger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestPipelineEndToEnd(t *testing.T) {
	src := &captureSource{emitCh: make(chan func(context.Context, model.Batch) error, 1)}
	exp := &recordExporter{}
	p := New(Config{Workers: 2, QueueSize: 16}, logger())
	p.AddSource(src)
	p.AddProcessor(passProcessor{})
	p.AddExporter(exp)

	ctx, cancel := context.WithCancel(context.Background())
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	emit := <-src.emitCh
	if err := emit(ctx, oneBatch); err != nil {
		t.Fatalf("emit: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if pts, _ := exp.snapshot(); pts == oneBatch.Len() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if pts, _ := exp.snapshot(); pts != oneBatch.Len() {
		t.Fatalf("exporter got %d points, want %d", pts, oneBatch.Len())
	}

	cancel()
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if _, closed := exp.snapshot(); !closed {
		t.Error("Shutdown should close the exporter")
	}
}

func TestPipelineProcessorDropsBatch(t *testing.T) {
	src := &captureSource{emitCh: make(chan func(context.Context, model.Batch) error, 1)}
	exp := &recordExporter{}
	drop := &dropProcessor{}
	p := New(Config{Workers: 1, QueueSize: 8}, logger())
	p.AddSource(src)
	p.AddProcessor(drop)
	p.AddExporter(exp)

	ctx, cancel := context.WithCancel(context.Background())
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = p.Shutdown(context.Background()) }()

	emit := <-src.emitCh
	_ = emit(ctx, oneBatch)

	// Give the worker a moment; the dropping processor must prevent any export.
	time.Sleep(100 * time.Millisecond)
	if pts, _ := exp.snapshot(); pts != 0 {
		t.Fatalf("exporter got %d points, want 0 (processor dropped the batch)", pts)
	}

	cancel()
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if !drop.closed {
		t.Error("Shutdown should close the processor")
	}
}

func TestPipelineShutdownIdempotent(t *testing.T) {
	p := New(Config{Workers: 1, QueueSize: 4}, logger())
	exp := &recordExporter{}
	p.AddExporter(exp)
	ctx, cancel := context.WithCancel(context.Background())
	_ = p.Start(ctx)
	cancel()
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Second Shutdown must be safe (no panic, no double-close issues).
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
}
