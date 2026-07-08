package spool

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
)

// gate is an inner exporter that succeeds for the first `allow` calls, then
// fails - letting a test drain an exact number of spooled batches.
type gate struct {
	mu    sync.Mutex
	allow int
}

func (g *gate) Export(context.Context, model.Batch) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.allow <= 0 {
		return io.ErrClosedPipe
	}
	g.allow--
	return nil
}
func (g *gate) Close() error { return nil }
func (g *gate) setAllow(n int) {
	g.mu.Lock()
	g.allow = n
	g.mu.Unlock()
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func batchSize(t *testing.T) int64 {
	t.Helper()
	data, err := encode(oneBatch)
	if err != nil {
		t.Fatal(err)
	}
	return int64(len(data))
}

// TestBackpressureWatermarkHysteresis: pressure engages at/above the high mark,
// holds while draining through the band, and releases only at/below the low mark.
func TestBackpressureWatermarkHysteresis(t *testing.T) {
	dir := t.TempDir()
	sz := batchSize(t)
	in := &gate{} // always fails initially -> everything spools
	e, err := New(in, Config{
		Dir:           dir,
		MaxBytes:      20 * sz,
		HighWatermark: 3 * sz,
		LowWatermark:  1 * sz,
		DrainInterval: time.Hour, // no auto-drain; we drive it
	}, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	enq := func() {
		if err := e.Export(context.Background(), oneBatch); err != nil {
			t.Fatalf("export: %v", err)
		}
	}

	enq() // 1*sz: below high
	if e.UnderPressure() {
		t.Fatal("pressure should be off at 1 batch")
	}
	enq()
	enq() // 3*sz: at high -> engage
	if !e.UnderPressure() {
		t.Fatalf("pressure should engage at high mark (bytes=%d high=%d)", e.Bytes(), 3*sz)
	}
	if e.Count() != 3 {
		t.Fatalf("count = %d, want 3", e.Count())
	}

	// Drain exactly one (lands in the band between low and high): pressure HOLDS.
	in.setAllow(1)
	e.drain(context.Background())
	if e.Count() != 2 {
		t.Fatalf("count after draining 1 = %d, want 2", e.Count())
	}
	if !e.UnderPressure() {
		t.Fatal("pressure must hold in the band (hysteresis)")
	}

	// Drain the rest -> at/below low mark -> release.
	in.setAllow(10)
	e.drain(context.Background())
	if e.Count() != 0 {
		t.Fatalf("count after full drain = %d, want 0", e.Count())
	}
	if e.UnderPressure() {
		t.Fatal("pressure must release at/below low mark")
	}
}

// TestCachedDepthTracksDisk: Bytes/Count match what is on disk across spool+drain.
func TestCachedDepthTracksDisk(t *testing.T) {
	dir := t.TempDir()
	in := &gate{}
	e, err := New(in, Config{Dir: dir, MaxBytes: 1 << 20, DrainInterval: time.Hour}, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	for range 4 {
		_ = e.Export(context.Background(), oneBatch)
	}
	if e.Count() != 4 || int(e.Count()) != countFiles(dir) {
		t.Fatalf("count=%d files=%d, want 4/4", e.Count(), countFiles(dir))
	}
	if e.Bytes() != batchSize(t)*4 {
		t.Fatalf("bytes=%d, want %d", e.Bytes(), batchSize(t)*4)
	}

	in.setAllow(10)
	e.drain(context.Background())
	if e.Count() != 0 || e.Bytes() != 0 || countFiles(dir) != 0 {
		t.Fatalf("after drain count=%d bytes=%d files=%d, want 0/0/0", e.Count(), e.Bytes(), countFiles(dir))
	}
}

// TestMaxAgeExpiry drops spooled batches older than max_age.
func TestMaxAgeExpiry(t *testing.T) {
	dir := t.TempDir()
	in := &gate{} // failing -> spools
	e, err := New(in, Config{Dir: dir, MaxBytes: 1 << 20, MaxAge: time.Millisecond, DrainInterval: time.Hour}, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	_ = e.Export(context.Background(), oneBatch)
	_ = e.Export(context.Background(), oneBatch)
	if e.Count() != 2 {
		t.Fatalf("count = %d, want 2", e.Count())
	}
	time.Sleep(20 * time.Millisecond) // exceed max_age
	e.expireOld()
	if e.Count() != 0 || countFiles(dir) != 0 {
		t.Fatalf("after expiry count=%d files=%d, want 0/0", e.Count(), countFiles(dir))
	}
}

// TestSeedDepthOnRestart: a new spool over an existing dir counts leftover files.
func TestSeedDepthOnRestart(t *testing.T) {
	dir := t.TempDir()
	down := &gate{} // failing
	e1, err := New(down, Config{Dir: dir, MaxBytes: 1 << 20, DrainInterval: time.Hour}, discard())
	if err != nil {
		t.Fatal(err)
	}
	_ = e1.Export(context.Background(), oneBatch)
	_ = e1.Export(context.Background(), oneBatch)
	_ = e1.Close()

	e2, err := New(&gate{}, Config{Dir: dir, MaxBytes: 1 << 20, DrainInterval: time.Hour}, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	if e2.Count() != 2 || e2.Bytes() != batchSize(t)*2 {
		t.Fatalf("seeded depth count=%d bytes=%d, want 2/%d", e2.Count(), e2.Bytes(), batchSize(t)*2)
	}
}
