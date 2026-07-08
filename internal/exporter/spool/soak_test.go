package spool

import (
	"context"
	"io"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
)

// recorder is an inner exporter that records which point IDs landed (and how
// many times), and can be flipped between down and up.
type recorder struct {
	mu  sync.Mutex
	up  bool
	got map[int64]int
}

func newRecorder() *recorder { return &recorder{got: make(map[int64]int)} }

func (r *recorder) Export(_ context.Context, b model.Batch) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.up {
		return io.ErrClosedPipe
	}
	for _, s := range b.Series {
		for _, p := range s.Points {
			r.got[p.IntValue]++
		}
	}
	return nil
}
func (r *recorder) Close() error { return nil }
func (r *recorder) setUp(v bool) { r.mu.Lock(); r.up = v; r.mu.Unlock() }
func (r *recorder) snapshot() map[int64]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[int64]int, len(r.got))
	maps.Copy(out, r.got)
	return out
}

func batchWithID(id int64) model.Batch {
	return model.Batch{Series: []model.Series{{
		Name:   "m",
		Type:   model.MetricGauge,
		Points: []model.Point{{TimeUnixNano: uint64(id + 1), IntValue: id}},
	}}}
}

// TestSoakDowntimeUnderLoadZeroLoss feeds N batches concurrently while the
// downstream is DOWN (everything spools), then brings it up and asserts every
// batch is delivered exactly once - no loss, no duplicates. Unbounded spool so
// nothing is shed (the 0-loss contract assumes the outage fits the budget).
func TestSoakDowntimeUnderLoadZeroLoss(t *testing.T) {
	const (
		n       = 500
		workers = 8
	)
	dir := t.TempDir()
	in := newRecorder() // starts down
	e, err := New(in, Config{Dir: dir, MaxBytes: 0 /* unbounded */, DrainInterval: 20 * time.Millisecond}, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	// Produce N uniquely-identified batches concurrently while downstream is down.
	var wg sync.WaitGroup
	ids := make(chan int64)
	for range workers {
		wg.Go(func() {
			for id := range ids {
				if err := e.Export(context.Background(), batchWithID(id)); err != nil {
					t.Errorf("export %d: %v", id, err)
				}
			}
		})
	}
	for i := range int64(n) {
		ids <- i
	}
	close(ids)
	wg.Wait()

	if e.Count() != n {
		t.Fatalf("spooled %d, want %d (downstream was down)", e.Count(), n)
	}

	// Recover downstream -> the drainer flushes everything.
	in.setUp(true)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(in.snapshot()) == n && e.Count() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	got := in.snapshot()
	if len(got) != n {
		t.Fatalf("delivered %d distinct points, want %d (data lost)", len(got), n)
	}
	for id := range int64(n) {
		switch got[id] {
		case 1: // exactly once
		case 0:
			t.Fatalf("point %d never delivered (loss)", id)
		default:
			t.Fatalf("point %d delivered %d times (duplicate)", id, got[id])
		}
	}
	if e.Count() != 0 {
		t.Fatalf("spool not empty after drain: %d", e.Count())
	}
}
