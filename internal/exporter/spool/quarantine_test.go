package spool

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
)

// classInner spools everything while spoolNow is set, then classifies by series
// name: a "poison" batch fails permanently, anything else drains.
type classInner struct {
	mu       sync.Mutex
	spoolNow bool
	drained  []string
}

func (c *classInner) Export(_ context.Context, b model.Batch) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.spoolNow {
		return io.ErrClosedPipe // transient -> forces a spool write
	}
	if b.Series[0].Name == "poison" {
		return fmt.Errorf("rejected: %w", pipeline.ErrPermanent)
	}
	c.drained = append(c.drained, b.Series[0].Name)
	return nil
}
func (c *classInner) Close() error { return nil }
func (c *classInner) setSpool(v bool) {
	c.mu.Lock()
	c.spoolNow = v
	c.mu.Unlock()
}
func (c *classInner) sent() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.drained...)
}

func namedBatch(name string) model.Batch {
	return model.Batch{Series: []model.Series{{
		Name: name, Type: model.MetricGauge,
		Points: []model.Point{{TimeUnixNano: 1, IntValue: 7}},
	}}}
}

// TestDrainQuarantinesPermanentBatch: a batch downstream rejects permanently must
// not wedge the head of the drain queue — it is discarded and the healthy batch
// behind it still ships.
func TestDrainQuarantinesPermanentBatch(t *testing.T) {
	dir := t.TempDir()
	in := &classInner{spoolNow: true}
	e, err := New(in, Config{Dir: dir, MaxBytes: 1 << 20, DrainInterval: time.Hour}, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	// Spool the poison batch first (older), then a healthy one behind it.
	if err := e.Export(context.Background(), namedBatch("poison")); err != nil {
		t.Fatal(err)
	}
	if err := e.Export(context.Background(), namedBatch("good")); err != nil {
		t.Fatal(err)
	}
	if countFiles(dir) != 2 {
		t.Fatalf("spooled %d files, want 2", countFiles(dir))
	}

	before := selfobs.SpoolQuarantined.Get()
	in.setSpool(false) // downstream up, but the poison batch is rejected permanently
	e.drain(context.Background())

	if countFiles(dir) != 0 {
		t.Fatalf("after drain %d files remain, want 0 (poison must not wedge the queue)", countFiles(dir))
	}
	if got := in.sent(); len(got) != 1 || got[0] != "good" {
		t.Fatalf("delivered %v, want [good]", got)
	}
	if d := selfobs.SpoolQuarantined.Get() - before; d != 1 {
		t.Errorf("SpoolQuarantined delta = %d, want 1", d)
	}
}
