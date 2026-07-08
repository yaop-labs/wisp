package spool

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
)

type toggle struct {
	mu   sync.Mutex
	fail bool
	got  int
}

func (t *toggle) Export(context.Context, model.Batch) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fail {
		return io.ErrClosedPipe
	}
	t.got++
	return nil
}
func (t *toggle) Close() error { return nil }
func (t *toggle) setFail(v bool) {
	t.mu.Lock()
	t.fail = v
	t.mu.Unlock()
}
func (t *toggle) sent() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.got
}

func countFiles(dir string) int {
	entries, _ := os.ReadDir(dir)
	n := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == fileSuffix {
			n++
		}
	}
	return n
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", msg)
}

var oneBatch = model.Batch{Series: []model.Series{{
	Name:   "x",
	Type:   model.MetricGauge,
	Points: []model.Point{{TimeUnixNano: 1, IntValue: 7}},
}}}

func TestSpoolAndDrain(t *testing.T) {
	dir := t.TempDir()
	in := &toggle{fail: true}
	e, err := New(in, Config{Dir: dir, DrainInterval: 20 * time.Millisecond}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	// Inner failing -> Export accepts (returns nil) and spools to disk.
	if err := e.Export(context.Background(), oneBatch); err != nil {
		t.Fatalf("export should accept by spooling, got %v", err)
	}
	if countFiles(dir) != 1 {
		t.Fatalf("expected 1 spooled file, got %d", countFiles(dir))
	}

	// Downstream recovers -> drainer re-sends and removes the file.
	in.setFail(false)
	waitFor(t, func() bool { return countFiles(dir) == 0 }, "spool to drain")
	if in.sent() < 1 {
		t.Error("expected the spooled batch to be re-sent")
	}
}

func TestSpoolSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// First agent: inner down, batch gets spooled, then we shut down.
	down := &toggle{fail: true}
	e1, err := New(down, Config{Dir: dir, DrainInterval: time.Hour}, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := e1.Export(context.Background(), oneBatch); err != nil {
		t.Fatal(err)
	}
	_ = e1.Close()
	if countFiles(dir) != 1 {
		t.Fatalf("expected 1 file persisted across restart, got %d", countFiles(dir))
	}

	// Second agent over the same dir, downstream healthy -> drains the leftover.
	up := &toggle{fail: false}
	e2, err := New(up, Config{Dir: dir, DrainInterval: 20 * time.Millisecond}, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	waitFor(t, func() bool { return countFiles(dir) == 0 }, "leftover spool to drain after restart")
	if up.sent() < 1 {
		t.Error("restarted agent should re-send the leftover batch")
	}
}
