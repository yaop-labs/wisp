package spool

import (
	"context"
	"testing"
	"time"
)

// TestFlushDrainsWhenDownstreamUp: a clean shutdown flushes spooled data when
// downstream is healthy.
func TestFlushDrainsWhenDownstreamUp(t *testing.T) {
	dir := t.TempDir()
	in := &gate{} // failing -> spools
	e, err := New(in, Config{Dir: dir, MaxBytes: 1 << 20, DrainInterval: time.Hour}, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	for range 3 {
		_ = e.Export(context.Background(), oneBatch)
	}
	if e.Count() != 3 {
		t.Fatalf("count = %d, want 3", e.Count())
	}

	in.setAllow(100) // downstream recovers
	if err := e.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if e.Count() != 0 || countFiles(dir) != 0 {
		t.Fatalf("after flush count=%d files=%d, want 0/0", e.Count(), countFiles(dir))
	}
}

// TestFlushReturnsWhenDownstreamDown: Flush makes no progress and returns
// promptly (data stays durable for the next start) rather than spinning.
func TestFlushReturnsWhenDownstreamDown(t *testing.T) {
	dir := t.TempDir()
	in := &gate{} // stays failing
	e, err := New(in, Config{Dir: dir, MaxBytes: 1 << 20, DrainInterval: time.Hour}, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	_ = e.Export(context.Background(), oneBatch)

	done := make(chan error, 1)
	go func() { done <- e.Flush(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("flush: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Flush did not return promptly when downstream is down")
	}
	if e.Count() != 1 {
		t.Fatalf("count = %d, want 1 (data preserved)", e.Count())
	}
}
