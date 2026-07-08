package retry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
)

type flaky struct {
	failUntil int
	calls     int
}

func (f *flaky) Export(context.Context, model.Batch) error {
	f.calls++
	if f.calls <= f.failUntil {
		return errors.New("boom")
	}
	return nil
}
func (f *flaky) Close() error { return nil }

func TestRetrySucceedsAfterFailures(t *testing.T) {
	f := &flaky{failUntil: 2}
	e := Wrap(f, Config{MaxAttempts: 5, InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond})
	if err := e.Export(context.Background(), model.Batch{}); err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if f.calls != 3 {
		t.Errorf("expected 3 calls (2 fail + 1 ok), got %d", f.calls)
	}
}

func TestRetryGivesUp(t *testing.T) {
	f := &flaky{failUntil: 100}
	e := Wrap(f, Config{MaxAttempts: 3, InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond})
	if err := e.Export(context.Background(), model.Batch{}); err == nil {
		t.Fatal("expected error after exhausting attempts")
	}
	if f.calls != 3 {
		t.Errorf("expected exactly 3 attempts, got %d", f.calls)
	}
}
