package retry

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/signal"
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

type permanentInner struct{ calls int }

func (p *permanentInner) Export(context.Context, model.Batch) error {
	p.calls++
	return fmt.Errorf("otlp: %w", pipeline.ErrPermanent)
}
func (p *permanentInner) Close() error { return nil }

func TestRetryStopsOnPermanent(t *testing.T) {
	p := &permanentInner{}
	e := Wrap(p, Config{MaxAttempts: 5, InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond})
	err := e.Export(context.Background(), model.Batch{})
	if !errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("want ErrPermanent, got %v", err)
	}
	if p.calls != 1 {
		t.Errorf("permanent error retried: %d calls, want 1", p.calls)
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

type flakySender struct {
	failUntil int
	calls     int
}

func (s *flakySender) Send(context.Context, signal.Envelope) error {
	s.calls++
	if s.calls <= s.failUntil {
		return errors.New("boom")
	}
	return nil
}
func (*flakySender) Close() error { return nil }

func TestSignalSenderUsesSameRetrySemantics(t *testing.T) {
	inner := &flakySender{failUntil: 2}
	sender := WrapSender(inner, Config{
		MaxAttempts: 5, InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond,
	})
	envelope, err := signal.New(signal.Logs, "test.v1", "bytes", []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if inner.calls != 3 {
		t.Fatalf("calls = %d, want 3", inner.calls)
	}
}
