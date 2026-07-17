package spool

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/signal"
)

type signalSender struct {
	mu        sync.Mutex
	down      map[signal.Kind]bool
	permanent map[signal.Kind]bool
	sent      []string
}

func (s *signalSender) Send(_ context.Context, envelope signal.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.permanent[envelope.Kind] {
		return errors.Join(errors.New("rejected"), pipeline.ErrPermanent)
	}
	if s.down[envelope.Kind] {
		return io.ErrClosedPipe
	}
	s.sent = append(s.sent, string(envelope.Kind)+":"+string(envelope.Payload))
	return nil
}

func (*signalSender) Close() error { return nil }

func (s *signalSender) setDown(kind signal.Kind, down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down[kind] = down
}

func (s *signalSender) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.sent...)
}

func newSignalSender() *signalSender {
	return &signalSender{
		down:      make(map[signal.Kind]bool),
		permanent: make(map[signal.Kind]bool),
	}
}

func testEnvelope(t *testing.T, kind signal.Kind, payload string) signal.Envelope {
	t.Helper()
	envelope, err := signal.New(kind, "test.v1", "application/octet-stream", []byte(payload), nil)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func recordSize(t *testing.T, envelope signal.Envelope) int64 {
	t.Helper()
	data, err := envelope.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return int64(len(data))
}

func TestDrainFailureIsIsolatedPerSignal(t *testing.T) {
	sender := newSignalSender()
	sender.setDown(signal.Metrics, true)
	sender.setDown(signal.Logs, true)
	q, err := NewQueue(sender, Config{
		Dir: t.TempDir(), MaxBytes: 1 << 20, DrainInterval: time.Hour,
	}, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	for _, envelope := range []signal.Envelope{
		testEnvelope(t, signal.Metrics, "m1"),
		testEnvelope(t, signal.Logs, "l1"),
		testEnvelope(t, signal.Metrics, "m2"),
		testEnvelope(t, signal.Logs, "l2"),
	} {
		if err := q.Accept(context.Background(), envelope); err != nil {
			t.Fatal(err)
		}
	}

	sender.setDown(signal.Logs, false)
	q.drain(context.Background())

	if got := sender.snapshot(); len(got) != 2 ||
		got[0] != "logs:l1" || got[1] != "logs:l2" {
		t.Fatalf("delivered %v, want both logs in order", got)
	}
	if got := q.SignalCount(signal.Logs); got != 0 {
		t.Fatalf("logs depth = %d, want 0", got)
	}
	if got := q.SignalCount(signal.Metrics); got != 2 {
		t.Fatalf("metrics depth = %d, want 2", got)
	}
}

func TestDrainRoundRobinBetweenSignals(t *testing.T) {
	sender := newSignalSender()
	sender.setDown(signal.Metrics, true)
	sender.setDown(signal.Logs, true)
	q, err := NewQueue(sender, Config{
		Dir: t.TempDir(), MaxBytes: 1 << 20, DrainInterval: time.Hour,
	}, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	for _, envelope := range []signal.Envelope{
		testEnvelope(t, signal.Metrics, "m1"),
		testEnvelope(t, signal.Metrics, "m2"),
		testEnvelope(t, signal.Metrics, "m3"),
		testEnvelope(t, signal.Logs, "l1"),
		testEnvelope(t, signal.Logs, "l2"),
	} {
		if err := q.Accept(context.Background(), envelope); err != nil {
			t.Fatal(err)
		}
	}
	sender.setDown(signal.Metrics, false)
	sender.setDown(signal.Logs, false)
	q.drain(context.Background())

	want := []string{"logs:l1", "metrics:m1", "logs:l2", "metrics:m2", "metrics:m3"}
	got := sender.snapshot()
	if len(got) != len(want) {
		t.Fatalf("delivered %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delivery order %v, want fair order %v", got, want)
		}
	}
}

func TestSignalLimitDepthPressureAndRestart(t *testing.T) {
	dir := t.TempDir()
	sample := testEnvelope(t, signal.Logs, "l0")
	size := recordSize(t, sample)
	cfg := Config{
		Dir: dir, MaxBytes: 20 * size, DrainInterval: time.Hour,
		SignalLimits: map[signal.Kind]SignalLimit{
			signal.Logs: {
				MaxBytes:      2 * size,
				HighWatermark: 2 * size,
				LowWatermark:  size,
			},
		},
	}

	down := newSignalSender()
	down.setDown(signal.Logs, true)
	down.setDown(signal.Metrics, true)
	q1, err := NewQueue(down, cfg, discard())
	if err != nil {
		t.Fatal(err)
	}
	for _, envelope := range []signal.Envelope{
		sample,
		testEnvelope(t, signal.Logs, "l1"),
		testEnvelope(t, signal.Logs, "l2"),
		testEnvelope(t, signal.Metrics, "m1"),
	} {
		if err := q1.Accept(context.Background(), envelope); err != nil {
			t.Fatal(err)
		}
	}
	if got := q1.SignalCount(signal.Logs); got != 2 {
		t.Fatalf("logs depth = %d, want quota to retain newest 2", got)
	}
	if !q1.UnderSignalPressure(signal.Logs) {
		t.Fatal("logs pressure should engage at its high watermark")
	}
	if err := q1.Close(); err != nil {
		t.Fatal(err)
	}

	up := newSignalSender()
	q2, err := NewQueue(up, cfg, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()
	if got := q2.SignalCount(signal.Logs); got != 2 {
		t.Fatalf("seeded logs depth = %d, want 2", got)
	}
	if got := q2.SignalCount(signal.Metrics); got != 1 {
		t.Fatalf("seeded metrics depth = %d, want 1", got)
	}
	if !q2.UnderSignalPressure(signal.Logs) {
		t.Fatal("seeded logs pressure should be restored")
	}

	q2.drain(context.Background())
	if q2.Count() != 0 || q2.UnderSignalPressure(signal.Logs) {
		t.Fatalf("after drain count=%d logs_pressure=%v, want 0/false",
			q2.Count(), q2.UnderSignalPressure(signal.Logs))
	}
	got := up.snapshot()
	if len(got) != 3 {
		t.Fatalf("delivered %v, want 3 retained envelopes", got)
	}
	for _, item := range got {
		if item == "logs:l0" {
			t.Fatalf("oldest over-quota log was delivered: %v", got)
		}
	}
}

func TestAcceptRejectsPermanentFailureWithoutSpooling(t *testing.T) {
	sender := newSignalSender()
	sender.permanent[signal.Logs] = true
	q, err := NewQueue(sender, Config{
		Dir: t.TempDir(), MaxBytes: 1 << 20, DrainInterval: time.Hour,
	}, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	err = q.Accept(context.Background(), testEnvelope(t, signal.Logs, "bad"))
	if !errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("Accept error = %v, want ErrPermanent", err)
	}
	if q.Count() != 0 {
		t.Fatalf("permanent rejection was spooled, count=%d", q.Count())
	}
}

func TestRecordLargerThanSignalLimitIsRejected(t *testing.T) {
	sender := newSignalSender()
	sender.setDown(signal.Logs, true)
	envelope := testEnvelope(t, signal.Logs, "too-large")
	q, err := NewQueue(sender, Config{
		Dir: t.TempDir(), MaxBytes: 1 << 20, DrainInterval: time.Hour,
		SignalLimits: map[signal.Kind]SignalLimit{
			signal.Logs: {MaxBytes: recordSize(t, envelope) - 1},
		},
	}, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	err = q.Accept(context.Background(), envelope)
	if !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("Accept error = %v, want ErrRecordTooLarge", err)
	}
	if q.Count() != 0 {
		t.Fatalf("oversized envelope was spooled, count=%d", q.Count())
	}
}

func TestTinyLimitStillGetsValidPressureBand(t *testing.T) {
	high, low := watermarks(1, 0, 0)
	if high != 1 || low != 0 {
		t.Fatalf("watermarks(1) = %d/%d, want 1/0", high, low)
	}
}

func TestQueueRejectsInvalidSignalLimit(t *testing.T) {
	_, err := NewQueue(newSignalSender(), Config{
		Dir: t.TempDir(),
		SignalLimits: map[signal.Kind]SignalLimit{
			signal.Logs: {MaxBytes: 10, HighWatermark: 8, LowWatermark: 9},
		},
	}, discard())
	if err == nil {
		t.Fatal("invalid signal watermark configuration was accepted")
	}
}
