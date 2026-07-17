package signalrouter

import (
	"context"
	"errors"
	"testing"

	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/signal"
)

type sender struct {
	got    signal.Kind
	closed bool
}

func (s *sender) Send(_ context.Context, envelope signal.Envelope) error {
	s.got = envelope.Kind
	return nil
}
func (s *sender) Close() error { s.closed = true; return nil }

func TestRouterDispatchAndUnsupported(t *testing.T) {
	logs := &sender{}
	router, err := New(map[signal.Kind]signal.Sender{signal.Logs: logs})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signal.New(signal.Logs, "test.v1", "bytes", []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := router.Send(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if logs.got != signal.Logs {
		t.Fatalf("routed kind = %q, want logs", logs.got)
	}
	envelope.Kind = signal.Traces
	if err := router.Send(context.Background(), envelope); !errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("unsupported error = %v, want ErrPermanent", err)
	}
	if err := router.Close(); err != nil || !logs.closed {
		t.Fatalf("close err=%v closed=%v", err, logs.closed)
	}
}
