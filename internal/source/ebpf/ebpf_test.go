package ebpf

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestAvailableContract: Available must return a reason exactly when it reports
// unavailable, and an empty reason when available.
func TestAvailableContract(t *testing.T) {
	ok, reason := Available()
	if !ok && reason == "" {
		t.Fatal("unavailable must include a reason")
	}
	if ok && reason != "" {
		t.Fatalf("available should have an empty reason, got %q", reason)
	}
	t.Logf("ebpf available=%v reason=%q", ok, reason)
}

// TestStartGracefulNoop: Start returns cleanly on ctx cancel and never emits
// (no fabricated metrics), regardless of host capability.
func TestStartGracefulNoop(t *testing.T) {
	s := New(Config{Probes: []string{"http", "grpc"}}, discard())
	ctx, cancel := context.WithCancel(context.Background())

	var emitted bool
	done := make(chan error, 1)
	go func() {
		done <- s.Start(ctx, func(context.Context, model.Batch) error {
			emitted = true
			return nil
		})
	}()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return on ctx cancel")
	}
	if emitted {
		t.Fatal("no-op probe must not emit metrics")
	}
}
