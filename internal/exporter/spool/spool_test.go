package spool

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/signal"
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

func TestEnvelopeCodecRoundTrip(t *testing.T) {
	batch := model.Batch{Series: append([]model.Series(nil), oneBatch.Series...)}
	batch.Series[0].Resource = model.Labels{
		{Name: "service.name", Value: "checkout"},
		{Name: "host.id", Value: "node-1"},
	}
	data, err := encode(batch)
	if err != nil {
		t.Fatal(err)
	}
	if !signal.IsRecord(data) {
		t.Fatal("new spool writes must use the envelope format")
	}
	envelope, err := signal.UnmarshalBinary(data, signal.DefaultMaxPayload)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Kind != signal.Metrics || envelope.Schema != metricSchema {
		t.Fatalf("envelope=%+v", envelope)
	}
	if envelope.Resource["service.name"] != "checkout" || envelope.Resource["host.id"] != "node-1" {
		t.Fatalf("resource=%v", envelope.Resource)
	}
	got, err := decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, batch) {
		t.Fatalf("round trip mismatch: got=%+v want=%+v", got, batch)
	}
}

func TestLegacyBatchDrainsAfterUpgrade(t *testing.T) {
	dir := t.TempDir()
	data, err := encodeLegacy(oneBatch)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "00000000000000000001-000001"+legacyFileSuffix)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	up := &toggle{}
	e, err := New(up, Config{Dir: dir, MaxAge: -1, DrainInterval: 20 * time.Millisecond}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	waitFor(t, func() bool {
		_, err := os.Stat(path)
		return os.IsNotExist(err)
	}, "legacy batch to drain")
	if up.sent() != 1 {
		t.Fatalf("legacy sends=%d, want 1", up.sent())
	}
}

func TestMetricAdapterRejectsOtherSignalKinds(t *testing.T) {
	envelope, err := signal.New(signal.Logs, "otlp.logs/v1", "application/x-protobuf", []byte("logs"), nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := envelope.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decode(data); err == nil {
		t.Fatal("metric adapter accepted a logs envelope")
	}
}

func TestEnvelopeOmitsAmbiguousOrInvalidResourceIdentity(t *testing.T) {
	tests := map[string]model.Batch{
		"mixed": {
			Series: []model.Series{
				{Name: "a", Resource: model.Labels{{Name: "service.name", Value: "one"}}, Points: []model.Point{{IntValue: 1}}},
				{Name: "b", Resource: model.Labels{{Name: "service.name", Value: "two"}}, Points: []model.Point{{IntValue: 2}}},
			},
		},
		"invalid": {
			Series: []model.Series{
				{Name: "a", Resource: model.Labels{{Name: "service.name", Value: "bad\nvalue"}}, Points: []model.Point{{IntValue: 1}}},
			},
		},
	}
	for name, batch := range tests {
		t.Run(name, func(t *testing.T) {
			data, err := encode(batch)
			if err != nil {
				t.Fatalf("telemetry admission must not fail because optional envelope identity is unusable: %v", err)
			}
			envelope, err := signal.UnmarshalBinary(data, signal.DefaultMaxPayload)
			if err != nil {
				t.Fatal(err)
			}
			if len(envelope.Resource) != 0 {
				t.Fatalf("resource=%v, want omitted", envelope.Resource)
			}
		})
	}
}
