package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/config"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fullConfig parses a config exercising all sources, processors, and the spool
// (spool dir under a temp dir so nothing is left behind).
func fullConfig(t *testing.T) config.Config {
	t.Helper()
	y := fmt.Sprintf(`
agent:
  self_metrics:
    endpoint: ""
sources:
  host:
    interval: 1s
  scrape:
    interval: 1s
    targets:
      - job: app
        static: ["127.0.0.1:9999"]
  otlp:
    grpc: "127.0.0.1:0"
processors:
  - type: relabel
    rules:
      - source_labels: [__name__]
        regex: "go_gc_.*"
        action: drop
  - type: reset
  - type: cardinality_limit
    max_series_per_target: 1000
    max_labels_per_series: 30
exporter:
  otlp:
    endpoint: "127.0.0.1:14317"
    protocol: grpc
  spool:
    dir: %q
    max_bytes: 1048576
resource:
  attributes:
    service.name: "wisp-test"
`, t.TempDir())
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg
}

func TestNewWiresFullAgent(t *testing.T) {
	a, err := New(fullConfig(t), discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a == nil || a.pipeline == nil {
		t.Fatal("expected a wired app")
	}
	if a.scrape == nil {
		t.Error("scrape source should be captured for hot-reload")
	}
	if a.healthy == nil {
		t.Error("spool present -> healthy func should be set")
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Resource.Attributes = nil // drop required service.name
	if _, err := New(cfg, discardLog()); err == nil {
		t.Error("New should reject a config without service.name")
	}
}

func TestNewRejectsBadProcessor(t *testing.T) {
	y := `
sources: {host: {interval: 1s}}
processors:
  - type: relabel
    rules:
      - regex: "("        # invalid regex
        action: keep
exporter: {otlp: {endpoint: "x:4317"}}
resource: {attributes: {service.name: wisp}}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := New(cfg, discardLog()); err == nil {
		t.Error("New should fail when a processor fails to build")
	}
}

func TestReload(t *testing.T) {
	a, err := New(fullConfig(t), discardLog())
	if err != nil {
		t.Fatal(err)
	}
	// Valid reload with a changed scrape target set.
	next := fullConfig(t)
	next.Sources.Scrape.Targets = []config.ScrapeTarget{{Job: "new", Static: []string{"127.0.0.1:1234"}}}
	if err := a.Reload(next); err != nil {
		t.Fatalf("valid Reload: %v", err)
	}
	// Invalid reload is rejected and the running config is kept.
	bad := fullConfig(t)
	bad.Resource.Attributes = nil
	if err := a.Reload(bad); err == nil {
		t.Error("Reload should reject an invalid config")
	}
}

func TestStartShutdownLifecycle(t *testing.T) {
	y := fmt.Sprintf(`
agent:
  self_metrics:
    endpoint: "127.0.0.1:0"
sources:
  host:
    interval: 1s
exporter:
  otlp:
    endpoint: "127.0.0.1:14317"
    protocol: grpc
  spool:
    dir: %q
    max_bytes: 1048576
resource:
  attributes:
    service.name: "wisp-test"
`, t.TempDir())
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := a.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // let one collection cycle run
	cancel()
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := a.Shutdown(stopCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}
