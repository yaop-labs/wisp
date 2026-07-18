package app

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/proto"

	"github.com/yaop-labs/wisp/internal/config"
	"github.com/yaop-labs/wisp/internal/signal"
)

func TestAppRedactsJournaldBeforeSharedSpoolPersistence(t *testing.T) {
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unavailableEndpoint := reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	const secret = "journald-secret-must-not-reach-disk"
	command := filepath.Join(dir, "journalctl")
	output := strings.Join([]string{
		"__CURSOR=cursor-app-1",
		"__REALTIME_TIMESTAMP=1700000000000000",
		"PRIORITY=6",
		"MESSAGE=token=" + secret,
		"",
		"",
	}, "\n")
	if err := os.WriteFile(
		command,
		[]byte("#!/bin/sh\nprintf '%s' '"+output+"'\n"),
		0o750,
	); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	checkpointPath := filepath.Join(dir, "state", "journald.json")
	spoolPath := filepath.Join(dir, "spool")
	yaml := fmt.Sprintf(`
sources:
  journald:
    checkpoint_file: %q
    poll_interval: 1h
    timeout: 1s
    start_at: beginning
    redaction:
      patterns: ['token=[^ ]+']
exporter:
  otlp:
    endpoint: %q
    protocol: grpc
    timeout: 100ms
    retry:
      max_attempts: 1
  spool:
    dir: %q
    max_bytes: 1048576
resource:
  attributes:
    service.name: wisp
`, checkpointPath, unavailableEndpoint, spoolPath)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	application, err := New(cfg, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := application.Start(runCtx); err != nil {
		t.Fatal(err)
	}

	var envelopePath string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		matches, globErr := filepath.Glob(
			filepath.Join(spoolPath, "*.envelope"),
		)
		if globErr != nil {
			t.Fatal(globErr)
		}
		if len(matches) == 1 {
			envelopePath = matches[0]
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if envelopePath == "" {
		t.Fatal("timed out waiting for journald spool envelope")
	}
	data, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(secret)) {
		t.Fatal("raw spool record contains unredacted journald secret")
	}
	envelope, err := signal.UnmarshalBinary(data, signal.DefaultMaxPayload)
	if err != nil {
		t.Fatal(err)
	}
	var request collogspb.ExportLogsServiceRequest
	if err := proto.Unmarshal(envelope.Payload, &request); err != nil {
		t.Fatal(err)
	}
	record := request.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	if got := record.Body.GetStringValue(); got != "[REDACTED]" {
		t.Fatalf("spooled body=%q", got)
	}
	if record.TimeUnixNano != 1_700_000_000_000_000_000 {
		t.Fatalf("event timestamp=%d", record.TimeUnixNano)
	}
	if _, err := os.Stat(checkpointPath); err != nil {
		t.Fatalf("checkpoint not persisted: %v", err)
	}

	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(
		context.Background(),
		3*time.Second,
	)
	defer shutdownCancel()
	if err := application.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
}

func TestEffectiveJournaldBoundsRespectDurableRequestBudget(t *testing.T) {
	cfg := &config.JournaldSource{
		MaxFieldBytes: 1 << 20,
		MaxBatchBytes: 2 << 20,
	}
	field, batch := effectiveJournaldBounds(cfg, 512<<10)
	if batch != 448<<10 || field != 448<<10 {
		t.Fatalf(
			"effective bounds field=%d batch=%d, want 448KiB",
			field,
			batch,
		)
	}
	field, batch = effectiveJournaldBounds(
		&config.JournaldSource{},
		3<<20,
	)
	if field != 256<<10 || batch != 512<<10 {
		t.Fatalf(
			"default bounds field=%d batch=%d",
			field,
			batch,
		)
	}
}
