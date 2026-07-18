package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/yaop-labs/wisp/internal/config"
	"github.com/yaop-labs/wisp/internal/signal"
)

func TestAppRoutesFileLogsThroughSharedSpool(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	collector := &logsCollector{
		got: make(chan *collogspb.ExportLogsServiceRequest, 1),
		ids: make(chan string, 1),
	}
	server := grpc.NewServer()
	collogspb.RegisterLogsServiceServer(server, collector)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")
	checkpointPath := filepath.Join(dir, "state", "filelog.json")
	if err := os.WriteFile(
		logPath,
		[]byte("START 1784369472 token=from-file\n detail\nSTART 1784369473 pending\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`
sources:
  filelog:
    include: [%q]
    checkpoint_file: %q
    poll_interval: 1h
    start_at: beginning
    redaction:
      patterns: ['token=\S+']
    multiline:
      start_pattern: '^START '
      flush_after: 1h
    timestamp:
      pattern: '^START (\d+)'
      format: unix
exporter:
  otlp:
    endpoint: %q
    protocol: grpc
    retry:
      max_attempts: 1
  spool:
    dir: %q
    max_bytes: 1048576
    signal_limits:
      logs:
        max_bytes: 524288
resource:
  attributes:
    service.name: checkout
`, logPath, checkpointPath, listener.Addr().String(), filepath.Join(dir, "spool"))
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

	select {
	case request := <-collector.got:
		record := request.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
		if got := record.Body.GetStringValue(); got != "START 1784369472 [REDACTED]\n detail" {
			t.Fatalf("collector body=%q, want framed and redacted content", got)
		}
		if got := record.TimeUnixNano; got != 1784369472*uint64(time.Second) {
			t.Fatalf("collector event time=%d", got)
		}
		if got := request.ResourceLogs[0].Resource.Attributes[0].Value.GetStringValue(); got != "checkout" {
			t.Fatalf("collector resource service.name=%q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for downstream file log")
	}
	select {
	case id := <-collector.ids:
		if decoded, err := hex.DecodeString(id); err != nil || len(decoded) != 16 {
			t.Fatalf("delivery envelope id=%q, want 32 hex chars", id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for delivery metadata")
	}
	if _, err := os.Stat(checkpointPath); err != nil {
		t.Fatalf("checkpoint not persisted: %v", err)
	}

	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := application.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
}

func TestAppRedactsFileLogBeforeSpoolPersistence(t *testing.T) {
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unavailableEndpoint := reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")
	checkpointPath := filepath.Join(dir, "filelog.json")
	spoolPath := filepath.Join(dir, "spool")
	const secret = "never-write-this-secret"
	if err := os.WriteFile(
		logPath,
		[]byte("token="+secret+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`
sources:
  filelog:
    include: [%q]
    checkpoint_file: %q
    poll_interval: 1h
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
    service.name: checkout
`, logPath, checkpointPath, unavailableEndpoint, spoolPath)
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
		matches, globErr := filepath.Glob(filepath.Join(spoolPath, "*.envelope"))
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
		t.Fatal("timed out waiting for redacted spool envelope")
	}
	data, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(secret)) {
		t.Fatal("raw spool record contains unredacted secret")
	}
	envelope, err := signal.UnmarshalBinary(data, signal.DefaultMaxPayload)
	if err != nil {
		t.Fatal(err)
	}
	var request collogspb.ExportLogsServiceRequest
	if err := proto.Unmarshal(envelope.Payload, &request); err != nil {
		t.Fatal(err)
	}
	body := request.ResourceLogs[0].ScopeLogs[0].LogRecords[0].
		Body.GetStringValue()
	if body != "[REDACTED]" {
		t.Fatalf("spooled body=%q, want redacted content", body)
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

func TestEffectiveFileLogBoundsRespectDurableRequestBudget(t *testing.T) {
	cfg := &config.FileLogSource{
		MaxLineBytes:  1 << 20,
		MaxBatchBytes: 2 << 20,
	}
	line, batch := effectiveFileLogBounds(cfg, 512<<10)
	if batch != 448<<10 || line != 448<<10 {
		t.Fatalf("effective bounds line=%d batch=%d, want 448KiB", line, batch)
	}
	line, batch = effectiveFileLogBounds(&config.FileLogSource{}, 3<<20)
	if line != 256<<10 || batch != 512<<10 {
		t.Fatalf("default bounds line=%d batch=%d", line, batch)
	}
}
