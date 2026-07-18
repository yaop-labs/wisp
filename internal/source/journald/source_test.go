package journald

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"

	"github.com/yaop-labs/wisp/internal/signal"
)

type capture struct {
	records []*logspb.LogRecord
	err     error
}

func (c *capture) emit(
	_ context.Context,
	envelope signal.Envelope,
) error {
	if c.err != nil {
		return c.err
	}
	var request collogspb.ExportLogsServiceRequest
	if err := proto.Unmarshal(envelope.Payload, &request); err != nil {
		return err
	}
	for _, resource := range request.ResourceLogs {
		for _, scope := range resource.ScopeLogs {
			for _, record := range scope.LogRecords {
				c.records = append(
					c.records,
					proto.Clone(record).(*logspb.LogRecord),
				)
			}
		}
	}
	return nil
}

func TestPollRetriesAdmissionBeforeAdvancingCursor(t *testing.T) {
	dir := t.TempDir()
	command := filepath.Join(dir, "journalctl")
	output := strings.Join([]string{
		"__CURSOR=cursor-1",
		"__REALTIME_TIMESTAMP=1700000000000000",
		"PRIORITY=4",
		"SYSLOG_IDENTIFIER=checkout",
		"MESSAGE=token=secret",
		"",
		"",
	}, "\n")
	script := "#!/bin/sh\nprintf '%s' '" + output + "'\n"
	if err := os.WriteFile(command, []byte(script), 0o750); err != nil {
		t.Fatal(err)
	}
	checkpointPath := filepath.Join(dir, "state", "journald.json")
	source, err := New(Config{
		CheckpointFile: checkpointPath,
		PollInterval:   time.Hour,
		Timeout:        time.Second,
		StartAt:        "beginning",
		MaxEntries:     10,
		MaxFieldBytes:  1024,
		MaxBatchBytes:  64 << 10,
		Redaction: &RedactionConfig{
			Patterns:    []string{`token=[^ ]+`},
			Replacement: "token=[REDACTED]",
		},
		Resource: map[string]string{"service.name": "checkout"},
		Command:  command,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	captured := &capture{err: errors.New("downstream unavailable")}
	source.SetLogsEmitter(captured.emit)
	source.poll(context.Background())
	if source.store.state.Cursor != "" {
		t.Fatalf(
			"cursor advanced after rejected admission: %q",
			source.store.state.Cursor,
		)
	}

	captured.err = nil
	source.poll(context.Background())
	if source.store.state.Cursor != "cursor-1" {
		t.Fatalf("cursor=%q", source.store.state.Cursor)
	}
	if len(captured.records) != 1 {
		t.Fatalf("records=%d", len(captured.records))
	}
	record := captured.records[0]
	if got := record.Body.GetStringValue(); got != "token=[REDACTED]" {
		t.Fatalf("body=%q", got)
	}
	if record.TimeUnixNano != 1_700_000_000_000_000_000 ||
		record.SeverityNumber != logspb.SeverityNumber_SEVERITY_NUMBER_WARN {
		t.Fatalf(
			"timestamp=%d severity=%v",
			record.TimeUnixNano,
			record.SeverityNumber,
		)
	}
	reloaded, err := loadCheckpoint(checkpointPath)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.state.Cursor != "cursor-1" {
		t.Fatalf("persisted cursor=%q", reloaded.state.Cursor)
	}
}

func TestConsumeDoesNotSkipQueuedRecordWhenLaterRecordIsDropped(
	t *testing.T,
) {
	dir := t.TempDir()
	source, err := New(Config{
		CheckpointFile: filepath.Join(dir, "journald.json"),
		StartAt:        "beginning",
		MaxEntries:     10,
		MaxFieldBytes:  16,
		MaxBatchBytes:  64 << 10,
		Redaction: &RedactionConfig{
			Patterns:    []string{"secret"},
			Replacement: strings.Repeat("x", 32),
		},
		Command: "/bin/true",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	source.store.state = checkpoint{
		Version:     checkpointVersion,
		Initialized: true,
		Cursor:      "cursor-old",
	}
	source.store.dirty = true
	if err := source.persistCheckpoint(); err != nil {
		t.Fatal(err)
	}
	source.SetLogsEmitter((&capture{
		err: errors.New("reject first batch"),
	}).emit)
	stream := bytes.NewBufferString(strings.Join([]string{
		"__CURSOR=cursor-1",
		"__REALTIME_TIMESTAMP=1700000000000000",
		"MESSAGE=hello",
		"",
		"__CURSOR=cursor-2",
		"__REALTIME_TIMESTAMP=1700000000000001",
		"MESSAGE=secret",
		"",
		"",
	}, "\n"))
	if err := source.consume(context.Background(), stream); err == nil {
		t.Fatal("expected admission failure")
	}
	if source.store.state.Cursor != "cursor-old" {
		t.Fatalf("cursor skipped unadmitted record: %q", source.store.state.Cursor)
	}
	reloaded, err := loadCheckpoint(source.cfg.CheckpointFile)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.state.Cursor != "cursor-old" {
		t.Fatalf("persisted cursor=%q", reloaded.state.Cursor)
	}
}

func TestCommandArgsResumeAfterCursorAndApplyFilters(t *testing.T) {
	source := &Source{
		cfg: Config{
			MaxEntries:  25,
			Directory:   "/host/var/log/journal",
			Units:       []string{"checkout.service"},
			Identifiers: []string{"worker"},
		},
		store: &checkpointStore{state: checkpoint{Cursor: "cursor-9"}},
	}
	args := strings.Join(source.commandArgs(), " ")
	for _, expected := range []string{
		"--output=export",
		"--lines=+25",
		"--after-cursor=cursor-9",
		"--directory=/host/var/log/journal",
		"--unit=checkout.service",
		"--identifier=worker",
	} {
		if !strings.Contains(args, expected) {
			t.Fatalf("args=%q, missing %q", args, expected)
		}
	}
}

func TestPollSurfacesCommandFailureWithoutAdvancingCursor(t *testing.T) {
	dir := t.TempDir()
	command := filepath.Join(dir, "journalctl")
	if err := os.WriteFile(
		command,
		[]byte("#!/bin/sh\necho 'permission denied' >&2\nexit 1\n"),
		0o750,
	); err != nil {
		t.Fatal(err)
	}
	source, err := New(Config{
		CheckpointFile: filepath.Join(dir, "journald.json"),
		StartAt:        "beginning",
		MaxEntries:     10,
		MaxFieldBytes:  1024,
		MaxBatchBytes:  64 << 10,
		Command:        command,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	source.SetLogsEmitter((&capture{}).emit)
	source.poll(context.Background())
	if source.Healthy() == nil ||
		!strings.Contains(source.Healthy().Error(), "permission denied") {
		t.Fatalf("health=%v", source.Healthy())
	}
	if source.store.state.Cursor != "" {
		t.Fatalf("cursor=%q", source.store.state.Cursor)
	}
}

func TestPollPausesBeforeCommandWhenCheckpointCannotPersist(t *testing.T) {
	dir := t.TempDir()
	commandMarker := filepath.Join(dir, "command-ran")
	command := filepath.Join(dir, "journalctl")
	script := "#!/bin/sh\ntouch '" + commandMarker + "'\n"
	if err := os.WriteFile(command, []byte(script), 0o750); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(dir, "state")
	source, err := New(Config{
		CheckpointFile: filepath.Join(parent, "journald.json"),
		StartAt:        "beginning",
		MaxEntries:     10,
		MaxFieldBytes:  1024,
		MaxBatchBytes:  64 << 10,
		Command:        command,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(parent, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	source.SetLogsEmitter((&capture{}).emit)
	source.poll(context.Background())
	if source.Healthy() == nil {
		t.Fatal("checkpoint failure did not affect health")
	}
	if _, err := os.Stat(commandMarker); !os.IsNotExist(err) {
		t.Fatalf("journalctl ran before initial checkpoint: %v", err)
	}
}

func TestConsumeReplacesMetadataHeavyRecordWithMarker(t *testing.T) {
	dir := t.TempDir()
	source, err := New(Config{
		CheckpointFile: filepath.Join(dir, "journald.json"),
		StartAt:        "beginning",
		MaxEntries:     10,
		MaxFieldBytes:  16,
		MaxBatchBytes:  8 << 10,
		Command:        "/bin/true",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	source.store.state = checkpoint{
		Version:     checkpointVersion,
		Initialized: true,
	}
	captured := &capture{}
	source.SetLogsEmitter(captured.emit)
	large := strings.Repeat("x", 4000)
	stream := bytes.NewBufferString(strings.Join([]string{
		"__CURSOR=cursor-heavy",
		"__REALTIME_TIMESTAMP=1700000000000000",
		"MESSAGE=hello",
		"_EXE=" + large,
		"_SYSTEMD_UNIT=" + large,
		"_HOSTNAME=" + large,
		"",
		"",
	}, "\n"))
	if err := source.consume(context.Background(), stream); err != nil {
		t.Fatal(err)
	}
	if len(captured.records) != 1 {
		t.Fatalf("records=%d", len(captured.records))
	}
	record := captured.records[0]
	if record.Body.GetStringValue() != "" {
		t.Fatalf("marker body=%q", record.Body.GetStringValue())
	}
	found := false
	for _, attribute := range record.Attributes {
		if attribute.Key == "wisp.journald.record_oversized" &&
			attribute.Value.GetBoolValue() {
			found = true
		}
	}
	if !found {
		t.Fatal("oversized marker attribute missing")
	}
	if source.store.state.Cursor != "cursor-heavy" {
		t.Fatalf("cursor=%q", source.store.state.Cursor)
	}
}
