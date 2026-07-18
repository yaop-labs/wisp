package filelog

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/proto"

	"github.com/yaop-labs/wisp/internal/signal"
)

type logCapture struct {
	bodies []string
	paths  []string
	err    error
	calls  int
	failAt int
}

func (c *logCapture) emit(_ context.Context, envelope signal.Envelope) error {
	c.calls++
	if c.err != nil && (c.failAt == 0 || c.calls == c.failAt) {
		return c.err
	}
	if envelope.Kind != signal.Logs || envelope.Schema != signal.OTLPLogsSchema {
		return errors.New("wrong envelope capability")
	}
	var request collogspb.ExportLogsServiceRequest
	if err := proto.Unmarshal(envelope.Payload, &request); err != nil {
		return err
	}
	for _, resource := range request.ResourceLogs {
		for _, scope := range resource.ScopeLogs {
			for _, record := range scope.LogRecords {
				c.bodies = append(c.bodies, record.Body.GetStringValue())
				for _, attribute := range record.Attributes {
					if attribute.Key == "log.file.path" {
						c.paths = append(c.paths, attribute.Value.GetStringValue())
					}
				}
			}
		}
	}
	return nil
}

func newTestSource(t *testing.T, path, checkpointPath, startAt string) *Source {
	t.Helper()
	source, err := New(Config{
		Include:        []string{path},
		CheckpointFile: checkpointPath,
		PollInterval:   time.Hour,
		StartAt:        startAt,
		MaxLineBytes:   64,
		MaxBatchBytes:  128,
		MaxReadBytes:   1024,
		Resource:       map[string]string{"service.name": "checkout"},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func appendFile(t *testing.T, path, value string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(value); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFileLogCheckpointRestartAndPartialLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	checkpoints := filepath.Join(dir, "state", "filelog.json")
	if err := os.WriteFile(path, []byte("one\ntwo"), 0o600); err != nil {
		t.Fatal(err)
	}

	first := newTestSource(t, path, checkpoints, "beginning")
	capture := &logCapture{}
	first.SetLogsEmitter(capture.emit)
	first.poll(context.Background())
	if got := capture.bodies; len(got) != 1 || got[0] != "one" {
		t.Fatalf("first poll bodies=%v, want [one]", got)
	}

	restarted := newTestSource(t, path, checkpoints, "beginning")
	restarted.SetLogsEmitter(capture.emit)
	restarted.poll(context.Background())
	if len(capture.bodies) != 1 {
		t.Fatalf("partial line replayed before newline: %v", capture.bodies)
	}
	appendFile(t, path, "\nthree\n")
	restarted.poll(context.Background())
	if got := capture.bodies; len(got) != 3 ||
		got[0] != "one" || got[1] != "two" || got[2] != "three" {
		t.Fatalf("bodies after completion=%v", got)
	}

	again := newTestSource(t, path, checkpoints, "beginning")
	again.SetLogsEmitter(capture.emit)
	again.poll(context.Background())
	if len(capture.bodies) != 3 {
		t.Fatalf("restart duplicated committed records: %v", capture.bodies)
	}
}

func TestFileLogAdmissionFailureDoesNotAdvanceCheckpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	if err := os.WriteFile(path, []byte("retry-me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "beginning")
	capture := &logCapture{err: errors.New("spool unavailable")}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())

	store, err := loadCheckpointStore(checkpoints)
	if err != nil {
		t.Fatal(err)
	}
	absolute, _ := filepath.Abs(path)
	if got := store.files[absolute].Offset; got != 0 {
		t.Fatalf("checkpoint offset=%d after failed admission, want 0", got)
	}
	capture.err = nil
	source.poll(context.Background())
	if got := capture.bodies; len(got) != 1 || got[0] != "retry-me" {
		t.Fatalf("retried bodies=%v", got)
	}
}

func TestFileLogCheckpointFailurePausesWithoutReemitting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	checkpoints := filepath.Join(dir, "state", "filelog.json")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "beginning")
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background()) // establish the initial identity and offset
	appendFile(t, path, "accepted-once\n")

	validPath := source.store.path
	source.store.path = dir // rename over a directory must fail after admission
	source.poll(context.Background())
	if source.Healthy() == nil {
		t.Fatal("checkpoint failure did not affect health")
	}
	if len(capture.bodies) != 1 {
		t.Fatalf("accepted bodies=%v, want one", capture.bodies)
	}
	source.poll(context.Background())
	if len(capture.bodies) != 1 {
		t.Fatalf("checkpoint retry re-emitted accepted batch: %v", capture.bodies)
	}

	source.store.path = validPath
	source.poll(context.Background())
	if err := source.Healthy(); err != nil {
		t.Fatalf("checkpoint health did not recover: %v", err)
	}
	if len(capture.bodies) != 1 {
		t.Fatalf("health recovery re-emitted accepted batch: %v", capture.bodies)
	}
}

func TestFileLogDrainsRotatedIdentityBeforeNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	rotated := filepath.Join(dir, "app.log.1")
	checkpoints := filepath.Join(dir, "filelog.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "beginning")
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())

	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	appendFile(t, rotated, "late-without-newline")
	if err := os.WriteFile(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Recreate the source to prove the old inode is recovered from the
	// checkpoint after a process restart, not only from in-memory state.
	source = newTestSource(t, path, checkpoints, "beginning")
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())
	want := []string{"old", "late-without-newline", "new"}
	if len(capture.bodies) != len(want) {
		t.Fatalf("rotation bodies=%v, want %v", capture.bodies, want)
	}
	for i := range want {
		if capture.bodies[i] != want[i] {
			t.Fatalf("rotation bodies=%v, want %v", capture.bodies, want)
		}
	}
}

func TestFileLogCommitsOnlySuccessfulBatchPrefix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	if err := os.WriteFile(path, []byte("aaaa\nbbbb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "beginning")
	source.cfg.MaxBatchBytes = 5
	capture := &logCapture{err: errors.New("second batch failed"), failAt: 2}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())
	if got := capture.bodies; len(got) != 1 || got[0] != "aaaa" {
		t.Fatalf("accepted prefix=%v, want [aaaa]", got)
	}
	store, err := loadCheckpointStore(checkpoints)
	if err != nil {
		t.Fatal(err)
	}
	absolute, _ := filepath.Abs(path)
	if got := store.files[absolute].Offset; got != int64(len("aaaa\n")) {
		t.Fatalf("checkpoint offset=%d, want successful prefix boundary", got)
	}

	capture.err = nil
	source.poll(context.Background())
	if got := capture.bodies; len(got) != 2 || got[1] != "bbbb" {
		t.Fatalf("retry bodies=%v, want only failed suffix", got)
	}
}

func TestFileLogDetectsTruncate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	if err := os.WriteFile(path, []byte("a-long-first-line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "beginning")
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())

	if err := os.WriteFile(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source.poll(context.Background())
	if got := capture.bodies; len(got) != 2 || got[1] != "new" {
		t.Fatalf("truncate bodies=%v", got)
	}
}

func TestFileLogStartAtEndSkipsExistingContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	if err := os.WriteFile(path, []byte("historical\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "end")
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())
	if len(capture.bodies) != 0 {
		t.Fatalf("start_at=end emitted historical records: %v", capture.bodies)
	}
	appendFile(t, path, "live\n")
	source.poll(context.Background())
	if got := capture.bodies; len(got) != 1 || got[0] != "live" {
		t.Fatalf("live bodies=%v", got)
	}
}

func TestFileLogDropsOversizedLineAndContinues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	if err := os.WriteFile(path, []byte("123456789\nok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "beginning")
	source.cfg.MaxLineBytes = 4
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())
	if got := capture.bodies; len(got) != 1 || got[0] != "ok" {
		t.Fatalf("oversized handling bodies=%v", got)
	}
}

func TestFileLogEmptyLinesStillRespectBatchBound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	data := make([]byte, 100)
	for i := range data {
		data[i] = '\n'
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "beginning")
	source.cfg.MaxBatchBytes = 256
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())
	if len(capture.bodies) != 100 {
		t.Fatalf("empty records=%d, want 100", len(capture.bodies))
	}
	if capture.calls < 2 {
		t.Fatalf("batches=%d, empty records bypassed batch bound", capture.calls)
	}
}

func TestCheckpointRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"files":{},"future":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCheckpointStore(path); err == nil {
		t.Fatal("unknown checkpoint field accepted")
	}
}
