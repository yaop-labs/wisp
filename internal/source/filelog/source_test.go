package filelog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"

	"github.com/yaop-labs/wisp/internal/signal"
)

type logCapture struct {
	bodies    []string
	paths     []string
	err       error
	calls     int
	failAt    int
	records   []*logspb.LogRecord
	resources []*resourcepb.Resource
	envelopes []signal.Envelope
}

func (c *logCapture) emit(_ context.Context, envelope signal.Envelope) error {
	c.calls++
	if c.err != nil && (c.failAt == 0 || c.calls == c.failAt) {
		return c.err
	}
	if envelope.Kind != signal.Logs || envelope.Schema != signal.OTLPLogsSchema {
		return errors.New("wrong envelope capability")
	}
	c.envelopes = append(c.envelopes, envelope)
	var request collogspb.ExportLogsServiceRequest
	if err := proto.Unmarshal(envelope.Payload, &request); err != nil {
		return err
	}
	for _, resource := range request.ResourceLogs {
		c.resources = append(
			c.resources,
			proto.Clone(resource.Resource).(*resourcepb.Resource),
		)
		for _, scope := range resource.ScopeLogs {
			for _, record := range scope.LogRecords {
				c.records = append(c.records, proto.Clone(record).(*logspb.LogRecord))
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
	return newTestSourceWithFormat(t, path, checkpointPath, startAt, "text")
}

func newTestSourceWithFormat(
	t *testing.T,
	path string,
	checkpointPath string,
	startAt string,
	format string,
) *Source {
	t.Helper()
	source, err := New(Config{
		Include:        []string{path},
		CheckpointFile: checkpointPath,
		PollInterval:   time.Hour,
		StartAt:        startAt,
		Format:         format,
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

func enableTestRedaction(
	t *testing.T,
	source *Source,
	patterns []string,
	replacement string,
) {
	t.Helper()
	config := &RedactionConfig{Patterns: patterns, Replacement: replacement}
	redactor, err := newContentRedactor(config, source.cfg.MaxLineBytes)
	if err != nil {
		t.Fatal(err)
	}
	source.cfg.Redaction = config
	source.redactor = redactor
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

func TestFileLogRedactsTextBeforeDurableEnvelope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	if err := os.WriteFile(
		path,
		[]byte("user=alice token=super-secret\nsafe\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "beginning")
	enableTestRedaction(t, source, []string{`token=[^ ]+`}, "")
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())

	want := []string{"user=alice [REDACTED]", "safe"}
	if len(capture.bodies) != len(want) {
		t.Fatalf("redacted bodies=%v, want %v", capture.bodies, want)
	}
	for index := range want {
		if capture.bodies[index] != want[index] {
			t.Fatalf("redacted bodies=%v, want %v", capture.bodies, want)
		}
	}
	for _, envelope := range capture.envelopes {
		if bytes.Contains(envelope.Payload, []byte("super-secret")) {
			t.Fatal("durable envelope contains unredacted secret")
		}
	}
}

func TestFileLogRedactsAssembledAndMalformedCRI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	data := "2026-07-18T10:11:12Z stdout P api_key=sec\n" +
		"2026-07-18T10:11:13Z stdout F ret\n" +
		"malformed token=hidden\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSourceWithFormat(t, path, checkpoints, "beginning", "cri")
	enableTestRedaction(
		t,
		source,
		[]string{`api_key=\w+`, `token=\w+`},
		"",
	)
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())

	want := []string{"[REDACTED]", "malformed [REDACTED]"}
	if len(capture.bodies) != len(want) {
		t.Fatalf("redacted CRI bodies=%v, want %v", capture.bodies, want)
	}
	for index := range want {
		if capture.bodies[index] != want[index] {
			t.Fatalf("redacted CRI bodies=%v, want %v", capture.bodies, want)
		}
	}
	if !attributeBool(capture.records[1], "wisp.cri.parse_error") {
		t.Fatal("redaction removed malformed CRI diagnostic attribute")
	}
	for _, envelope := range capture.envelopes {
		if bytes.Contains(envelope.Payload, []byte("secret")) ||
			bytes.Contains(envelope.Payload, []byte("hidden")) {
			t.Fatal("CRI durable envelope contains unredacted secret")
		}
	}
}

func TestFileLogRedactionExpansionDropsAndCheckpointsRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	if err := os.WriteFile(path, []byte("aaaa\nok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "beginning")
	source.cfg.MaxLineBytes = 4
	enableTestRedaction(t, source, []string{`a`}, "XX")
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())
	if got := capture.bodies; len(got) != 1 || got[0] != "ok" {
		t.Fatalf("post-expansion bodies=%v", got)
	}

	restarted := newTestSource(t, path, checkpoints, "beginning")
	restarted.SetLogsEmitter(capture.emit)
	restarted.poll(context.Background())
	if len(capture.bodies) != 1 {
		t.Fatalf("redaction-dropped record replayed after restart: %v", capture.bodies)
	}
}

func TestFileLogCRIMapsTimestampStreamAndFragments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	const first = "2026-07-18T10:11:12.123456789Z"
	data := first + " stdout P hel" + "\n" +
		"2026-07-18T10:11:12.223456789Z stdout F lo" + "\n" +
		"2026-07-18T10:11:13Z stderr F failed" + "\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSourceWithFormat(t, path, checkpoints, "beginning", "cri")
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())

	if got := capture.bodies; len(got) != 2 ||
		got[0] != "hello" || got[1] != "failed" {
		t.Fatalf("CRI bodies=%v", got)
	}
	wantTime, err := time.Parse(time.RFC3339Nano, first)
	if err != nil {
		t.Fatal(err)
	}
	if got := capture.records[0].TimeUnixNano; got != uint64(wantTime.UnixNano()) {
		t.Fatalf("CRI time=%d, want %d", got, wantTime.UnixNano())
	}
	if capture.records[0].ObservedTimeUnixNano == 0 {
		t.Fatal("CRI observed time is zero")
	}
	if got := attributeString(capture.records[0], "log.iostream"); got != "stdout" {
		t.Fatalf("CRI stream=%q, want stdout", got)
	}
	if got := attributeInt(capture.records[0], "wisp.file.offset"); got != 0 {
		t.Fatalf("CRI offset=%d, want first fragment offset 0", got)
	}
}

func TestFileLogCRIRestartBeforeFinalFragmentReplaysPendingSequence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	const partial = "2026-07-18T10:11:12Z stdout P before-"
	if err := os.WriteFile(path, []byte(partial+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first := newTestSourceWithFormat(t, path, checkpoints, "beginning", "cri")
	capture := &logCapture{}
	first.SetLogsEmitter(capture.emit)
	first.poll(context.Background())
	if len(capture.bodies) != 0 {
		t.Fatalf("pending CRI fragment emitted: %v", capture.bodies)
	}
	store, err := loadCheckpointStore(checkpoints)
	if err != nil {
		t.Fatal(err)
	}
	absolute, _ := filepath.Abs(path)
	if got := store.files[absolute].Offset; got != 0 {
		t.Fatalf("pending CRI checkpoint=%d, want 0", got)
	}

	appendFile(t, path, "2026-07-18T10:11:13Z stdout F after\n")
	restarted := newTestSourceWithFormat(t, path, checkpoints, "beginning", "cri")
	restarted.SetLogsEmitter(capture.emit)
	restarted.poll(context.Background())
	if got := capture.bodies; len(got) != 1 || got[0] != "before-after" {
		t.Fatalf("reassembled CRI bodies=%v", got)
	}
}

func TestFileLogCRIAdmissionFailureDoesNotCommitFragments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	data := "2026-07-18T10:11:12Z stdout P retry-\n" +
		"2026-07-18T10:11:13Z stdout F me\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSourceWithFormat(t, path, checkpoints, "beginning", "cri")
	capture := &logCapture{err: errors.New("spool unavailable")}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())

	store, err := loadCheckpointStore(checkpoints)
	if err != nil {
		t.Fatal(err)
	}
	absolute, _ := filepath.Abs(path)
	if got := store.files[absolute].Offset; got != 0 {
		t.Fatalf("failed CRI admission checkpoint=%d, want 0", got)
	}
	capture.err = nil
	source.poll(context.Background())
	if got := capture.bodies; len(got) != 1 || got[0] != "retry-me" {
		t.Fatalf("retried CRI bodies=%v", got)
	}
}

func TestFileLogCRIOversizedSequenceContinuesAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	data := "2026-07-18T10:11:12Z stdout P abc\n" +
		"2026-07-18T10:11:13Z stdout P de\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSourceWithFormat(t, path, checkpoints, "beginning", "cri")
	source.cfg.MaxLineBytes = 4
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())

	store, err := loadCheckpointStore(checkpoints)
	if err != nil {
		t.Fatal(err)
	}
	absolute, _ := filepath.Abs(path)
	state := store.files[absolute]
	if state.Offset != int64(len(data)) || !state.CRIDropping {
		t.Fatalf("oversized CRI checkpoint=%+v, want end+drop state", state)
	}

	appendFile(t, path,
		"2026-07-18T10:11:14Z stdout F ignored\n"+
			"2026-07-18T10:11:15Z stdout F ok\n")
	restarted := newTestSourceWithFormat(t, path, checkpoints, "beginning", "cri")
	restarted.cfg.MaxLineBytes = 4
	restarted.SetLogsEmitter(capture.emit)
	restarted.poll(context.Background())
	if got := capture.bodies; len(got) != 1 || got[0] != "ok" {
		t.Fatalf("post-oversize CRI bodies=%v", got)
	}
	store, err = loadCheckpointStore(checkpoints)
	if err != nil {
		t.Fatal(err)
	}
	if store.files[absolute].CRIDropping {
		t.Fatal("CRI drop state not cleared by final fragment")
	}
}

func TestFileLogCRIPreservesMalformedLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	if err := os.WriteFile(path, []byte("not a CRI record\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSourceWithFormat(t, path, checkpoints, "beginning", "cri")
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())

	if got := capture.bodies; len(got) != 1 || got[0] != "not a CRI record" {
		t.Fatalf("malformed CRI bodies=%v", got)
	}
	if !attributeBool(capture.records[0], "wisp.cri.parse_error") {
		t.Fatal("malformed CRI record lacks parse_error attribute")
	}
}

func TestFileLogCRIFlushesPendingSequenceOnRotation(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "pods")
	path := filepath.Join(root, "default_api_uid-123", "api", "0.log")
	rotated := filepath.Join(filepath.Dir(path), "0.log.1")
	checkpoints := filepath.Join(dir, "filelog.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		path,
		[]byte("2026-07-18T10:11:12Z stdout P orphan\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	source := newTestSourceWithFormat(t, path, checkpoints, "beginning", "cri")
	source.cfg.Kubernetes = &KubernetesConfig{PodLogsRoot: root}
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		path,
		[]byte("2026-07-18T10:11:13Z stdout F new\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	source.poll(context.Background())
	if got := capture.bodies; len(got) != 2 ||
		got[0] != "orphan" || got[1] != "new" {
		t.Fatalf("rotated CRI bodies=%v", got)
	}
	if !attributeBool(capture.records[0], "wisp.cri.partial") {
		t.Fatal("rotated incomplete CRI record lacks partial attribute")
	}
	if len(capture.resources) != 2 {
		t.Fatalf("rotated resources=%d, want 2", len(capture.resources))
	}
	for i, resource := range capture.resources {
		if got := resourceAttributeString(resource, "k8s.pod.name"); got != "api" {
			t.Fatalf("rotated resource[%d] pod=%q, want api", i, got)
		}
	}
}

func TestFileLogCRIStreamMismatchPreservesBothRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	data := "2026-07-18T10:11:12Z stdout P first\n" +
		"2026-07-18T10:11:13Z stderr F second\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSourceWithFormat(t, path, checkpoints, "beginning", "cri")
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())

	if got := capture.bodies; len(got) != 2 ||
		got[0] != "first" || got[1] != "second" {
		t.Fatalf("stream mismatch bodies=%v", got)
	}
	if !attributeBool(capture.records[0], "wisp.cri.sequence_error") ||
		!attributeBool(capture.records[0], "wisp.cri.partial") {
		t.Fatal("interrupted CRI sequence lacks diagnostic attributes")
	}
}

func TestFileLogCRIFragmentSpanBoundMakesProgress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	prefix := "2026-07-18T10:11:12Z stdout P "
	data := prefix + "a\n" + prefix + "b\n" +
		"2026-07-18T10:11:13Z stdout F ignored\n" +
		"2026-07-18T10:11:14Z stdout F ok\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSourceWithFormat(t, path, checkpoints, "beginning", "cri")
	source.cfg.MaxReadBytes = 64
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())
	if len(capture.bodies) != 0 {
		t.Fatalf("over-budget fragment sequence emitted: %v", capture.bodies)
	}
	source.poll(context.Background())
	if got := capture.bodies; len(got) != 1 || got[0] != "ok" {
		t.Fatalf("post-budget CRI bodies=%v", got)
	}
}

func TestFileLogKubernetesPathEnrichesOTLPResourceAndEnvelope(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "pods")
	path := filepath.Join(
		root,
		"payments_checkout-7c8d9_275ecb36-5aa8-4c2a-9c47-d8bb681b9aff",
		"api",
		"2.log",
	)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		path,
		[]byte("2026-07-18T10:11:12Z stdout F paid\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	source := newTestSourceWithFormat(
		t,
		path,
		filepath.Join(dir, "filelog.json"),
		"beginning",
		"cri",
	)
	source.cfg.Kubernetes = &KubernetesConfig{PodLogsRoot: root}
	source.cfg.Resource["k8s.pod.name"] = "configured-wrong-value"
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())

	if got := capture.bodies; len(got) != 1 || got[0] != "paid" {
		t.Fatalf("Kubernetes bodies=%v", got)
	}
	if len(capture.resources) != 1 {
		t.Fatalf("resources=%d, want 1", len(capture.resources))
	}
	resource := capture.resources[0]
	wantStrings := map[string]string{
		"service.name":       "checkout",
		"k8s.namespace.name": "payments",
		"k8s.pod.name":       "checkout-7c8d9",
		"k8s.pod.uid":        "275ecb36-5aa8-4c2a-9c47-d8bb681b9aff",
		"k8s.container.name": "api",
	}
	for key, want := range wantStrings {
		if got := resourceAttributeString(resource, key); got != want {
			t.Fatalf("resource %s=%q, want %q", key, got, want)
		}
	}
	if got := resourceAttributeInt(resource, "k8s.container.restart_count"); got != 2 {
		t.Fatalf("restart count=%d, want 2", got)
	}
	if len(capture.envelopes) != 1 ||
		capture.envelopes[0].Resource["k8s.pod.uid"] !=
			"275ecb36-5aa8-4c2a-9c47-d8bb681b9aff" {
		t.Fatalf("envelope resource=%v", capture.envelopes)
	}
	if _, exists := capture.envelopes[0].Resource["k8s.container.restart_count"]; exists {
		t.Fatal("integer restart count leaked into string-only envelope identity")
	}
}

func TestFileLogKubernetesEnrichmentMissPreservesRecord(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "pods")
	path := filepath.Join(root, "custom.log")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		path,
		[]byte("2026-07-18T10:11:12Z stdout F retained\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	source := newTestSourceWithFormat(
		t,
		path,
		filepath.Join(dir, "filelog.json"),
		"beginning",
		"cri",
	)
	source.cfg.Kubernetes = &KubernetesConfig{PodLogsRoot: root}
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())

	if got := capture.bodies; len(got) != 1 || got[0] != "retained" {
		t.Fatalf("enrichment miss bodies=%v", got)
	}
	if got := resourceAttributeString(capture.resources[0], "service.name"); got != "checkout" {
		t.Fatalf("base resource lost on enrichment miss: %q", got)
	}
	if got := resourceAttributeString(capture.resources[0], "k8s.pod.name"); got != "" {
		t.Fatalf("unexpected Kubernetes metadata on miss: %q", got)
	}
}

func attributeString(record *logspb.LogRecord, key string) string {
	for _, attribute := range record.Attributes {
		if attribute.Key == key {
			return attribute.Value.GetStringValue()
		}
	}
	return ""
}

func attributeInt(record *logspb.LogRecord, key string) int64 {
	for _, attribute := range record.Attributes {
		if attribute.Key == key {
			return attribute.Value.GetIntValue()
		}
	}
	return 0
}

func attributeBool(record *logspb.LogRecord, key string) bool {
	for _, attribute := range record.Attributes {
		if attribute.Key == key {
			return attribute.Value.GetBoolValue()
		}
	}
	return false
}

func resourceAttributeString(resource *resourcepb.Resource, key string) string {
	for _, attribute := range resource.Attributes {
		if attribute.Key == key {
			return attribute.Value.GetStringValue()
		}
	}
	return ""
}

func resourceAttributeInt(resource *resourcepb.Resource, key string) int64 {
	for _, attribute := range resource.Attributes {
		if attribute.Key == key {
			return attribute.Value.GetIntValue()
		}
	}
	return 0
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

func TestCheckpointOlderVersionsLoadAndUpgrade(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "checkpoint.json")
			document := fmt.Sprintf(`{"version":%d,"files":{}}`, version)
			if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
				t.Fatal(err)
			}
			store, err := loadCheckpointStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.save(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `"version":3`) {
				t.Fatalf("checkpoint was not upgraded: %s", data)
			}
		})
	}
}
