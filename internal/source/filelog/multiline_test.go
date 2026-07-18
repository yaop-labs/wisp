package filelog

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func enableTestMultiline(
	t *testing.T,
	source *Source,
	pattern string,
	maxLines int,
	flushAfter time.Duration,
) {
	t.Helper()
	config := &MultilineConfig{
		StartPattern: pattern,
		MaxLines:     maxLines,
		FlushAfter:   flushAfter,
	}
	framer, err := newMultilineFramer(config)
	if err != nil {
		t.Fatal(err)
	}
	source.cfg.Multiline = config
	source.multiline = framer
}

func TestFileLogMultilineRestartBoundaryAndTimeout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	first := "2026-07-18 first\n  stack one\n"
	second := "2026-07-18 second\n  stack two\n"
	if err := os.WriteFile(path, []byte(first+second), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "beginning")
	enableTestMultiline(t, source, `^\d{4}-\d{2}-\d{2} `, 32, time.Hour)
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())

	if got := capture.bodies; len(got) != 1 ||
		got[0] != "2026-07-18 first\n  stack one" {
		t.Fatalf("first multiline poll=%v", got)
	}
	store, err := loadCheckpointStore(checkpoints)
	if err != nil {
		t.Fatal(err)
	}
	absolute, _ := filepath.Abs(path)
	if got := store.files[absolute].Offset; got != int64(len(first)) {
		t.Fatalf("pending multiline checkpoint=%d, want %d", got, len(first))
	}

	restarted := newTestSource(t, path, checkpoints, "beginning")
	enableTestMultiline(t, restarted, `^\d{4}-\d{2}-\d{2} `, 32, time.Hour)
	restarted.SetLogsEmitter(capture.emit)
	restarted.poll(context.Background())
	if len(capture.bodies) != 1 {
		t.Fatalf("pending multiline emitted before boundary: %v", capture.bodies)
	}
	appendFile(t, path, "2026-07-18 third\n")
	restarted.poll(context.Background())
	if got := capture.bodies; len(got) != 2 ||
		got[1] != "2026-07-18 second\n  stack two" {
		t.Fatalf("multiline after restart=%v", got)
	}

	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	restarted.multiline.flushAfter = 100 * time.Millisecond
	restarted.poll(context.Background())
	if got := capture.bodies; len(got) != 3 ||
		got[2] != "2026-07-18 third" {
		t.Fatalf("timeout-flushed multiline=%v", got)
	}
	if got := attributeString(
		capture.records[2],
		"wisp.multiline.flush_reason",
	); got != "timeout" {
		t.Fatalf("timeout flush reason=%q", got)
	}
}

func TestFileLogMultilineRotationFlushesPendingRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	rotated := filepath.Join(dir, "app.log.1")
	checkpoints := filepath.Join(dir, "filelog.json")
	if err := os.WriteFile(
		path,
		[]byte("START old\n continuation\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "beginning")
	enableTestMultiline(t, source, `^START `, 32, time.Hour)
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("START new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source.poll(context.Background())
	if got := capture.bodies; len(got) != 1 ||
		got[0] != "START old\n continuation" {
		t.Fatalf("rotation multiline=%v", got)
	}
	if got := attributeString(
		capture.records[0],
		"wisp.multiline.flush_reason",
	); got != "rotation" {
		t.Fatalf("rotation flush reason=%q", got)
	}
}

func TestFileLogMultilineTimeoutWaitsForPhysicalLineCompletion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	if err := os.WriteFile(
		path,
		[]byte("START one\npartial"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "beginning")
	enableTestMultiline(t, source, `^START `, 32, 100*time.Millisecond)
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())
	if len(capture.bodies) != 0 {
		t.Fatalf("timeout split incomplete physical line: %v", capture.bodies)
	}
	store, err := loadCheckpointStore(checkpoints)
	if err != nil {
		t.Fatal(err)
	}
	absolute, _ := filepath.Abs(path)
	if got := store.files[absolute].Offset; got != 0 {
		t.Fatalf("partial physical line checkpoint=%d, want 0", got)
	}

	appendFile(t, path, "\nSTART two\n")
	source.poll(context.Background())
	if got := capture.bodies; len(got) != 1 ||
		got[0] != "START one\npartial" {
		t.Fatalf("completed physical multiline=%v", got)
	}
}

func TestFileLogMultilineAdmissionFailureKeepsCheckpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	if err := os.WriteFile(
		path,
		[]byte("START retry\n detail\nSTART pending\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "beginning")
	enableTestMultiline(t, source, `^START `, 32, time.Hour)
	capture := &logCapture{err: errors.New("spool unavailable")}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())

	store, err := loadCheckpointStore(checkpoints)
	if err != nil {
		t.Fatal(err)
	}
	absolute, _ := filepath.Abs(path)
	if got := store.files[absolute].Offset; got != 0 {
		t.Fatalf("failed multiline checkpoint=%d, want 0", got)
	}
	capture.err = nil
	source.poll(context.Background())
	if got := capture.bodies; len(got) != 1 ||
		got[0] != "START retry\n detail" {
		t.Fatalf("retried multiline bodies=%v", got)
	}
}

func TestFileLogMultilineOversizedStateRecoversAfterRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	data := "START too-many\none\ntwo\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "beginning")
	enableTestMultiline(t, source, `^START `, 2, time.Hour)
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())

	store, err := loadCheckpointStore(checkpoints)
	if err != nil {
		t.Fatal(err)
	}
	absolute, _ := filepath.Abs(path)
	state := store.files[absolute]
	if state.Offset != int64(len(data)) || !state.MultilineDropping {
		t.Fatalf("oversized multiline checkpoint=%+v", state)
	}
	appendFile(t, path, "ignored\nSTART recovered\nSTART pending\n")
	restarted := newTestSource(t, path, checkpoints, "beginning")
	enableTestMultiline(t, restarted, `^START `, 2, time.Hour)
	restarted.SetLogsEmitter(capture.emit)
	restarted.poll(context.Background())
	if got := capture.bodies; len(got) != 1 || got[0] != "START recovered" {
		t.Fatalf("recovered multiline bodies=%v", got)
	}
	store, err = loadCheckpointStore(checkpoints)
	if err != nil {
		t.Fatal(err)
	}
	if store.files[absolute].MultilineDropping {
		t.Fatal("multiline drop state not cleared after new start boundary")
	}
}

func TestFileLogMultilineRedactsAfterAssembly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	if err := os.WriteFile(
		path,
		[]byte("START secret=abc\ncontinued\nSTART next\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "beginning")
	enableTestMultiline(t, source, `^START `, 32, time.Hour)
	enableTestRedaction(t, source, []string{`(?s)secret=.*`}, "")
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())
	if got := capture.bodies; len(got) != 1 ||
		got[0] != "START [REDACTED]" {
		t.Fatalf("redacted multiline=%v", got)
	}
}

func TestMultilineFramerValidatesAndDefaults(t *testing.T) {
	framer, err := newMultilineFramer(&MultilineConfig{
		StartPattern: `^START `,
	})
	if err != nil {
		t.Fatal(err)
	}
	if framer.maxLines != defaultMultilineMaxLines ||
		framer.flushAfter != defaultMultilineFlushAfter {
		t.Fatalf("multiline defaults=%+v", framer)
	}
	invalid := []MultilineConfig{
		{},
		{StartPattern: "["},
		{StartPattern: "a*"},
		{StartPattern: "^x", MaxLines: maxMultilineLines + 1},
		{StartPattern: "^x", FlushAfter: time.Millisecond},
	}
	for index := range invalid {
		if _, err := newMultilineFramer(&invalid[index]); err == nil {
			t.Fatalf("invalid multiline config %d accepted", index)
		}
	}
}
