package spool

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/selfobs"
)

// TestSpoolWriteFailureMarksUnhealthy: when persistence fails (read-only dir),
// the spool surfaces it (Healthy=false, counter++) instead of silently losing.
func TestSpoolWriteFailureMarksUnhealthy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}
	dir := t.TempDir()
	in := &gate{} // failing -> forces a spool write
	e, err := New(in, Config{Dir: dir, MaxBytes: 1 << 20, DrainInterval: time.Hour}, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	if !e.Healthy() {
		t.Fatal("spool should start healthy")
	}

	// Make the dir read-only so the temp-file write fails.
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	before := selfobs.SpoolWriteErrors.Get()
	if err := e.Export(context.Background(), oneBatch); err == nil {
		t.Fatal("Export should return error when persistence fails")
	}
	if e.Healthy() {
		t.Fatal("spool should be unhealthy after a write failure")
	}
	if selfobs.SpoolWriteErrors.Get() == before {
		t.Fatal("SpoolWriteErrors counter should have incremented")
	}

	// Recover: dir writable again -> next spool write succeeds -> healthy.
	_ = os.Chmod(dir, 0o755)
	if err := e.Export(context.Background(), oneBatch); err != nil {
		t.Fatalf("Export after recovery: %v", err)
	}
	if !e.Healthy() {
		t.Fatal("spool should recover to healthy after a successful write")
	}
}

// TestCleanupTempOnStart drops torn .tmp files left by a previous crash.
func TestCleanupTempOnStart(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "00000000000000000001-000001.batch.tmp")
	if err := os.WriteFile(tmp, []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := New(&gate{}, Config{Dir: dir, MaxBytes: 1 << 20, DrainInterval: time.Hour}, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("leftover .tmp should have been removed on start")
	}
}
