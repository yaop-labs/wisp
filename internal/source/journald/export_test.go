package journald

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestExportReaderParsesTextAndBinaryFields(t *testing.T) {
	var stream bytes.Buffer
	stream.WriteString("__CURSOR=cursor-1\n")
	stream.WriteString("__REALTIME_TIMESTAMP=1700000000000000\n")
	stream.WriteString("PRIORITY=4\n")
	stream.WriteString("MESSAGE\n")
	var size [8]byte
	binary.LittleEndian.PutUint64(size[:], uint64(len("line one\nline two")))
	stream.Write(size[:])
	stream.WriteString("line one\nline two")
	stream.WriteByte('\n')
	stream.WriteByte('\n')

	reader := newExportReader(&stream, 1024)
	entry, err := reader.next()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(entry.fields["MESSAGE"]); got != "line one\nline two" {
		t.Fatalf("MESSAGE=%q", got)
	}
	if got := string(entry.fields["__CURSOR"]); got != "cursor-1" {
		t.Fatalf("cursor=%q", got)
	}
	if _, err := reader.next(); !errors.Is(err, io.EOF) {
		t.Fatalf("EOF error=%v", err)
	}
}

func TestExportReaderDiscardsOversizedMessageButKeepsLaterCursor(t *testing.T) {
	var stream bytes.Buffer
	stream.WriteString("MESSAGE\n")
	var size [8]byte
	binary.LittleEndian.PutUint64(size[:], 8)
	stream.Write(size[:])
	stream.WriteString("12345678")
	stream.WriteByte('\n')
	stream.WriteString("__CURSOR=cursor-after-message\n")
	stream.WriteString("__REALTIME_TIMESTAMP=1700000000000000\n\n")

	entry, err := newExportReader(&stream, 4).next()
	if err != nil {
		t.Fatal(err)
	}
	if !entry.messageOversized {
		t.Fatal("oversized MESSAGE was not marked")
	}
	if _, ok := entry.fields["MESSAGE"]; ok {
		t.Fatal("oversized MESSAGE retained")
	}
	if got := string(entry.fields["__CURSOR"]); got != "cursor-after-message" {
		t.Fatalf("cursor=%q", got)
	}
}

func TestExportReaderRejectsTruncatedBinaryField(t *testing.T) {
	var stream bytes.Buffer
	stream.WriteString("MESSAGE\n")
	var size [8]byte
	binary.LittleEndian.PutUint64(size[:], 10)
	stream.Write(size[:])
	stream.WriteString("short")

	_, err := newExportReader(&stream, 1024).next()
	if err == nil {
		t.Fatal("expected truncated binary field error")
	}
}
