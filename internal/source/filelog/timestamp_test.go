package filelog

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTimestampParserFormatsAndBounds(t *testing.T) {
	tests := []struct {
		name   string
		format string
		body   string
		want   uint64
		wantOK bool
	}{
		{
			name:   "rfc3339 nano",
			format: "rfc3339nano",
			body:   "2026-07-18T10:11:12.123456789Z message",
			want:   1784369472123456789,
			wantOK: true,
		},
		{name: "unix", format: "unix", body: "10 message", want: 10_000_000_000, wantOK: true},
		{name: "unix milliseconds", format: "unix_ms", body: "10 message", want: 10_000_000, wantOK: true},
		{name: "unix microseconds", format: "unix_us", body: "10 message", want: 10_000, wantOK: true},
		{name: "unix nanoseconds", format: "unix_ns", body: "10 message", want: 10, wantOK: true},
		{name: "missing", format: "unix", body: "message"},
		{name: "overflow", format: "unix", body: "18446744073709551615 message"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parser, err := newTimestampParser(&TimestampConfig{
				Pattern: `^(\S+)`,
				Format:  test.format,
			})
			if err != nil {
				t.Fatal(err)
			}
			got, ok := parser.parse([]byte(test.body))
			if got != test.want || ok != test.wantOK {
				t.Fatalf("timestamp=%d ok=%v, want %d/%v", got, ok, test.want, test.wantOK)
			}
		})
	}

	parser, err := newTimestampParser(&TimestampConfig{
		Pattern: `^(.+)`,
		Format:  "unix",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parser.parse([]byte(strings.Repeat("1", maxTimestampCaptureBytes+1))); ok {
		t.Fatal("oversized timestamp capture accepted")
	}
}

func TestTimestampParserValidatesConfig(t *testing.T) {
	invalid := []TimestampConfig{
		{},
		{Pattern: `^\S+$`, Format: "unix"},
		{Pattern: `^(a)(b)`, Format: "unix"},
		{Pattern: `()`, Format: "unix"},
		{Pattern: `^(\S+)`, Format: "guess"},
	}
	for index := range invalid {
		if _, err := newTimestampParser(&invalid[index]); err == nil {
			t.Fatalf("invalid timestamp config %d accepted", index)
		}
	}
}

func TestFileLogTimestampParsesBeforeRedactionAndPreservesFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	checkpoints := filepath.Join(dir, "filelog.json")
	if err := os.WriteFile(
		path,
		[]byte("2026-07-18T10:11:12Z token=secret\nbad token=hidden\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	source := newTestSource(t, path, checkpoints, "beginning")
	parser, err := newTimestampParser(&TimestampConfig{
		Pattern: `^(\S+)`,
		Format:  "rfc3339nano",
	})
	if err != nil {
		t.Fatal(err)
	}
	source.timestamp = parser
	enableTestRedaction(t, source, []string{`token=\S+`}, "")
	capture := &logCapture{}
	source.SetLogsEmitter(capture.emit)
	source.poll(context.Background())

	wantTime, err := time.Parse(time.RFC3339Nano, "2026-07-18T10:11:12Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(capture.records) != 2 ||
		capture.records[0].TimeUnixNano != uint64(wantTime.UnixNano()) ||
		capture.records[1].TimeUnixNano != 0 {
		t.Fatalf("timestamped records=%v", capture.records)
	}
	if capture.bodies[0] != "2026-07-18T10:11:12Z [REDACTED]" ||
		capture.bodies[1] != "bad [REDACTED]" {
		t.Fatalf("timestamp/redaction bodies=%v", capture.bodies)
	}
}
