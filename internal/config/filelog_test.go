package config

import (
	"strings"
	"testing"
)

func TestFileLogConfigParses(t *testing.T) {
	cfg, err := Parse([]byte(`
sources:
  filelog:
    include: ["/var/log/app/*.log"]
    exclude: ["/var/log/app/*.gz"]
    checkpoint_file: "/var/lib/wisp/filelog.json"
    poll_interval: 500ms
    start_at: beginning
    max_line_bytes: 65536
    max_batch_bytes: 262144
    max_read_bytes_per_poll: 1048576
exporter:
  otlp:
    endpoint: "127.0.0.1:4317"
resource:
  attributes:
    service.name: checkout
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sources.FileLog == nil ||
		cfg.Sources.FileLog.CheckpointFile != "/var/lib/wisp/filelog.json" ||
		cfg.Sources.FileLog.StartAt != "beginning" {
		t.Fatalf("filelog config=%+v", cfg.Sources.FileLog)
	}
}

func TestFileLogConfigRejectsUnsafeBounds(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "missing checkpoint",
			body: `include: ["/tmp/*.log"]`,
			want: "checkpoint_file",
		},
		{
			name: "bad start",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    start_at: middle",
			want: "start_at",
		},
		{
			name: "batch below line",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    max_line_bytes: 1024\n    max_batch_bytes: 512",
			want: "max_batch_bytes",
		},
		{
			name: "read below batch",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    max_line_bytes: 1024\n    max_batch_bytes: 65536\n    max_read_bytes_per_poll: 32768",
			want: "max_read_bytes_per_poll",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse([]byte(`
sources:
  filelog:
    ` + test.body + `
exporter:
  otlp:
    endpoint: "127.0.0.1:4317"
resource:
  attributes:
    service.name: checkout
`))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}
