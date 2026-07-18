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
    format: cri
    kubernetes:
      pod_logs_root: /host/var/log/pods
    redaction:
      patterns: ['(?i)bearer\s+[a-z0-9._-]+', 'token=[^ ]+']
      replacement: '[MASKED]'
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
		cfg.Sources.FileLog.StartAt != "beginning" ||
		cfg.Sources.FileLog.Format != "cri" ||
		cfg.Sources.FileLog.Kubernetes == nil ||
		cfg.Sources.FileLog.Kubernetes.PodLogsRoot != "/host/var/log/pods" ||
		cfg.Sources.FileLog.Redaction == nil ||
		len(cfg.Sources.FileLog.Redaction.Patterns) != 2 ||
		cfg.Sources.FileLog.Redaction.Replacement != "[MASKED]" {
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
			name: "bad format",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    format: docker-json",
			want: "format",
		},
		{
			name: "kubernetes requires CRI",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    kubernetes: {}",
			want: "requires format: cri",
		},
		{
			name: "relative pod logs root",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    format: cri\n    kubernetes:\n      pod_logs_root: var/log/pods",
			want: "absolute non-root",
		},
		{
			name: "filesystem root is too broad",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    format: cri\n    kubernetes:\n      pod_logs_root: /",
			want: "absolute non-root",
		},
		{
			name: "redaction requires rules",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    redaction: {}",
			want: "patterns",
		},
		{
			name: "invalid redaction regexp",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    redaction:\n      patterns: ['[']",
			want: "patterns[0]",
		},
		{
			name: "empty matching regexp",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    redaction:\n      patterns: ['a*']",
			want: "empty input",
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
