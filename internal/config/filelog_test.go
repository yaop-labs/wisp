package config

import (
	"strings"
	"testing"
	"time"
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

func TestFileLogMultilineConfigParses(t *testing.T) {
	cfg, err := Parse([]byte(`
sources:
  filelog:
    include: ["/var/log/app/*.log"]
    checkpoint_file: "/var/lib/wisp/filelog.json"
    format: text
    multiline:
      start_pattern: '^\d{4}-\d{2}-\d{2} '
      max_lines: 128
      flush_after: 3s
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
	multiline := cfg.Sources.FileLog.Multiline
	if multiline == nil || multiline.MaxLines != 128 ||
		multiline.FlushAfter.Std() != 3*time.Second {
		t.Fatalf("multiline config=%+v", multiline)
	}
}

func TestFileLogTimestampConfigParses(t *testing.T) {
	cfg, err := Parse([]byte(`
sources:
  filelog:
    include: ["/var/log/app/*.log"]
    checkpoint_file: "/var/lib/wisp/filelog.json"
    format: text
    timestamp:
      pattern: '^(\S+)'
      format: rfc3339nano
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
	timestamp := cfg.Sources.FileLog.Timestamp
	if timestamp == nil || timestamp.Format != "rfc3339nano" {
		t.Fatalf("timestamp config=%+v", timestamp)
	}
}

func TestFileLogKubernetesAPIConfigParses(t *testing.T) {
	cfg, err := Parse([]byte(`
sources:
  filelog:
    include: ["/var/log/pods/*/*/*.log"]
    checkpoint_file: "/var/lib/wisp/filelog.json"
    format: cri
    kubernetes:
      pod_logs_root: /var/log/pods
      api:
        timeout: 2s
        cache_ttl: 5m
        stale_after: 1h
        failure_retry: 30s
        max_pods: 5000
        workers: 4
        labels: [app.kubernetes.io/name, app.kubernetes.io/version]
exporter:
  otlp:
    endpoint: "127.0.0.1:4317"
resource:
  attributes:
    service.name: wisp
`))
	if err != nil {
		t.Fatal(err)
	}
	api := cfg.Sources.FileLog.Kubernetes.API
	if api == nil || api.Timeout.Std() != 2*time.Second ||
		api.CacheTTL.Std() != 5*time.Minute ||
		api.StaleAfter.Std() != time.Hour ||
		api.MaxPods != 5000 || api.Workers != 4 ||
		len(api.Labels) != 2 {
		t.Fatalf("Kubernetes API config=%+v", api)
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
			name: "Kubernetes API stale below TTL",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    format: cri\n    kubernetes:\n      api:\n        cache_ttl: 1h\n        stale_after: 5m",
			want: "stale_after",
		},
		{
			name: "Kubernetes API duplicate label",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    format: cri\n    kubernetes:\n      api:\n        labels: [app, app]",
			want: "duplicate",
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
			name: "multiline rejects CRI",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    format: cri\n    multiline:\n      start_pattern: '^START '",
			want: "text format",
		},
		{
			name: "multiline requires start pattern",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    multiline: {}",
			want: "start_pattern",
		},
		{
			name: "multiline rejects empty match",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    multiline:\n      start_pattern: 'a*'",
			want: "empty input",
		},
		{
			name: "multiline rejects short flush",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    multiline:\n      start_pattern: '^START '\n      flush_after: 1ms",
			want: "flush_after",
		},
		{
			name: "timestamp rejects CRI",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    format: cri\n    timestamp:\n      pattern: '^(\\\\S+)'\n      format: rfc3339nano",
			want: "text format",
		},
		{
			name: "timestamp requires one capture",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    timestamp:\n      pattern: '^\\\\S+'\n      format: rfc3339nano",
			want: "capture group",
		},
		{
			name: "timestamp rejects unknown format",
			body: "include: [\"/tmp/*.log\"]\n    checkpoint_file: /tmp/cp\n    timestamp:\n      pattern: '^(\\\\S+)'\n      format: auto",
			want: "timestamp.format",
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
