package config

import (
	"strings"
	"testing"
	"time"
)

func TestJournaldConfigParses(t *testing.T) {
	cfg, err := Parse([]byte(`
sources:
  journald:
    checkpoint_file: /var/lib/wisp/journald.json
    poll_interval: 2s
    timeout: 8s
    start_at: beginning
    directory: /host/var/log/journal
    units: [checkout.service]
    identifiers: [worker]
    max_entries_per_poll: 250
    max_field_bytes: 131072
    max_batch_bytes: 524288
    redaction:
      patterns: ['token=[^ ]+']
      replacement: token=[MASKED]
exporter:
  otlp:
    endpoint: 127.0.0.1:4317
resource:
  attributes:
    service.name: wisp
`))
	if err != nil {
		t.Fatal(err)
	}
	source := cfg.Sources.Journald
	if source == nil ||
		source.PollInterval.Std() != 2*time.Second ||
		source.Timeout.Std() != 8*time.Second ||
		source.StartAt != "beginning" ||
		source.MaxEntries != 250 ||
		source.Redaction == nil ||
		len(source.Redaction.Patterns) != 1 {
		t.Fatalf("journald config=%+v", source)
	}
}

func TestJournaldConfigRejectsUnsafeValues(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"missing checkpoint", "start_at: end", "checkpoint_file"},
		{
			"short timeout",
			"checkpoint_file: /tmp/cp\n    timeout: 10ms",
			"timeout",
		},
		{
			"relative directory",
			"checkpoint_file: /tmp/cp\n    directory: var/log/journal",
			"absolute non-root",
		},
		{
			"bad filter",
			"checkpoint_file: /tmp/cp\n    units: [\"bad\\nunit\"]",
			"printable",
		},
		{
			"batch below field",
			"checkpoint_file: /tmp/cp\n    max_field_bytes: 1024\n    max_batch_bytes: 512",
			"max_batch_bytes",
		},
		{
			"empty matching redaction",
			"checkpoint_file: /tmp/cp\n    redaction:\n      patterns: ['a*']",
			"empty input",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse([]byte(`
sources:
  journald:
    ` + test.body + `
exporter:
  otlp:
    endpoint: 127.0.0.1:4317
resource:
  attributes:
    service.name: wisp
`))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}
