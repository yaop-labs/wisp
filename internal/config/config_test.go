package config

import "testing"

const cfgYAML = `
sources:
  host:
    interval: 15s
processors:
  - type: cardinality_limit
    max_series_per_target: 50000
  - type: relabel
    rules:
      - source_labels: [__name__]
        regex: "go_.*"
        action: drop
exporter:
  otlp:
    endpoint: "127.0.0.1:4317"
resource:
  attributes:
    service.name: "wisp"
`

func TestProcessorRawDecodes(t *testing.T) {
	cfg, err := Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Processors) != 2 {
		t.Fatalf("expected 2 processors, got %d", len(cfg.Processors))
	}

	// Regression guard: each processor's typed fields must decode from Raw
	// (go-yaml inline yaml.Node silently drops siblings; we use UnmarshalYAML).
	if cfg.Processors[0].Type != "cardinality_limit" {
		t.Fatalf("processor[0] type = %q", cfg.Processors[0].Type)
	}
	var card CardinalityConfig
	if err := cfg.Processors[0].Raw.Decode(&card); err != nil {
		t.Fatal(err)
	}
	if card.MaxSeriesPerTarget != 50000 {
		t.Errorf("max_series_per_target = %d, want 50000 (Raw not captured?)", card.MaxSeriesPerTarget)
	}

	var rel RelabelConfig
	if err := cfg.Processors[1].Raw.Decode(&rel); err != nil {
		t.Fatal(err)
	}
	if len(rel.Rules) != 1 || rel.Rules[0].Action != "drop" {
		t.Errorf("relabel rules not decoded: %+v", rel.Rules)
	}
}

func TestValidateRequiresServiceName(t *testing.T) {
	_, err := Parse([]byte(`
sources:
  host:
    interval: 15s
exporter:
  otlp:
    endpoint: "127.0.0.1:4317"
`))
	if err == nil {
		t.Fatal("expected error when resource.attributes.service.name is missing")
	}
}
