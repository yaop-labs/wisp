package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDocumentReturnsJSONEnvelopeSpec(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wisp.yaml")
	data := []byte(`
sources:
  host:
    interval: 15s
exporter:
  otlp:
    endpoint: 127.0.0.1:4317
resource:
  attributes:
    service.name: wisp
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, spec, err := LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Resource.Attributes["service.name"] != "wisp" {
		t.Fatalf("config=%+v", cfg)
	}
	if !json.Valid(spec) {
		t.Fatalf("spec is not JSON: %s", spec)
	}
}

func TestParseRejectsUnknownFieldsAndMultipleDocuments(t *testing.T) {
	base := `
sources: {host: {interval: 15s}}
exporter: {otlp: {endpoint: "127.0.0.1:4317"}}
resource: {attributes: {service.name: wisp}}
`
	for name, data := range map[string]string{
		"unknown":  base + "\nunknown_section: true\n",
		"multiple": base + "\n---\n{}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(data)); err == nil {
				t.Fatal("expected config rejection")
			}
		})
	}
}
