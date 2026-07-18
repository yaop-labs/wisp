package config

import (
	"strings"
	"testing"
)

func TestOTLPTraceProcessingConfigParses(t *testing.T) {
	cfg, err := Parse([]byte(`
sources:
  otlp:
    grpc: "127.0.0.1:4317"
    traces:
      validation: reject
      resource:
        conflict: replace
        attributes:
          deployment.environment.name: production
          service.namespace: shop
exporter:
  otlp:
    endpoint: "127.0.0.1:4318"
resource:
  attributes:
    service.name: wisp
`))
	if err != nil {
		t.Fatal(err)
	}
	traces := cfg.Sources.OTLP.Traces
	if traces == nil || traces.Validation != "reject" ||
		traces.Resource == nil ||
		traces.Resource.Conflict != "replace" ||
		traces.Resource.Attributes["deployment.environment.name"] !=
			"production" ||
		traces.Resource.Attributes["service.namespace"] != "shop" {
		t.Fatalf("traces=%+v", traces)
	}
}

func TestOTLPTraceProcessingConfigRejectsInvalidValues(t *testing.T) {
	tests := map[string]string{
		"validation": `
      validation: drop`,
		"empty resource": `
      resource:
        conflict: preserve
        attributes: {}`,
		"conflict": `
      resource:
        conflict: merge
        attributes: {service.namespace: shop}`,
		"empty key": `
      resource:
        attributes: {"": shop}`,
		"control value": `
      resource:
        attributes: {service.namespace: "bad\x01value"}`,
		"oversized value": `
      resource:
        attributes: {service.namespace: "` +
			strings.Repeat("x", 4097) + `"}`,
	}
	for name, traceConfig := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(`
sources:
  otlp:
    grpc: "127.0.0.1:4317"
    traces:` + traceConfig + `
exporter:
  otlp:
    endpoint: "127.0.0.1:4318"
resource:
  attributes:
    service.name: wisp
`))
			if err == nil {
				t.Fatal("invalid trace processing config accepted")
			}
		})
	}
}
