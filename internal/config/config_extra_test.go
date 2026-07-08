package config

import (
	"strings"
	"testing"
	"time"
)

const validYAML = `
sources:
  host:
    interval: 15s
exporter:
  otlp:
    endpoint: "127.0.0.1:4317"
resource:
  attributes:
    service.name: "wisp"
`

func TestParseValid(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Sources.Host == nil || cfg.Sources.Host.Interval.Std() != 15*time.Second {
		t.Errorf("host interval not decoded: %+v", cfg.Sources.Host)
	}
}

func TestParseBadYAML(t *testing.T) {
	if _, err := Parse([]byte("sources: [this is not a map")); err == nil {
		t.Error("malformed YAML should error")
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name, yaml, wantSubstr string
	}{
		{"no sources", `
exporter: {otlp: {endpoint: "x:4317"}}
resource: {attributes: {service.name: wisp}}`, "at least one source"},
		{"no endpoint", `
sources: {host: {interval: 15s}}
resource: {attributes: {service.name: wisp}}`, "endpoint is required"},
		{"no service.name", `
sources: {host: {interval: 15s}}
exporter: {otlp: {endpoint: "x:4317"}}
resource: {attributes: {foo: bar}}`, "service.name is required"},
		{"processor without type", `
sources: {host: {interval: 15s}}
exporter: {otlp: {endpoint: "x:4317"}}
resource: {attributes: {service.name: wisp}}
processors: [{max_series_per_target: 10}]`, "type is required"},
		{"otlp source without address", `
sources: {otlp: {}}
exporter: {otlp: {endpoint: "x:4317"}}
resource: {attributes: {service.name: wisp}}`, "grpc or http"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.yaml))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), c.wantSubstr) {
				t.Errorf("error = %q, want substring %q", err, c.wantSubstr)
			}
		})
	}
}

func TestDurationUnmarshal(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sources.Host.Interval.Std() != 15*time.Second {
		t.Errorf("interval = %v", cfg.Sources.Host.Interval.Std())
	}
	// Invalid duration string -> error.
	if _, err := Parse([]byte(strings.Replace(validYAML, "15s", "fortnight", 1))); err == nil {
		t.Error("invalid duration should error")
	}
}

func TestDecodeTLSAuthAndDiscovery(t *testing.T) {
	const y = `
sources:
  scrape:
    interval: 30s
    dns_sd:
      - job: node
        names: ["_m._tcp.svc"]
        type: srv
    kubernetes_sd:
      - job: pods
        namespace: prod
        port: 9100
  otlp:
    grpc: "0.0.0.0:4317"
    tls:
      enabled: true
      cert_file: /s.crt
      key_file: /s.key
      client_ca_file: /ca.crt
    auth:
      api_keys: ["k1", "k2"]
exporter:
  otlp:
    endpoint: "127.0.0.1:4317"
    headers:
      authorization: "Bearer x"
    tls:
      enabled: true
      ca_file: /ca.crt
  spool:
    dir: ./spool
    max_bytes: 1048576
    max_age: 6h
resource:
  attributes:
    service.name: "wisp"
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	sc := cfg.Sources.Scrape
	if len(sc.DNSSD) != 1 || sc.DNSSD[0].Type != "srv" || sc.DNSSD[0].Names[0] != "_m._tcp.svc" {
		t.Errorf("dns_sd not decoded: %+v", sc.DNSSD)
	}
	if len(sc.KubeSD) != 1 || sc.KubeSD[0].Namespace != "prod" || sc.KubeSD[0].Port != 9100 {
		t.Errorf("kubernetes_sd not decoded: %+v", sc.KubeSD)
	}
	otlp := cfg.Sources.OTLP
	if otlp.TLS == nil || !otlp.TLS.Enabled || otlp.TLS.ClientCAFile != "/ca.crt" {
		t.Errorf("receiver tls not decoded: %+v", otlp.TLS)
	}
	if otlp.Auth == nil || len(otlp.Auth.APIKeys) != 2 {
		t.Errorf("receiver auth not decoded: %+v", otlp.Auth)
	}
	if cfg.Exporter.OTLP.Headers["authorization"] != "Bearer x" {
		t.Errorf("exporter headers not decoded: %+v", cfg.Exporter.OTLP.Headers)
	}
	if cfg.Exporter.OTLP.TLS == nil || cfg.Exporter.OTLP.TLS.CAFile != "/ca.crt" {
		t.Errorf("exporter tls not decoded: %+v", cfg.Exporter.OTLP.TLS)
	}
	if cfg.Exporter.Spool.MaxAge.Std() != 6*time.Hour || cfg.Exporter.Spool.MaxBytes != 1<<20 {
		t.Errorf("spool not decoded: %+v", cfg.Exporter.Spool)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("/no/such/wisp-config.yaml"); err == nil {
		t.Error("Load of a missing file should error")
	}
}

func TestAnyEnabled(t *testing.T) {
	if (SourcesConfig{}).AnyEnabled() {
		t.Error("empty sources should not be enabled")
	}
	if !(SourcesConfig{OTLP: &OTLPSource{}}).AnyEnabled() {
		t.Error("otlp source should count as enabled")
	}
}
