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
		{"exporter tls set but disabled", `
sources: {host: {interval: 15s}}
exporter: {otlp: {endpoint: "x:4317", tls: {enabled: false, ca_file: /ca.crt}}}
resource: {attributes: {service.name: wisp}}`, "enabled is false"},
		{"receiver tls set but disabled", `
sources: {otlp: {grpc: "0.0.0.0:4317", tls: {enabled: false, cert_file: /s.crt, key_file: /s.key}}}
exporter: {otlp: {endpoint: "x:4317"}}
resource: {attributes: {service.name: wisp}}`, "enabled is false"},
		{"invalid signal limit kind", `
sources: {host: {interval: 15s}}
exporter: {otlp: {endpoint: "x:4317"}, spool: {dir: /tmp/spool, signal_limits: {"Bad Kind": {max_bytes: 10}}}}
resource: {attributes: {service.name: wisp}}`, "invalid signal kind"},
		{"invalid signal limit watermarks", `
sources: {host: {interval: 15s}}
exporter: {otlp: {endpoint: "x:4317"}, spool: {dir: /tmp/spool, signal_limits: {logs: {max_bytes: 10, high_watermark: 8, low_watermark: 9}}}}
resource: {attributes: {service.name: wisp}}`, "below high_watermark"},
		{"log request split limit too small", `
sources: {host: {interval: 15s}}
exporter: {otlp: {endpoint: "x:4317", max_log_request_bytes: 1024}}
resource: {attributes: {service.name: wisp}}`, "max_log_request_bytes"},
		{"trace request split limit too small", `
sources: {host: {interval: 15s}}
exporter: {otlp: {endpoint: "x:4317", max_trace_request_bytes: 1024}}
resource: {attributes: {service.name: wisp}}`, "max_trace_request_bytes"},
		{"trace sampling mode required", `
sources: {otlp: {grpc: "127.0.0.1:4317", traces: {sampling: {sampling_percentage: 10}}}}
exporter: {otlp: {endpoint: "x:4317"}}
resource: {attributes: {service.name: wisp}}`, "sampling.mode"},
		{"trace sampling percentage required", `
sources: {otlp: {grpc: "127.0.0.1:4317", traces: {sampling: {mode: hash_seed}}}}
exporter: {otlp: {endpoint: "x:4317"}}
resource: {attributes: {service.name: wisp}}`, "sampling_percentage is required"},
		{"trace sampling percentage bounded", `
sources: {otlp: {grpc: "127.0.0.1:4317", traces: {sampling: {mode: hash_seed, sampling_percentage: 101}}}}
exporter: {otlp: {endpoint: "x:4317"}}
resource: {attributes: {service.name: wisp}}`, "between 0 and 100"},
		{"trace sampling percentage resolution", `
sources: {otlp: {grpc: "127.0.0.1:4317", traces: {sampling: {mode: hash_seed, sampling_percentage: 0.00001}}}}
exporter: {otlp: {endpoint: "x:4317"}}
resource: {attributes: {service.name: wisp}}`, "below hash_seed resolution"},
		{"host interval too short", `
sources: {host: {interval: 99ms}}
exporter: {otlp: {endpoint: "x:4317"}}
resource: {attributes: {service.name: wisp}}`, "interval must be at least 100ms"},
		{"unknown host collector", `
sources: {host: {collectors: [cpu, typo]}}
exporter: {otlp: {endpoint: "x:4317"}}
resource: {attributes: {service.name: wisp}}`, `unsupported collector "typo"`},
		{"duplicate host collector", `
sources: {host: {collectors: [cpu, cpu]}}
exporter: {otlp: {endpoint: "x:4317"}}
resource: {attributes: {service.name: wisp}}`, `duplicate collector "cpu"`},
		{"relative host virtual filesystem path", `
sources: {host: {procfs_path: host/proc}}
exporter: {otlp: {endpoint: "x:4317"}}
resource: {attributes: {service.name: wisp}}`, "procfs_path must be a clean absolute path"},
		{"unclean host virtual filesystem path", `
sources: {host: {sysfs_path: /host/sys/../sys}}
exporter: {otlp: {endpoint: "x:4317"}}
resource: {attributes: {service.name: wisp}}`, "sysfs_path must be a clean absolute path"},
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
    traces:
      sampling:
        mode: hash_seed
        sampling_percentage: 12.5
        hash_seed: 42
    tls:
      enabled: true
      cert_file: /s.crt
      key_file: /s.key
      client_ca_file: /ca.crt
    auth:
      bearer:
        - name: app-1
          token: k1
        - name: app-2
          token_env: WISP_TEST_TOKEN
exporter:
  otlp:
    endpoint: "127.0.0.1:4317"
    max_log_request_bytes: 1048576
    max_trace_request_bytes: 2097152
    auth:
      token: egress-key
    headers:
      x-tenant: tenant-a
    tls:
      enabled: true
      ca_file: /ca.crt
  spool:
    dir: ./spool
    max_bytes: 1048576
    max_age: 6h
    signal_limits:
      metrics:
        max_bytes: 524288
      logs:
        max_bytes: 524288
        high_watermark: 419430
        low_watermark: 262144
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
	if otlp.Auth == nil || len(otlp.Auth.Bearer) != 2 || otlp.Auth.Bearer[1].TokenEnv != "WISP_TEST_TOKEN" {
		t.Errorf("receiver auth not decoded: %+v", otlp.Auth)
	}
	if otlp.Traces == nil ||
		otlp.Traces.Sampling == nil ||
		otlp.Traces.Sampling.SamplingPercentage == nil ||
		*otlp.Traces.Sampling.SamplingPercentage != 12.5 ||
		otlp.Traces.Sampling.HashSeed != 42 {
		t.Errorf(
			"trace sampling not decoded: %+v",
			otlp.Traces,
		)
	}
	if cfg.Exporter.OTLP.Auth == nil || cfg.Exporter.OTLP.Auth.Token != "egress-key" {
		t.Errorf("exporter auth not decoded: %+v", cfg.Exporter.OTLP.Auth)
	}
	if cfg.Exporter.OTLP.Headers["x-tenant"] != "tenant-a" {
		t.Errorf("exporter headers not decoded: %+v", cfg.Exporter.OTLP.Headers)
	}
	if cfg.Exporter.OTLP.TLS == nil || cfg.Exporter.OTLP.TLS.CAFile != "/ca.crt" {
		t.Errorf("exporter tls not decoded: %+v", cfg.Exporter.OTLP.TLS)
	}
	if cfg.Exporter.OTLP.MaxLogRequestBytes != 1<<20 {
		t.Errorf("max_log_request_bytes = %d", cfg.Exporter.OTLP.MaxLogRequestBytes)
	}
	if cfg.Exporter.OTLP.MaxTraceRequestBytes != 2<<20 {
		t.Errorf(
			"max_trace_request_bytes = %d",
			cfg.Exporter.OTLP.MaxTraceRequestBytes,
		)
	}
	if cfg.Exporter.Spool.MaxAge.Std() != 6*time.Hour || cfg.Exporter.Spool.MaxBytes != 1<<20 {
		t.Errorf("spool not decoded: %+v", cfg.Exporter.Spool)
	}
	if got := cfg.Exporter.Spool.SignalLimits["logs"]; got.MaxBytes != 1<<19 ||
		got.HighWatermark != 419430 || got.LowWatermark != 1<<18 {
		t.Errorf("logs signal limit not decoded: %+v", got)
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

func TestEdgePolicyFlagsDecode(t *testing.T) {
	cfg, err := Parse([]byte(`
sources:
  otlp:
    grpc: "0.0.0.0:4317"
    insecure: true
    danger_allow_bearer_over_plaintext: true
exporter:
  otlp:
    endpoint: "coral.internal:4317"
    insecure: true
    danger_allow_bearer_over_plaintext: true
resource:
  attributes:
    service.name: wisp
`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Sources.OTLP.Insecure || !cfg.Sources.OTLP.DangerAllowBearerOverPlaintext {
		t.Fatalf("receiver edge flags not decoded: %+v", cfg.Sources.OTLP)
	}
	if !cfg.Exporter.OTLP.Insecure || !cfg.Exporter.OTLP.DangerAllowBearerOverPlaintext {
		t.Fatalf("exporter edge flags not decoded: %+v", cfg.Exporter.OTLP)
	}
}
