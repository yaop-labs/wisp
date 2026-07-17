// Package config loads and validates wisp's YAML configuration. wisp refuses to
// start without an explicit --config, matching the rest of the yaop stack.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/tlsconf"
	"gopkg.in/yaml.v3"
)

// Duration wraps time.Duration for YAML unmarshaling (e.g. "15s").
type Duration time.Duration

func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration: expected scalar at line %d", node.Line)
	}
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("duration %q: %w", node.Value, err)
	}
	*d = Duration(parsed)
	return nil
}

// Config is the wisp agent configuration.
type Config struct {
	Agent      AgentConfig       `yaml:"agent"`
	Sources    SourcesConfig     `yaml:"sources"`
	Processors []ProcessorConfig `yaml:"processors"`
	Exporter   ExporterConfig    `yaml:"exporter"`
	Resource   ResourceConfig    `yaml:"resource"`
}

// AgentConfig holds agent-wide settings.
type AgentConfig struct {
	LogLevel    string            `yaml:"log_level"`
	SelfMetrics SelfMetricsConfig `yaml:"self_metrics"`
}

// SelfMetricsConfig configures wisp's own Prometheus /metrics endpoint.
type SelfMetricsConfig struct {
	Endpoint string `yaml:"endpoint"`
}

// SourcesConfig enables the collection sources. A nil pointer means disabled.
type SourcesConfig struct {
	Host   *HostSource   `yaml:"host"`
	Scrape *ScrapeSource `yaml:"scrape"`
	OTLP   *OTLPSource   `yaml:"otlp"`
	EBPF   *EBPFSource   `yaml:"ebpf"`
}

// HostSource configures node/host metric collection from /proc, /sys, cgroups.
type HostSource struct {
	Interval   Duration `yaml:"interval"`
	Collectors []string `yaml:"collectors"`
}

// ScrapeSource configures Prometheus/OpenMetrics pull scraping.
type ScrapeSource struct {
	Interval Duration       `yaml:"interval"`
	Timeout  Duration       `yaml:"timeout"` // per-scrape HTTP timeout; defaults to interval
	Targets  []ScrapeTarget `yaml:"targets"`
	FileSD   []FileSDConfig `yaml:"file_sd"`
	DNSSD    []DNSSDConfig  `yaml:"dns_sd"`
	KubeSD   []KubeSDConfig `yaml:"kubernetes_sd"`
}

// KubeSDConfig configures Kubernetes pod discovery for a scrape job. Pods opt in
// via the prometheus.io/scrape annotation; port comes from prometheus.io/port
// or falls back to Port.
type KubeSDConfig struct {
	Job       string `yaml:"job"`
	Namespace string `yaml:"namespace"` // empty -> all namespaces
	Port      int    `yaml:"port"`
}

// DNSSDConfig configures DNS-based service discovery for a scrape job. SRV
// records yield host+port; A/AAAA records yield hosts combined with port.
type DNSSDConfig struct {
	Job   string   `yaml:"job"`
	Names []string `yaml:"names"`
	Type  string   `yaml:"type"` // srv (default when port unset) | a | aaaa
	Port  int      `yaml:"port"` // required for a/aaaa
}

// ScrapeTarget is one scrape job with static targets.
type ScrapeTarget struct {
	Job    string   `yaml:"job"`
	Static []string `yaml:"static"`
}

// FileSDConfig configures file-based service discovery (Prometheus file_sd JSON).
type FileSDConfig struct {
	Files []string `yaml:"files"`
}

// OTLPSource configures the OTLP receiver (apps push to wisp as a local gateway).
type OTLPSource struct {
	GRPC                           string                `yaml:"grpc"`
	HTTP                           string                `yaml:"http"`
	TLS                            *tlsconf.ServerConfig `yaml:"tls"`
	Auth                           *bearer.ServerConfig  `yaml:"auth"`
	Insecure                       bool                  `yaml:"insecure"`
	DangerAllowBearerOverPlaintext bool                  `yaml:"danger_allow_bearer_over_plaintext"`
}

// EBPFSource configures kernel-side probes (Linux-only, requires CAP_BPF).
type EBPFSource struct {
	Probes []string `yaml:"probes"`
}

// ProcessorConfig stores a processor type plus the full YAML node, so each
// processor can decode its own typed fields from Raw. A custom unmarshaler is
// required because go-yaml v3 does not capture siblings into an inline yaml.Node.
type ProcessorConfig struct {
	Type string
	Raw  yaml.Node
}

func (pc *ProcessorConfig) UnmarshalYAML(node *yaml.Node) error {
	pc.Raw = *node
	var head struct {
		Type string `yaml:"type"`
	}
	if err := node.Decode(&head); err != nil {
		return err
	}
	pc.Type = head.Type
	return nil
}

// CardinalityConfig configures the cardinality_limit processor - the edge guards
// mirroring amber's MaxActiveSeries / MaxLabelsPerSeries.
type CardinalityConfig struct {
	MaxSeriesPerTarget int `yaml:"max_series_per_target"`
	MaxLabelsPerSeries int `yaml:"max_labels_per_series"`
}

// RelabelConfig configures the relabel processor.
type RelabelConfig struct {
	Rules []RelabelRule `yaml:"rules"`
}

// RelabelRule is one relabel step.
type RelabelRule struct {
	SourceLabels []string `yaml:"source_labels"`
	Separator    string   `yaml:"separator"`
	Regex        string   `yaml:"regex"`
	TargetLabel  string   `yaml:"target_label"`
	Replacement  string   `yaml:"replacement"`
	Action       string   `yaml:"action"`
}

// ExporterConfig configures egress: OTLP to the collector, fronted by a spool.
type ExporterConfig struct {
	OTLP  OTLPExporter `yaml:"otlp"`
	Spool SpoolConfig  `yaml:"spool"`
}

// OTLPExporter configures the OTLP exporter to the collector (or amber directly).
type OTLPExporter struct {
	Endpoint                       string                `yaml:"endpoint"`
	Protocol                       string                `yaml:"protocol"` // "grpc" | "http"
	Timeout                        Duration              `yaml:"timeout"`
	Retry                          RetryConfig           `yaml:"retry"`
	TLS                            *tlsconf.ClientConfig `yaml:"tls"`
	Auth                           *bearer.ClientConfig  `yaml:"auth"`
	Insecure                       bool                  `yaml:"insecure"`
	DangerAllowBearerOverPlaintext bool                  `yaml:"danger_allow_bearer_over_plaintext"`
	Headers                        map[string]string     `yaml:"headers"` // additional non-auth headers
}

// RetryConfig configures exporter retries.
type RetryConfig struct {
	MaxAttempts    int      `yaml:"max_attempts"`
	InitialBackoff Duration `yaml:"initial_backoff"`
	MaxBackoff     Duration `yaml:"max_backoff"`
}

// SpoolConfig configures the on-disk durability queue. The spool engages
// backpressure (sheds at the source) above ~80% full and releases below ~50%;
// max_age caps how long spooled data is kept. When enabled (dir set) but the
// bounds are omitted they default to 512MiB / 6h so the queue can't fill the
// disk; a negative value opts out (unbounded size / never expire).
type SpoolConfig struct {
	Dir      string   `yaml:"dir"`
	MaxBytes int64    `yaml:"max_bytes"`
	MaxAge   Duration `yaml:"max_age"`
}

// ResourceConfig holds resource attributes attached to every series. service.name
// is required; amber routes series to the right service by it.
type ResourceConfig struct {
	Attributes map[string]string `yaml:"attributes"`
}

// Load reads and validates a config file.
func Load(path string) (Config, error) {
	cfg, _, err := LoadDocument(path)
	return cfg, err
}

// LoadDocument returns both the typed configuration and a canonical JSON
// representation suitable for a Gyre Envelope. Keeping the envelope JSON-valid
// matters for audit/config APIs even though the operator-facing file is YAML.
func LoadDocument(path string) (Config, json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return Config{}, nil, err
	}
	var document any
	if err := yaml.Unmarshal(data, &document); err != nil {
		return Config{}, nil, fmt.Errorf("config: canonicalize yaml: %w", err)
	}
	spec, err := json.Marshal(document)
	if err != nil {
		return Config{}, nil, fmt.Errorf("config: encode envelope spec: %w", err)
	}
	return cfg, spec, nil
}

// Parse unmarshals and validates config from raw YAML.
func Parse(data []byte) (Config, error) {
	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("config: parse yaml: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Config{}, fmt.Errorf("config: multiple YAML documents are not supported")
		}
		return Config{}, fmt.Errorf("config: parse trailing yaml: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks invariants the agent cannot run without.
func (c *Config) Validate() error {
	if !c.Sources.AnyEnabled() {
		return fmt.Errorf("sources: at least one source must be enabled")
	}
	for i, pc := range c.Processors {
		if pc.Type == "" {
			return fmt.Errorf("processors[%d]: type is required", i)
		}
	}
	if c.Exporter.OTLP.Endpoint == "" {
		return fmt.Errorf("exporter.otlp.endpoint is required")
	}
	if o := c.Sources.OTLP; o != nil && o.GRPC == "" && o.HTTP == "" {
		return fmt.Errorf("sources.otlp: at least one of grpc or http address is required")
	}
	// Reef owns the transport-security contract. Disabled blocks are validated
	// here without filesystem I/O; enabled blocks are fully materialized (and
	// their files checked) when app wiring builds the edge.
	if c.Exporter.OTLP.TLS != nil && !c.Exporter.OTLP.TLS.Enabled {
		if _, err := tlsconf.Client(c.Exporter.OTLP.TLS); err != nil {
			return fmt.Errorf("exporter.otlp.tls: %w", err)
		}
	}
	if c.Sources.OTLP != nil && c.Sources.OTLP.TLS != nil && !c.Sources.OTLP.TLS.Enabled {
		if _, err := tlsconf.Server(c.Sources.OTLP.TLS); err != nil {
			return fmt.Errorf("sources.otlp.tls: %w", err)
		}
	}
	if _, ok := c.Resource.Attributes["service.name"]; !ok {
		return fmt.Errorf("resource.attributes.service.name is required")
	}
	return nil
}

// Enabled lists the names of the configured sources, in pipeline order. It is
// the single place the source set is enumerated (AnyEnabled and startup logging
// both derive from it).
func (s SourcesConfig) Enabled() []string {
	var names []string
	if s.Host != nil {
		names = append(names, "host")
	}
	if s.Scrape != nil {
		names = append(names, "scrape")
	}
	if s.OTLP != nil {
		names = append(names, "otlp")
	}
	if s.EBPF != nil {
		names = append(names, "ebpf")
	}
	return names
}

// AnyEnabled reports whether at least one source is configured.
func (s SourcesConfig) AnyEnabled() bool { return len(s.Enabled()) > 0 }
