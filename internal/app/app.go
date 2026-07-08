// Package app wires a wisp agent from config: sources -> pipeline -> exporter,
// plus the self-metrics endpoint.
package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/yaop-labs/wisp/internal/config"
	otlpexp "github.com/yaop-labs/wisp/internal/exporter/otlp"
	retryexp "github.com/yaop-labs/wisp/internal/exporter/retry"
	spoolexp "github.com/yaop-labs/wisp/internal/exporter/spool"
	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/processor/cardinality"
	"github.com/yaop-labs/wisp/internal/processor/relabel"
	"github.com/yaop-labs/wisp/internal/processor/reset"
	"github.com/yaop-labs/wisp/internal/redact"
	"github.com/yaop-labs/wisp/internal/selfobs"
	ebpfsrc "github.com/yaop-labs/wisp/internal/source/ebpf"
	hostsrc "github.com/yaop-labs/wisp/internal/source/host"
	otlprecv "github.com/yaop-labs/wisp/internal/source/otlp"
	scrapesrc "github.com/yaop-labs/wisp/internal/source/scrape"
	"github.com/yaop-labs/wisp/internal/tlsconfig"
)

type App struct {
	pipeline     *pipeline.Pipeline
	selfEndpoint string
	logger       *slog.Logger
	selfSrv      *http.Server
	// scrape, when set, is the hot-reloadable scrape source (see Reload).
	scrape *scrapesrc.Source
	// healthy, when set, gates /healthz - false means not-ready (e.g. the
	// durability spool is failing to persist).
	healthy func() bool
}

// scrapeConfigFrom builds the scrape source config from the agent config - used
// at construction and on hot-reload so both paths agree.
func scrapeConfigFrom(sc *config.ScrapeSource) scrapesrc.Config {
	jobs := make(map[string][]string)
	for _, t := range sc.Targets {
		jobs[t.Job] = append(jobs[t.Job], t.Static...)
	}
	var globs []string
	for _, f := range sc.FileSD {
		globs = append(globs, f.Files...)
	}
	dnsSD := make([]scrapesrc.DNSSD, 0, len(sc.DNSSD))
	for _, d := range sc.DNSSD {
		dnsSD = append(dnsSD, scrapesrc.DNSSD{Job: d.Job, Names: d.Names, Type: d.Type, Port: d.Port})
	}
	kubeSD := make([]scrapesrc.KubernetesSD, 0, len(sc.KubeSD))
	for _, k := range sc.KubeSD {
		kubeSD = append(kubeSD, scrapesrc.KubernetesSD{Job: k.Job, Namespace: k.Namespace, Port: k.Port})
	}
	return scrapesrc.Config{Interval: sc.Interval.Std(), Static: jobs, FileSD: globs, DNSSD: dnsSD, KubeSD: kubeSD}
}

// tlsSettings maps the YAML TLS config onto the transport-agnostic Settings.
func tlsSettings(c *config.TLSConfig) tlsconfig.Settings {
	return tlsconfig.Settings{
		Enabled:            c.Enabled,
		CAFile:             c.CAFile,
		CertFile:           c.CertFile,
		KeyFile:            c.KeyFile,
		ServerName:         c.ServerName,
		InsecureSkipVerify: c.InsecureSkipVerify,
		ClientCAFile:       c.ClientCAFile,
	}
}

// clientTLS builds the exporter-side *tls.Config, or nil when TLS is disabled.
func clientTLS(c *config.TLSConfig) (*tls.Config, error) {
	if c == nil || !c.Enabled {
		return nil, nil
	}
	return tlsconfig.Client(tlsSettings(c))
}

// serverTLS builds the receiver-side *tls.Config, or nil when TLS is disabled.
func serverTLS(c *config.TLSConfig) (*tls.Config, error) {
	if c == nil || !c.Enabled {
		return nil, nil
	}
	return tlsconfig.Server(tlsSettings(c))
}

func New(cfg config.Config, logger *slog.Logger) (*App, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	p := pipeline.New(pipeline.Config{}, logger)
	resource := buildResource(cfg.Resource, logger)

	if cfg.Sources.Host != nil {
		hc := cfg.Sources.Host
		p.AddSource(hostsrc.New(hc.Interval.Std(), hc.Collectors, resource, logger))
		logger.Info("host source enabled", "interval", hc.Interval.Std())
	}
	var scrapeSrc *scrapesrc.Source
	if cfg.Sources.Scrape != nil {
		sc := cfg.Sources.Scrape
		scrapeSrc = scrapesrc.New(scrapeConfigFrom(sc), logger)
		p.AddSource(scrapeSrc)
		logger.Info("scrape source enabled", "interval", sc.Interval.Std(), "targets", len(sc.Targets), "file_sd_globs", len(sc.FileSD))
	}
	if cfg.Sources.OTLP != nil {
		oc := cfg.Sources.OTLP
		recvTLS, err := serverTLS(oc.TLS)
		if err != nil {
			return nil, fmt.Errorf("otlp receiver tls: %w", err)
		}
		var apiKeys []string
		if oc.Auth != nil {
			apiKeys = oc.Auth.APIKeys
		}
		p.AddSource(otlprecv.New(otlprecv.Options{
			GRPCAddr: oc.GRPC, HTTPAddr: oc.HTTP, TLS: recvTLS, APIKeys: apiKeys,
		}, logger))
		logger.Info("otlp receive source enabled",
			"grpc", oc.GRPC, "http", oc.HTTP,
			"tls", recvTLS != nil, "mtls", oc.TLS != nil && oc.TLS.ClientCAFile != "",
			"auth", len(apiKeys) > 0)
	}
	if cfg.Sources.EBPF != nil {
		p.AddSource(ebpfsrc.New(ebpfsrc.Config{Probes: cfg.Sources.EBPF.Probes}, logger))
		ok, reason := ebpfsrc.Available()
		logger.Info("ebpf source configured", "available", ok, "reason", reason, "probes", cfg.Sources.EBPF.Probes)
	}
	for _, pc := range cfg.Processors {
		pr, ok, err := buildProcessor(pc, logger)
		if err != nil {
			return nil, fmt.Errorf("processor %q: %w", pc.Type, err)
		}
		if ok {
			p.AddProcessor(pr)
		}
	}

	expTLS, err := clientTLS(cfg.Exporter.OTLP.TLS)
	if err != nil {
		return nil, fmt.Errorf("otlp exporter tls: %w", err)
	}
	otlpExp, err := otlpexp.New(otlpexp.Config{
		Endpoint: cfg.Exporter.OTLP.Endpoint,
		Protocol: cfg.Exporter.OTLP.Protocol,
		Timeout:  cfg.Exporter.OTLP.Timeout.Std(),
		TLS:      expTLS,
		Headers:  cfg.Exporter.OTLP.Headers,
	}, logger)
	if err != nil {
		return nil, err
	}
	if len(cfg.Exporter.OTLP.Headers) > 0 {
		// Log only the header names - never their values (bearer tokens etc.).
		logger.Info("otlp exporter auth headers configured", "header_keys", redact.Keys(cfg.Exporter.OTLP.Headers))
	}

	// otlp -> retry (transient blips) -> spool (outages, restarts).
	var exporter pipeline.Exporter = retryexp.Wrap(otlpExp, retryexp.Config{
		MaxAttempts:    cfg.Exporter.OTLP.Retry.MaxAttempts,
		InitialBackoff: cfg.Exporter.OTLP.Retry.InitialBackoff.Std(),
		MaxBackoff:     cfg.Exporter.OTLP.Retry.MaxBackoff.Std(),
	})
	var healthy func() bool // nil -> always ready; set when the spool is present
	if cfg.Exporter.Spool.Dir != "" {
		sp, err := spoolexp.New(exporter, spoolexp.Config{
			Dir:      cfg.Exporter.Spool.Dir,
			MaxBytes: cfg.Exporter.Spool.MaxBytes,
			MaxAge:   cfg.Exporter.Spool.MaxAge.Std(),
		}, logger)
		if err != nil {
			return nil, err
		}
		exporter = sp
		// Close the backpressure loop: when the spool crosses its high-water
		// mark, emit sheds at the source (pull) / returns 429 (push).
		p.SetPressure(sp.UnderPressure)
		healthy = sp.Healthy // gate /healthz on durability
		selfobs.RegisterGaugeFunc("wisp_spool_bytes", "Current on-disk spool size in bytes.", func() float64 { return float64(sp.Bytes()) })
		selfobs.RegisterGaugeFunc("wisp_spool_batches", "Current number of batches in the on-disk spool.", func() float64 { return float64(sp.Count()) })
		selfobs.RegisterGaugeFunc("wisp_backpressure_active", "1 when the spool is above its high-water mark and sources are being shed.", func() float64 {
			if sp.UnderPressure() {
				return 1
			}
			return 0
		})
		logger.Info("spool enabled", "dir", cfg.Exporter.Spool.Dir, "max_bytes", cfg.Exporter.Spool.MaxBytes, "max_age", cfg.Exporter.Spool.MaxAge.Std())
	}
	p.AddExporter(exporter)

	return &App{pipeline: p, selfEndpoint: cfg.Agent.SelfMetrics.Endpoint, logger: logger, scrape: scrapeSrc, healthy: healthy}, nil
}

// Reload applies a new config to the running agent without a restart. Only the
// safe, frequently-tuned surface is live-reloadable today - scrape targets,
// file_sd globs, and scrape interval. Changes to listeners, the exporter
// endpoint/protocol, the spool, or the processor chain require a restart and are
// ignored here (logged by the caller). The config is validated first; on error
// the running config is kept.
func (a *App) Reload(cfg config.Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("reload: invalid config, keeping current: %w", err)
	}
	switch {
	case a.scrape != nil && cfg.Sources.Scrape != nil:
		sc := cfg.Sources.Scrape
		a.scrape.Reload(scrapeConfigFrom(sc))
		a.logger.Info("reloaded scrape source", "interval", sc.Interval.Std(), "targets", len(sc.Targets), "file_sd_globs", len(sc.FileSD))
	case a.scrape != nil && cfg.Sources.Scrape == nil:
		a.logger.Warn("reload: scrape source cannot be disabled without a restart; keeping current targets")
	case a.scrape == nil && cfg.Sources.Scrape != nil:
		a.logger.Warn("reload: enabling the scrape source requires a restart")
	}
	return nil
}

func (a *App) Start(ctx context.Context) error {
	if a.selfEndpoint != "" {
		if err := a.startSelfMetrics(ctx); err != nil {
			return err
		}
	}
	return a.pipeline.Start(ctx)
}

func (a *App) Shutdown(ctx context.Context) error {
	if a.selfSrv != nil {
		_ = a.selfSrv.Shutdown(ctx)
	}
	return a.pipeline.Shutdown(ctx)
}

func (a *App) startSelfMetrics(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", selfobs.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if a.healthy != nil && !a.healthy() {
			http.Error(w, "spool unhealthy: durability layer failing", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	ln, err := net.Listen("tcp", a.selfEndpoint)
	if err != nil {
		return fmt.Errorf("self_metrics: listen %s: %w", a.selfEndpoint, err)
	}
	a.selfSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second, // bound slow-header (Slowloris) clients
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		if err := a.selfSrv.Serve(ln); err != nil && err != http.ErrServerClosed && ctx.Err() == nil {
			a.logger.Error("self_metrics server error", "err", err)
		}
	}()
	a.logger.Info("self-metrics endpoint enabled", "endpoint", a.selfEndpoint)
	return nil
}

// buildProcessor constructs a pipeline processor from its config. The bool is
// false (with nil error) for known-but-unimplemented types, which are skipped
// with a warning rather than failing startup.
func buildProcessor(pc config.ProcessorConfig, logger *slog.Logger) (pipeline.Processor, bool, error) {
	switch pc.Type {
	case "cardinality_limit":
		var c config.CardinalityConfig
		if err := pc.Raw.Decode(&c); err != nil {
			return nil, false, err
		}
		logger.Info("processor enabled", "type", pc.Type, "max_series_per_target", c.MaxSeriesPerTarget, "max_labels_per_series", c.MaxLabelsPerSeries)
		return cardinality.New(c.MaxSeriesPerTarget, c.MaxLabelsPerSeries), true, nil
	case "reset":
		logger.Info("processor enabled", "type", pc.Type)
		return reset.New(), true, nil
	case "relabel":
		var c config.RelabelConfig
		if err := pc.Raw.Decode(&c); err != nil {
			return nil, false, err
		}
		rules := make([]relabel.Rule, len(c.Rules))
		for i, r := range c.Rules {
			rules[i] = relabel.Rule{
				SourceLabels: r.SourceLabels,
				Separator:    r.Separator,
				Regex:        r.Regex,
				TargetLabel:  r.TargetLabel,
				Replacement:  r.Replacement,
				Action:       r.Action,
			}
		}
		pr, err := relabel.New(rules)
		if err != nil {
			return nil, false, err
		}
		logger.Info("processor enabled", "type", pc.Type, "rules", len(rules))
		return pr, true, nil
	default:
		logger.Warn("processor configured but not yet wired", "type", pc.Type)
		return nil, false, nil
	}
}

// buildResource turns configured resource attributes into a stable label set,
// auto-filling host.name from the OS hostname when not set.
func buildResource(cfg config.ResourceConfig, logger *slog.Logger) model.Labels {
	attrs := make(map[string]string, len(cfg.Attributes)+1)
	maps.Copy(attrs, cfg.Attributes)
	if _, ok := attrs["host.name"]; !ok {
		if h, err := os.Hostname(); err == nil {
			attrs["host.name"] = h
		} else {
			logger.Warn("could not resolve host.name", "err", err)
		}
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	labels := make(model.Labels, 0, len(keys))
	for _, k := range keys {
		labels = append(labels, model.Label{Name: k, Value: attrs[k]})
	}
	return labels
}
