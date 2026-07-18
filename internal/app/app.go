// Package app wires a wisp agent from config: sources -> pipeline -> exporter,
// plus the self-metrics endpoint.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/yaop-labs/wisp/internal/config"
	otlpexp "github.com/yaop-labs/wisp/internal/exporter/otlp"
	retryexp "github.com/yaop-labs/wisp/internal/exporter/retry"
	"github.com/yaop-labs/wisp/internal/exporter/signalrouter"
	spoolexp "github.com/yaop-labs/wisp/internal/exporter/spool"
	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/otlpwire"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/processor/cardinality"
	"github.com/yaop-labs/wisp/internal/processor/relabel"
	"github.com/yaop-labs/wisp/internal/processor/reset"
	"github.com/yaop-labs/wisp/internal/redact"
	"github.com/yaop-labs/wisp/internal/selfobs"
	"github.com/yaop-labs/wisp/internal/signal"
	ebpfsrc "github.com/yaop-labs/wisp/internal/source/ebpf"
	filelogsrc "github.com/yaop-labs/wisp/internal/source/filelog"
	hostsrc "github.com/yaop-labs/wisp/internal/source/host"
	otlprecv "github.com/yaop-labs/wisp/internal/source/otlp"
	scrapesrc "github.com/yaop-labs/wisp/internal/source/scrape"
)

type App struct {
	pipeline     *pipeline.Pipeline
	selfEndpoint string
	logger       *slog.Logger
	selfSrv      *http.Server
	// operational exposes the Gyre lifecycle endpoints alongside /metrics.
	// It is installed before Start by NewGyreComponent.
	operational http.Handler
	configMu    sync.Mutex
	config      config.Config
	// scrape, when set, is the hot-reloadable scrape source (see Reload).
	scrape       *scrapesrc.Source
	otlpReceiver *otlprecv.Receiver
	// checks gate readiness. Liveness remains cheap and process-local: a broken
	// durability layer makes Wisp unready/degraded, not falsely dead.
	checks []readinessCheck
}

// readinessCheck is a cheap named dependency/durability probe.
type readinessCheck struct {
	name  string
	check func() error
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
	return scrapesrc.Config{Interval: sc.Interval.Std(), Timeout: sc.Timeout.Std(), Static: jobs, FileSD: globs, DNSSD: dnsSD, KubeSD: kubeSD}
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
	logRequestBytes := effectiveLogRequestBytes(cfg)

	// Source registry: one entry per source type (name for logs, presence gate,
	// and constructor). Adding a source is one entry here plus its config field
	// and config.SourcesConfig.Enabled - not scattered if-blocks.
	var (
		scrapeSrc  *scrapesrc.Source
		otlpRecv   *otlprecv.Receiver
		filelogSrc *filelogsrc.Source
	)
	registry := []struct {
		name    string
		present bool
		build   func() (pipeline.Source, error)
	}{
		{"host", cfg.Sources.Host != nil, func() (pipeline.Source, error) {
			hc := cfg.Sources.Host
			logger.Info("host source enabled", "interval", hc.Interval.Std())
			return hostsrc.New(hc.Interval.Std(), hc.Collectors, resource, logger), nil
		}},
		{"scrape", cfg.Sources.Scrape != nil, func() (pipeline.Source, error) {
			sc := cfg.Sources.Scrape
			scrapeSrc = scrapesrc.New(scrapeConfigFrom(sc), logger) // captured for hot-reload
			logger.Info("scrape source enabled", "interval", sc.Interval.Std(), "targets", len(sc.Targets), "file_sd_globs", len(sc.FileSD))
			return scrapeSrc, nil
		}},
		{"otlp", cfg.Sources.OTLP != nil, func() (pipeline.Source, error) {
			oc := cfg.Sources.OTLP
			logger.Info("otlp receive source enabled",
				"grpc", oc.GRPC, "http", oc.HTTP,
				"tls", oc.TLS != nil && oc.TLS.Enabled, "mtls", oc.TLS != nil && oc.TLS.ClientCAFile != "",
				"auth", oc.Auth != nil && len(oc.Auth.Bearer) > 0)
			receiver, err := otlprecv.New(otlprecv.Options{
				GRPCAddr:                       oc.GRPC,
				HTTPAddr:                       oc.HTTP,
				TLS:                            oc.TLS,
				Auth:                           oc.Auth,
				Insecure:                       oc.Insecure,
				DangerAllowBearerOverPlaintext: oc.DangerAllowBearerOverPlaintext,
				MaxLogRequestBytes:             logRequestBytes,
			}, logger)
			otlpRecv = receiver
			return receiver, err
		}},
		{"filelog", cfg.Sources.FileLog != nil, func() (pipeline.Source, error) {
			fc := cfg.Sources.FileLog
			maxLineBytes, maxBatchBytes := effectiveFileLogBounds(fc, logRequestBytes)
			source, err := filelogsrc.New(filelogsrc.Config{
				Include:        fc.Include,
				Exclude:        fc.Exclude,
				CheckpointFile: fc.CheckpointFile,
				PollInterval:   fc.PollInterval.Std(),
				StartAt:        fc.StartAt,
				Format:         fc.Format,
				MaxLineBytes:   maxLineBytes,
				MaxBatchBytes:  maxBatchBytes,
				MaxReadBytes:   fc.MaxReadBytes,
				Resource:       maps.Clone(cfg.Resource.Attributes),
			}, logger)
			if err != nil {
				return nil, err
			}
			filelogSrc = source
			logger.Info("filelog source enabled",
				"include_patterns", len(fc.Include),
				"exclude_patterns", len(fc.Exclude),
				"checkpoint_file", fc.CheckpointFile,
				"format", source.Format(),
				"max_line_bytes", maxLineBytes,
				"max_batch_bytes", maxBatchBytes)
			return source, nil
		}},
		{"ebpf", cfg.Sources.EBPF != nil, func() (pipeline.Source, error) {
			ok, reason := ebpfsrc.Available()
			logger.Info("ebpf source configured", "available", ok, "reason", reason, "probes", cfg.Sources.EBPF.Probes)
			return ebpfsrc.New(ebpfsrc.Config{Probes: cfg.Sources.EBPF.Probes}, logger), nil
		}},
	}
	for _, s := range registry {
		if !s.present {
			continue
		}
		src, err := s.build()
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", s.name, err)
		}
		p.AddSource(src)
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

	otlpExp, err := otlpexp.New(otlpexp.Config{
		Endpoint:                       cfg.Exporter.OTLP.Endpoint,
		Protocol:                       cfg.Exporter.OTLP.Protocol,
		Timeout:                        cfg.Exporter.OTLP.Timeout.Std(),
		TLS:                            cfg.Exporter.OTLP.TLS,
		Auth:                           cfg.Exporter.OTLP.Auth,
		Insecure:                       cfg.Exporter.OTLP.Insecure,
		DangerAllowBearerOverPlaintext: cfg.Exporter.OTLP.DangerAllowBearerOverPlaintext,
		Headers:                        cfg.Exporter.OTLP.Headers,
	}, logger)
	if err != nil {
		return nil, err
	}
	if len(cfg.Exporter.OTLP.Headers) > 0 {
		// Log only the header names, never their values.
		logger.Info("otlp exporter additional headers configured", "header_keys", redact.Keys(cfg.Exporter.OTLP.Headers))
	}
	if cfg.Exporter.OTLP.Auth != nil {
		logger.Info("otlp exporter reef bearer auth configured")
	}

	retryConfig := retryexp.Config{
		MaxAttempts:    cfg.Exporter.OTLP.Retry.MaxAttempts,
		InitialBackoff: cfg.Exporter.OTLP.Retry.InitialBackoff.Std(),
		MaxBackoff:     cfg.Exporter.OTLP.Retry.MaxBackoff.Std(),
	}
	// Metrics keep their typed adapter. Logs and traces get independent OTLP
	// capabilities and all routes converge on one signal-neutral durability
	// queue.
	var exporter pipeline.Exporter = retryexp.Wrap(otlpExp, retryConfig)
	var (
		logsSender   signal.Sender
		tracesSender signal.Sender
	)
	if otlpRecv != nil || filelogSrc != nil {
		signalConfig := otlpexp.Config{
			Endpoint:                       cfg.Exporter.OTLP.Endpoint,
			Protocol:                       cfg.Exporter.OTLP.Protocol,
			Timeout:                        cfg.Exporter.OTLP.Timeout.Std(),
			TLS:                            cfg.Exporter.OTLP.TLS,
			Auth:                           cfg.Exporter.OTLP.Auth,
			Insecure:                       cfg.Exporter.OTLP.Insecure,
			DangerAllowBearerOverPlaintext: cfg.Exporter.OTLP.DangerAllowBearerOverPlaintext,
			Headers:                        cfg.Exporter.OTLP.Headers,
			MaxLogRequestBytes:             logRequestBytes,
		}
		logsExporter, logsErr := otlpexp.NewLogs(signalConfig, logger)
		if logsErr != nil {
			_ = exporter.Close()
			return nil, logsErr
		}
		logsSender = retryexp.WrapSender(logsExporter, retryConfig)
	}
	if otlpRecv != nil {
		signalConfig := otlpexp.Config{
			Endpoint:                       cfg.Exporter.OTLP.Endpoint,
			Protocol:                       cfg.Exporter.OTLP.Protocol,
			Timeout:                        cfg.Exporter.OTLP.Timeout.Std(),
			TLS:                            cfg.Exporter.OTLP.TLS,
			Auth:                           cfg.Exporter.OTLP.Auth,
			Insecure:                       cfg.Exporter.OTLP.Insecure,
			DangerAllowBearerOverPlaintext: cfg.Exporter.OTLP.DangerAllowBearerOverPlaintext,
			Headers:                        cfg.Exporter.OTLP.Headers,
		}
		tracesExporter, tracesErr := otlpexp.NewTraces(signalConfig, logger)
		if tracesErr != nil {
			_ = exporter.Close()
			_ = logsSender.Close()
			return nil, tracesErr
		}
		tracesSender = retryexp.WrapSender(tracesExporter, retryConfig)
		logger.Info("otlp traces lossless passthrough configured",
			"max_receiver_request_bytes", otlpwire.MaxReceiverRequestBytes)
	}
	if logsSender != nil {
		logger.Info("otlp logs request splitting configured",
			"max_request_bytes", logRequestBytes)
	}
	var checks []readinessCheck
	if cfg.Exporter.Spool.Dir != "" {
		signalLimits := make(map[signal.Kind]spoolexp.SignalLimit, len(cfg.Exporter.Spool.SignalLimits))
		for kind, limit := range cfg.Exporter.Spool.SignalLimits {
			signalLimits[signal.Kind(kind)] = spoolexp.SignalLimit{
				MaxBytes: limit.MaxBytes, HighWatermark: limit.HighWatermark,
				LowWatermark: limit.LowWatermark,
			}
		}
		routes := map[signal.Kind]signal.Sender{
			signal.Metrics: spoolexp.NewMetricSender(exporter),
		}
		if logsSender != nil {
			routes[signal.Logs] = logsSender
		}
		if tracesSender != nil {
			routes[signal.Traces] = tracesSender
		}
		router, routeErr := signalrouter.New(routes)
		if routeErr != nil {
			_ = exporter.Close()
			if logsSender != nil {
				_ = logsSender.Close()
			}
			if tracesSender != nil {
				_ = tracesSender.Close()
			}
			return nil, routeErr
		}
		queue, queueErr := spoolexp.NewQueue(router, spoolexp.Config{
			Dir:          cfg.Exporter.Spool.Dir,
			MaxBytes:     cfg.Exporter.Spool.MaxBytes,
			MaxAge:       cfg.Exporter.Spool.MaxAge.Std(),
			SignalLimits: signalLimits,
		}, logger)
		if queueErr != nil {
			_ = router.Close()
			return nil, queueErr
		}
		sp := spoolexp.NewMetricAdapter(queue)
		exporter = sp
		if otlpRecv != nil {
			otlpRecv.SetLogsEmitter(func(ctx context.Context, envelope signal.Envelope) error {
				if queue.UnderSignalPressure(signal.Logs) {
					return pipeline.ErrBackpressure
				}
				return queue.Accept(ctx, envelope)
			})
			otlpRecv.SetTracesEmitter(func(ctx context.Context, envelope signal.Envelope) error {
				if queue.UnderSignalPressure(signal.Traces) {
					return pipeline.ErrBackpressure
				}
				return queue.Accept(ctx, envelope)
			})
		}
		if filelogSrc != nil {
			filelogSrc.SetLogsEmitter(func(ctx context.Context, envelope signal.Envelope) error {
				if queue.UnderSignalPressure(signal.Logs) {
					return pipeline.ErrBackpressure
				}
				return queue.Accept(ctx, envelope)
			})
		}
		// Close the backpressure loop: when the spool crosses its high-water
		// mark, emit sheds at the source (pull) / returns 429 (push).
		p.SetPressure(sp.UnderPressure)
		checks = append(checks, readinessCheck{"spool", func() error {
			if !sp.Healthy() {
				return fmt.Errorf("durability layer failing")
			}
			return nil
		}})
		selfobs.RegisterGaugeFunc("wisp_spool_bytes", "Current on-disk spool size in bytes.", func() float64 { return float64(sp.Bytes()) })
		selfobs.RegisterGaugeFunc("wisp_spool_batches", "Current number of batches in the on-disk spool.", func() float64 { return float64(sp.Count()) })
		selfobs.RegisterGaugeFunc("wisp_backpressure_active", "1 when the spool is above its high-water mark and sources are being shed.", func() float64 {
			if sp.UnderPressure() {
				return 1
			}
			return 0
		})
		selfobs.RegisterGaugeVecFunc("wisp_spool_signal_bytes", "Current on-disk spool size by signal in bytes.", "signal", func() map[string]float64 {
			out := make(map[string]float64)
			for kind, depth := range sp.DepthBySignal() {
				out[string(kind)] = float64(depth.Bytes)
			}
			return out
		})
		selfobs.RegisterGaugeVecFunc("wisp_spool_signal_envelopes", "Current number of on-disk envelopes by signal.", "signal", func() map[string]float64 {
			out := make(map[string]float64)
			for kind, depth := range sp.DepthBySignal() {
				out[string(kind)] = float64(depth.Count)
			}
			return out
		})
		selfobs.RegisterGaugeVecFunc("wisp_spool_signal_pressure_active", "1 when a signal is under global or signal-specific spool pressure.", "signal", func() map[string]float64 {
			out := make(map[string]float64)
			for kind, depth := range sp.DepthBySignal() {
				if depth.UnderPressure {
					out[string(kind)] = 1
				} else {
					out[string(kind)] = 0
				}
			}
			return out
		})
		logger.Info("spool enabled", "dir", cfg.Exporter.Spool.Dir, "max_bytes", cfg.Exporter.Spool.MaxBytes, "max_age", cfg.Exporter.Spool.MaxAge.Std())
	} else if logsSender != nil {
		if otlpRecv != nil {
			otlpRecv.SetLogsEmitter(logsSender.Send)
			otlpRecv.SetTracesEmitter(tracesSender.Send)
		}
		if filelogSrc != nil {
			filelogSrc.SetLogsEmitter(logsSender.Send)
		}
		senders := []signal.Sender{logsSender}
		if tracesSender != nil {
			senders = append(senders, tracesSender)
		}
		exporter = &exporterWithSignalClose{
			Exporter: exporter,
			senders:  senders,
		}
	}
	if filelogSrc != nil {
		checks = append(checks, readinessCheck{"filelog checkpoint", filelogSrc.Healthy})
		selfobs.RegisterGaugeFunc(
			"wisp_filelog_active_files",
			"Current number of regular files matched by filelog include/exclude patterns.",
			func() float64 { return float64(filelogSrc.ActiveFiles()) },
		)
	}
	p.AddExporter(exporter)

	return &App{
		pipeline:     p,
		selfEndpoint: cfg.Agent.SelfMetrics.Endpoint,
		logger:       logger,
		scrape:       scrapeSrc,
		otlpReceiver: otlpRecv,
		checks:       checks,
		config:       cfg,
	}, nil
}

const envelopeMetadataReserve = 256 << 10
const fileLogRequestReserve = 64 << 10

func effectiveLogRequestBytes(cfg config.Config) int {
	limit := cfg.Exporter.OTLP.MaxLogRequestBytes
	if limit <= 0 {
		limit = otlpwire.DefaultMaxRequestBytes
	}
	if cfg.Exporter.Spool.Dir == "" {
		return limit
	}
	caps := []int64{cfg.Exporter.Spool.MaxBytes}
	if logs, ok := cfg.Exporter.Spool.SignalLimits[string(signal.Logs)]; ok {
		caps = append(caps, logs.MaxBytes)
	}
	for _, capBytes := range caps {
		if capBytes <= 0 {
			continue
		}
		candidate := capBytes - envelopeMetadataReserve
		if candidate <= 0 {
			candidate = capBytes / 2
		}
		if candidate > 0 && candidate < int64(limit) {
			limit = int(candidate)
		}
	}
	return limit
}

func effectiveFileLogBounds(cfg *config.FileLogSource, requestLimit int) (int, int) {
	maxLine := cfg.MaxLineBytes
	if maxLine <= 0 {
		maxLine = 256 << 10
	}
	maxBatch := cfg.MaxBatchBytes
	if maxBatch <= 0 {
		maxBatch = 512 << 10
	}
	payloadLimit := requestLimit - fileLogRequestReserve
	if payloadLimit < 1 {
		payloadLimit = 1
	}
	if maxBatch > payloadLimit {
		maxBatch = payloadLimit
	}
	if maxLine > maxBatch {
		maxLine = maxBatch
	}
	return maxLine, maxBatch
}

type exporterWithSignalClose struct {
	pipeline.Exporter
	senders []signal.Sender
}

func (e *exporterWithSignalClose) Close() error {
	err := e.Exporter.Close()
	for i := len(e.senders) - 1; i >= 0; i-- {
		err = errors.Join(err, e.senders[i].Close())
	}
	return err
}

// SetOperationalHandler installs the Gyre lifecycle handler. It must be called
// before Start; Wisp intentionally serves operational state and self-metrics on
// one listener so operators have one local endpoint to secure and scrape.
func (a *App) SetOperationalHandler(handler http.Handler) {
	a.operational = handler
}

// Ready checks dependencies that determine whether Wisp can durably accept and
// forward telemetry. These checks must stay cheap because Gyre calls them from
// /readyz.
func (a *App) Ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a == nil || a.pipeline == nil {
		return fmt.Errorf("pipeline unavailable")
	}
	for _, c := range a.checks {
		if err := c.check(); err != nil {
			return fmt.Errorf("%s: %w", c.name, err)
		}
	}
	return nil
}

type ReloadOutcome struct {
	Changed []string
}

// Reload applies a new config to the running agent without a restart. Only the
// safe, frequently-tuned surface is live-reloadable today - scrape targets,
// file_sd globs, and scrape interval. Changes to listeners, the exporter
// endpoint/protocol, the spool, or the processor chain are rejected. The config
// is validated first; on any error the running config and generation are kept.
func (a *App) Reload(cfg config.Config) (ReloadOutcome, error) {
	if err := cfg.Validate(); err != nil {
		return ReloadOutcome{}, fmt.Errorf("reload: invalid config, keeping current: %w", err)
	}
	a.configMu.Lock()
	defer a.configMu.Unlock()

	if fields := restartRequiredChanges(a.config, cfg); len(fields) > 0 {
		return ReloadOutcome{}, fmt.Errorf("reload requires restart for %s; keeping current config", strings.Join(fields, ", "))
	}
	var changed []string
	switch {
	case a.scrape != nil && cfg.Sources.Scrape != nil:
		sc := cfg.Sources.Scrape
		if !reflect.DeepEqual(a.config.Sources.Scrape, cfg.Sources.Scrape) {
			a.scrape.Reload(scrapeConfigFrom(sc))
			a.logger.Info("reloaded scrape source", "interval", sc.Interval.Std(), "targets", len(sc.Targets), "file_sd_globs", len(sc.FileSD))
			changed = append(changed, "sources.scrape")
		}
	case a.scrape != nil && cfg.Sources.Scrape == nil:
		return ReloadOutcome{}, fmt.Errorf("reload requires restart for sources.scrape; keeping current config")
	case a.scrape == nil && cfg.Sources.Scrape != nil:
		return ReloadOutcome{}, fmt.Errorf("reload requires restart for sources.scrape; keeping current config")
	}
	a.config = cfg
	return ReloadOutcome{Changed: changed}, nil
}

// restartRequiredChanges returns config surfaces that cannot be changed without
// rebuilding listeners, processors, exporters, or resource identity. Rejecting
// these changes preserves last-known-good semantics instead of silently
// accepting a generation that Wisp did not actually apply.
func restartRequiredChanges(current, next config.Config) []string {
	var fields []string
	if !reflect.DeepEqual(current.Agent, next.Agent) {
		fields = append(fields, "agent")
	}
	if !reflect.DeepEqual(current.Sources.Host, next.Sources.Host) {
		fields = append(fields, "sources.host")
	}
	if !reflect.DeepEqual(current.Sources.OTLP, next.Sources.OTLP) {
		fields = append(fields, "sources.otlp")
	}
	if !reflect.DeepEqual(current.Sources.FileLog, next.Sources.FileLog) {
		fields = append(fields, "sources.filelog")
	}
	if !reflect.DeepEqual(current.Sources.EBPF, next.Sources.EBPF) {
		fields = append(fields, "sources.ebpf")
	}
	if (current.Sources.Scrape == nil) != (next.Sources.Scrape == nil) {
		fields = append(fields, "sources.scrape")
	}
	if !processorsEqual(current.Processors, next.Processors) {
		fields = append(fields, "processors")
	}
	if !reflect.DeepEqual(current.Exporter, next.Exporter) {
		fields = append(fields, "exporter")
	}
	if !reflect.DeepEqual(current.Resource, next.Resource) {
		fields = append(fields, "resource")
	}
	return fields
}

// processorsEqual compares processor meaning rather than yaml.Node source
// positions/styles. Gyre reloads use a canonical JSON spec, so raw YAML node
// metadata necessarily differs from the startup document even when the
// processor configuration is identical.
func processorsEqual(current, next []config.ProcessorConfig) bool {
	if len(current) != len(next) {
		return false
	}
	for i := range current {
		if current[i].Type != next[i].Type {
			return false
		}
		var currentValue, nextValue any
		if err := current[i].Raw.Decode(&currentValue); err != nil {
			return false
		}
		if err := next[i].Raw.Decode(&nextValue); err != nil {
			return false
		}
		if !reflect.DeepEqual(currentValue, nextValue) {
			return false
		}
	}
	return true
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
	if a.operational != nil {
		mux.Handle("/healthz", a.operational)
		mux.Handle("/readyz", a.operational)
		mux.Handle("/status", a.operational)
	} else {
		// Keep a minimal liveness endpoint for direct App users. The production
		// binary always installs Gyre before Start.
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}

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

// buildProcessor constructs a pipeline processor from its config. Unknown
// processor types fail startup/reload rather than being silently ignored.
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
		return nil, false, fmt.Errorf("unsupported processor type %q", pc.Type)
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
	labels := make(model.Labels, 0, len(attrs))
	for _, k := range slices.Sorted(maps.Keys(attrs)) {
		labels = append(labels, model.Label{Name: k, Value: attrs[k]})
	}
	return labels
}
