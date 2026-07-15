package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/selfobs"
)

// ErrBackpressure is returned by emit when the durability spool has crossed its
// high-water mark: the batch is shed at the source rather than buffered.
// Pull sources treat it as load-shedding (drop quietly); the push receiver maps
// it to gRPC RESOURCE_EXHAUSTED / HTTP 429 so the client backs off.
var ErrBackpressure = errors.New("pipeline: backpressure (spool above high-water mark)")

// IsLoggableEmitError reports whether a source should log an emit failure: a
// genuine error, not shutdown (ctx cancelled) or expected backpressure shedding.
// Centralized so a new source can't forget the ErrBackpressure exclusion and
// flood logs whenever the spool is above its high-water mark.
func IsLoggableEmitError(ctx context.Context, err error) bool {
	return err != nil && ctx.Err() == nil && !errors.Is(err, ErrBackpressure)
}

// ErrPermanent marks an export failure that will never succeed for this batch:
// a malformed or oversized request (payload-specific HTTP/gRPC status), as
// opposed to a transient outage or recoverable server/configuration state. The
// retry exporter stops retrying it and the spool quarantines the batch instead
// of letting it block the drain queue.
var ErrPermanent = errors.New("pipeline: permanent export failure")

// Config controls pipeline concurrency.
type Config struct {
	Workers   int
	QueueSize int
}

func (c *Config) setDefaults() {
	if c.Workers <= 0 {
		c.Workers = runtime.NumCPU()
	}
	if c.QueueSize <= 0 {
		c.QueueSize = 10000
	}
}

// Pipeline moves metric batches from sources through processors to exporters.
type Pipeline struct {
	cfg        Config
	sources    []Source
	processors []Processor
	exporters  []Exporter
	logger     *slog.Logger

	in           chan model.Batch
	wg           sync.WaitGroup // worker goroutines
	srcWG        sync.WaitGroup // source goroutines; joined before close(in)
	shutdownOnce sync.Once

	// runCtx is a cancellable child of Start's context handed to sources.
	// Shutdown cancels it so sources stop deterministically even when the parent
	// context is still live (e.g. a programmatic stop in tests).
	runCtx    context.Context
	runCancel context.CancelFunc

	// exportCtx is the context workers export under. It starts as runCtx and is
	// swapped to the shutdown context for the final drain, so queued batches ship
	// under a live deadline instead of the run context SIGTERM already cancelled.
	exportCtx atomic.Pointer[context.Context]

	// pressure, when set and returning true, makes emit shed batches at the
	// source instead of admitting them. Wired to the spool's high-water mark.
	pressure func() bool
}

// SetPressure wires a backpressure signal (e.g. the spool's UnderPressure) that
// emit consults before admitting a batch. Call before Start.
func (p *Pipeline) SetPressure(fn func() bool) { p.pressure = fn }

func (p *Pipeline) setExportCtx(ctx context.Context) { p.exportCtx.Store(&ctx) }

// exportContext returns the context workers should export under (runCtx during
// normal operation, the shutdown context during the final drain).
func (p *Pipeline) exportContext() context.Context {
	if c := p.exportCtx.Load(); c != nil {
		return *c
	}
	return context.Background()
}

func New(cfg Config, logger *slog.Logger) *Pipeline {
	cfg.setDefaults()
	return &Pipeline{
		cfg:    cfg,
		logger: logger,
		in:     make(chan model.Batch, cfg.QueueSize),
	}
}

func (p *Pipeline) AddSource(s Source)        { p.sources = append(p.sources, s) }
func (p *Pipeline) AddProcessor(pr Processor) { p.processors = append(p.processors, pr) }
func (p *Pipeline) AddExporter(e Exporter)    { p.exporters = append(p.exporters, e) }

// Start launches the worker pool and all sources.
func (p *Pipeline) Start(ctx context.Context) error {
	p.runCtx, p.runCancel = context.WithCancel(ctx)
	p.setExportCtx(p.runCtx)
	// Strip discovery meta labels (__meta_*) as the always-last stage, so the core
	// loop treats it like any other processor instead of special-casing one
	// source's convention (Prometheus semantics: __meta_* is relabel-only).
	p.processors = append(p.processors, metaStripper{})

	for i := 0; i < p.cfg.Workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}

	emit := func(ctx context.Context, b model.Batch) error {
		if b.Len() == 0 {
			return nil
		}
		if p.pressure != nil && p.pressure() {
			selfobs.BackpressureShed.Add(uint64(b.Len()))
			return ErrBackpressure
		}
		select {
		case p.in <- b:
			// Count points as emitted only once they are actually admitted to the
			// queue - not at the source, where a shed or dropped batch would still
			// be counted (inflating loss = emitted - exported - shed).
			selfobs.SamplesEmitted.Add(uint64(b.Len()))
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	for _, s := range p.sources {
		p.srcWG.Add(1)
		go func() {
			defer p.srcWG.Done()
			if err := s.Start(p.runCtx, emit); err != nil && p.runCtx.Err() == nil {
				p.logger.Error("source exited with error", "err", err)
			}
		}()
	}
	return nil
}

// Shutdown stops sources, drains the queue, closes processors and exporters.
// Safe to call multiple times.
func (p *Pipeline) Shutdown(ctx context.Context) error {
	var err error
	p.shutdownOnce.Do(func() {
		for _, s := range p.sources {
			if stopErr := s.Stop(ctx); stopErr != nil {
				p.logger.Error("source stop error", "err", stopErr)
			}
		}
		// Export the final drain under the shutdown context, not the run context
		// SIGTERM already cancelled — otherwise every queued batch fails Export
		// instantly and is dropped (or loops pointlessly through the spool). Swap
		// before cancelling runCtx so no drained batch sees a cancelled ctx. (P0-4)
		p.setExportCtx(ctx)
		// Cancel the run context and wait for every source goroutine (and the
		// in-flight scrapes they spawn) to return before closing the queue.
		// Otherwise a source still inside emit() can send on a closed channel and
		// panic, aborting shutdown before the spool is flushed. (P0-3)
		if p.runCancel != nil {
			p.runCancel()
		}
		p.srcWG.Wait()

		close(p.in)
		p.wg.Wait()

		for i := len(p.processors) - 1; i >= 0; i-- {
			if closeErr := p.processors[i].Close(); closeErr != nil {
				p.logger.Error("processor close error", "err", closeErr)
			}
		}
		// Best-effort final drain (bounded by ctx) before closing, so a clean
		// shutdown flushes the durability spool when downstream is up.
		for _, e := range p.exporters {
			if f, ok := e.(Flusher); ok {
				if flushErr := f.Flush(ctx); flushErr != nil {
					p.logger.Warn("exporter flush incomplete on shutdown", "err", flushErr)
				}
			}
		}
		for _, e := range p.exporters {
			if closeErr := e.Close(); closeErr != nil {
				p.logger.Error("exporter close error", "err", closeErr)
				err = closeErr
			}
		}
	})
	return err
}

func (p *Pipeline) worker() {
	defer p.wg.Done()
	for b := range p.in {
		ctx := p.exportContext()
		if err := p.process(ctx, b); err != nil && ctx.Err() == nil {
			p.logger.Error("pipeline processing error", "err", err)
		}
	}
}

func (p *Pipeline) process(ctx context.Context, b model.Batch) error {
	var err error
	for _, pr := range p.processors {
		b, err = pr.Process(ctx, b)
		if err != nil {
			return fmt.Errorf("processor: %w", err)
		}
		if b.Len() == 0 {
			return nil
		}
	}
	for _, e := range p.exporters {
		if err := e.Export(ctx, b); err != nil {
			p.logger.Error("exporter error", "err", err)
		}
	}
	return nil
}

const metaLabelPrefix = "__meta_"

// metaStripper is the pipeline's always-last processor: it removes discovery meta
// labels before export. Appended automatically in Start.
type metaStripper struct{}

func (metaStripper) Process(_ context.Context, b model.Batch) (model.Batch, error) {
	stripMetaLabels(&b)
	return b, nil
}
func (metaStripper) Close() error { return nil }

// stripMetaLabels removes discovery meta labels (__meta_*) from every series'
// resource and point attributes before export.
func stripMetaLabels(b *model.Batch) {
	for i := range b.Series {
		b.Series[i].Resource = withoutMeta(b.Series[i].Resource)
		b.Series[i].Attrs = withoutMeta(b.Series[i].Attrs)
	}
}

func withoutMeta(ls model.Labels) model.Labels {
	meta := 0
	for _, l := range ls {
		if strings.HasPrefix(l.Name, metaLabelPrefix) {
			meta++
		}
	}
	if meta == 0 {
		return ls
	}
	out := make(model.Labels, 0, len(ls)-meta)
	for _, l := range ls {
		if !strings.HasPrefix(l.Name, metaLabelPrefix) {
			out = append(out, l)
		}
	}
	return out
}
