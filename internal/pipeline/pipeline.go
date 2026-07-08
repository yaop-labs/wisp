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
// Its shape mirrors the collector's trace pipeline.
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

	// runCtx is a cancellable child of Start's context handed to sources and
	// workers. Shutdown cancels it so sources stop deterministically even when
	// the parent context is still live (e.g. a programmatic stop in tests).
	runCtx    context.Context
	runCancel context.CancelFunc

	// pressure, when set and returning true, makes emit shed batches at the
	// source instead of admitting them. Wired to the spool's high-water mark.
	pressure func() bool

	batchesIn      atomic.Uint64
	batchesDropped atomic.Uint64
	pointsOut      atomic.Uint64
}

// SetPressure wires a backpressure signal (e.g. the spool's UnderPressure) that
// emit consults before admitting a batch. Call before Start.
func (p *Pipeline) SetPressure(fn func() bool) { p.pressure = fn }

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

	for i := 0; i < p.cfg.Workers; i++ {
		p.wg.Add(1)
		go p.worker(p.runCtx)
	}

	emit := func(ctx context.Context, b model.Batch) error {
		if b.Len() == 0 {
			return nil
		}
		if p.pressure != nil && p.pressure() {
			selfobs.BackpressureShed.Add(uint64(b.Len()))
			return ErrBackpressure
		}
		p.batchesIn.Add(1)
		select {
		case p.in <- b:
			return nil
		case <-ctx.Done():
			p.batchesDropped.Add(1)
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

func (p *Pipeline) worker(ctx context.Context) {
	defer p.wg.Done()
	for b := range p.in {
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
	// Discovery meta labels (__meta_*) are available to relabel but must not be
	// exported - strip them after the processor chain (Prometheus semantics).
	stripMetaLabels(&b)
	for _, e := range p.exporters {
		if err := e.Export(ctx, b); err != nil {
			p.logger.Error("exporter error", "err", err)
		}
	}
	p.pointsOut.Add(uint64(b.Len()))
	return nil
}

// Stats returns pipeline counters for observability.
func (p *Pipeline) Stats() (batchesIn, batchesDropped, pointsOut uint64) {
	return p.batchesIn.Load(), p.batchesDropped.Load(), p.pointsOut.Load()
}

const metaLabelPrefix = "__meta_"

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
