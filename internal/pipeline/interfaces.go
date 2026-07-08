// Package pipeline defines the source->processor->exporter contracts that move
// metric batches through wisp. The shapes mirror the collector's trace pipeline.
package pipeline

import (
	"context"

	"github.com/yaop-labs/wisp/internal/model"
)

// Source produces Batches and pushes them into the pipeline via emit. Start
// blocks until ctx is canceled or a fatal error occurs. Sources are pull
// (scrape, host), push (otlp receive), or probe (ebpf).
type Source interface {
	Start(ctx context.Context, emit func(context.Context, model.Batch) error) error
	Stop(ctx context.Context) error
}

// Processor transforms or filters a Batch at the edge (relabel, cardinality
// guard, reset detection, histogram conversion). Returning an empty Batch drops
// everything. Close releases resources.
type Processor interface {
	Process(ctx context.Context, b model.Batch) (model.Batch, error)
	Close() error
}

// Exporter ships Batches that passed the full processor chain (OTLP to the
// collector, fronted by the on-disk spool). Export may be called concurrently;
// Close waits for in-flight exports.
type Exporter interface {
	Export(ctx context.Context, b model.Batch) error
	Close() error
}

// Flusher is an optional Exporter capability: a best-effort final drain on
// graceful shutdown, bounded by ctx. The spool implements it so a clean stop
// flushes durable data when downstream is up.
type Flusher interface {
	Flush(ctx context.Context) error
}
