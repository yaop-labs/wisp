// Package selfobs holds wisp's own metrics and serves them as Prometheus text.
// It is stdlib-only (no client_golang).
package selfobs

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

// Counter is a monotonic integer counter.
type Counter struct{ v atomic.Uint64 }

func (c *Counter) Inc()         { c.v.Add(1) }
func (c *Counter) Add(n uint64) { c.v.Add(n) }
func (c *Counter) Get() uint64  { return c.v.Load() }

// Agent self-metrics, incremented from the collection and export paths.
var (
	HostCollections      = &Counter{} // wisp_host_collections_total
	SamplesEmitted       = &Counter{} // wisp_samples_emitted_total
	BatchesExported      = &Counter{} // wisp_batches_exported_total
	ExportFailures       = &Counter{} // wisp_export_failures_total
	ScrapeErrors         = &Counter{} // wisp_scrape_errors_total
	CardinalityDropped   = &Counter{} // wisp_cardinality_dropped_total
	CardinalityUntracked = &Counter{} // wisp_cardinality_untracked_total
	LabelLimitDropped    = &Counter{} // wisp_label_limit_dropped_total
	ResetUntracked       = &Counter{} // wisp_reset_untracked_total
	ResetReordered       = &Counter{} // wisp_reset_reordered_total
	SpoolEnqueued        = &Counter{} // wisp_spool_enqueued_total
	SpoolDrained         = &Counter{} // wisp_spool_drained_total
	SpoolDropped         = &Counter{} // wisp_spool_dropped_total
	SpoolExpired         = &Counter{} // wisp_spool_expired_total
	SpoolWriteErrors     = &Counter{} // wisp_spool_write_errors_total
	BackpressureShed     = &Counter{} // wisp_backpressure_shed_total
	OTLPReceived         = &Counter{} // wisp_otlp_received_total
	OTLPUnsupported      = &Counter{} // wisp_otlp_unsupported_total
)

type metric struct {
	name, help string
	c          *Counter
}

var registry = []metric{
	{"wisp_host_collections_total", "Host metric collection cycles completed.", HostCollections},
	{"wisp_samples_emitted_total", "Data points emitted by sources into the pipeline.", SamplesEmitted},
	{"wisp_batches_exported_total", "Batches successfully shipped by an exporter.", BatchesExported},
	{"wisp_export_failures_total", "Export attempts that returned an error.", ExportFailures},
	{"wisp_scrape_errors_total", "Scrape attempts that failed (fetch or parse).", ScrapeErrors},
	{"wisp_cardinality_dropped_total", "Series dropped by the per-target cardinality budget.", CardinalityDropped},
	{"wisp_cardinality_untracked_total", "New series admitted un-budgeted because the cardinality tracker is at capacity.", CardinalityUntracked},
	{"wisp_label_limit_dropped_total", "Series dropped because they exceeded max_labels_per_series.", LabelLimitDropped},
	{"wisp_reset_untracked_total", "Counter points not reset-normalized because the reset tracker is at capacity.", ResetUntracked},
	{"wisp_reset_reordered_total", "Counter points seen out of order (older timestamp than the series' last processed point); passed through without reset detection to avoid spurious inflation.", ResetReordered},
	{"wisp_spool_enqueued_total", "Batches written to the on-disk spool after export failure.", SpoolEnqueued},
	{"wisp_spool_drained_total", "Spooled batches successfully re-sent.", SpoolDrained},
	{"wisp_spool_dropped_total", "Spooled batches dropped because the spool was full.", SpoolDropped},
	{"wisp_spool_expired_total", "Spooled batches dropped because they exceeded max_age.", SpoolExpired},
	{"wisp_spool_write_errors_total", "Spool persistence failures (durability layer I/O errors).", SpoolWriteErrors},
	{"wisp_backpressure_shed_total", "Data points shed at the source because the spool crossed its high-water mark.", BackpressureShed},
	{"wisp_otlp_received_total", "Data points received over the OTLP receiver.", OTLPReceived},
	{"wisp_otlp_unsupported_total", "Received OTLP points dropped (explicit Histogram / Summary shapes are not modeled; send exponential histograms).", OTLPUnsupported},
}

// gaugeFunc is a gauge whose current value is read from fn at scrape time.
type gaugeFunc struct {
	name, help string
	fn         func() float64
}

var (
	gaugeMu    sync.Mutex
	gaugeFuncs []gaugeFunc
)

// RegisterGaugeFunc registers a pull-based gauge, or replaces the one with the
// same name (idempotent so repeated agent construction in tests can't duplicate
// a series). Intended to be called at wire-up time, before serving.
func RegisterGaugeFunc(name, help string, fn func() float64) {
	gaugeMu.Lock()
	defer gaugeMu.Unlock()
	for i := range gaugeFuncs {
		if gaugeFuncs[i].name == name {
			gaugeFuncs[i] = gaugeFunc{name, help, fn}
			return
		}
	}
	gaugeFuncs = append(gaugeFuncs, gaugeFunc{name, help, fn})
}

// Handler serves the registered self-metrics in Prometheus text format.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		for _, m := range registry {
			fmt.Fprintf(w, "# HELP %s %s\n", m.name, m.help)
			fmt.Fprintf(w, "# TYPE %s counter\n", m.name)
			fmt.Fprintf(w, "%s %d\n", m.name, m.c.Get())
		}
		gaugeMu.Lock()
		gauges := make([]gaugeFunc, len(gaugeFuncs))
		copy(gauges, gaugeFuncs)
		gaugeMu.Unlock()
		sort.Slice(gauges, func(i, j int) bool { return gauges[i].name < gauges[j].name })
		for _, g := range gauges {
			fmt.Fprintf(w, "# HELP %s %s\n", g.name, g.help)
			fmt.Fprintf(w, "# TYPE %s gauge\n", g.name)
			fmt.Fprintf(w, "%s %g\n", g.name, g.fn())
		}
	})
}
