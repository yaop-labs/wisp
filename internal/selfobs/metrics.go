// Package selfobs holds wisp's own metrics and serves them as Prometheus text.
// It is stdlib-only (no client_golang).
package selfobs

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
)

// Counter is a monotonic integer counter.
type Counter struct{ v atomic.Uint64 }

func (c *Counter) Inc()         { c.v.Add(1) }
func (c *Counter) Add(n uint64) { c.v.Add(n) }
func (c *Counter) Get() uint64  { return c.v.Load() }

type metric struct {
	name, help string
	c          *Counter
}

var registry []metric

// newCounter creates a counter and registers it for the /metrics endpoint in one
// step, so a counter can't exist without being exposed (or be listed twice).
func newCounter(name, help string) *Counter {
	c := &Counter{}
	registry = append(registry, metric{name, help, c})
	return c
}

// Agent self-metrics, incremented from the collection and export paths.
var (
	HostCollections        = newCounter("wisp_host_collections_total", "Host metric collection cycles completed.")
	SamplesEmitted         = newCounter("wisp_samples_emitted_total", "Data points emitted by sources into the pipeline.")
	BatchesExported        = newCounter("wisp_batches_exported_total", "Batches successfully shipped by an exporter.")
	ExportFailures         = newCounter("wisp_export_failures_total", "Export attempts that returned an error.")
	ScrapeErrors           = newCounter("wisp_scrape_errors_total", "Scrape attempts that failed (fetch or parse).")
	CardinalityDropped     = newCounter("wisp_cardinality_dropped_total", "Series dropped by the per-target cardinality budget.")
	CardinalityUntracked   = newCounter("wisp_cardinality_untracked_total", "New series admitted un-budgeted because the cardinality tracker is at capacity.")
	LabelLimitDropped      = newCounter("wisp_label_limit_dropped_total", "Series dropped because they exceeded max_labels_per_series.")
	ResetUntracked         = newCounter("wisp_reset_untracked_total", "Counter points not reset-normalized because the reset tracker is at capacity.")
	ResetReordered         = newCounter("wisp_reset_reordered_total", "Counter points dropped because their timestamp was older than the series' last processed point and a correct reset offset could not be reconstructed.")
	SpoolEnqueued          = newCounter("wisp_spool_enqueued_total", "Batches written to the on-disk spool after export failure.")
	SpoolDrained           = newCounter("wisp_spool_drained_total", "Spooled batches successfully re-sent.")
	SpoolDropped           = newCounter("wisp_spool_dropped_total", "Spooled batches dropped because the spool was full.")
	SpoolQuarantined       = newCounter("wisp_spool_quarantined_total", "Spooled batches discarded on drain because downstream rejected them permanently (malformed/oversized).")
	SpoolCorrupt           = newCounter("wisp_spool_corrupt_total", "Spooled files dropped on drain because they could not be decoded (torn by a crash mid-write, or bit-rot).")
	SpoolExpired           = newCounter("wisp_spool_expired_total", "Spooled batches dropped because they exceeded max_age.")
	SpoolWriteErrors       = newCounter("wisp_spool_write_errors_total", "Spool persistence failures (durability layer I/O errors).")
	BackpressureShed       = newCounter("wisp_backpressure_shed_total", "Data points shed at the source because the spool crossed its high-water mark.")
	OTLPReceived           = newCounter("wisp_otlp_received_total", "Data points received over the OTLP receiver.")
	OTLPUnsupported        = newCounter("wisp_otlp_unsupported_total", "Received OTLP points dropped (explicit Histogram / Summary shapes are not modeled; send exponential histograms).")
	OTLPLogsReceived       = newCounter("wisp_otlp_logs_received_total", "Log records durably accepted from OTLP.")
	OTLPLogsChunks         = newCounter("wisp_otlp_logs_chunks_total", "Durable OTLP Logs chunks admitted after bounded splitting.")
	OTLPLogsChunksExported = newCounter("wisp_otlp_logs_chunks_exported_total", "OTLP Logs chunks successfully exported downstream.")
	OTLPLogsSplitRequests  = newCounter("wisp_otlp_logs_split_requests_total", "Incoming OTLP Logs requests split into multiple durable envelopes.")
	OTLPLogsCompatSplits   = newCounter("wisp_otlp_logs_compat_split_attempts_total", "Exporter-side split attempts for legacy oversized Logs envelopes.")
	OTLPLogsRejected       = newCounter("wisp_otlp_logs_rejected_total", "Log records rejected in an OTLP downstream partial-success response.")
)

// gaugeFunc is a gauge whose current value is read from fn at scrape time.
type gaugeFunc struct {
	name, help string
	fn         func() float64
}

type gaugeVecFunc struct {
	name, help, label string
	fn                func() map[string]float64
}

var (
	gaugeMu    sync.Mutex
	gaugeFuncs []gaugeFunc
	gaugeVecs  []gaugeVecFunc
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

// RegisterGaugeVecFunc registers a pull-based gauge with one bounded label.
// Re-registering a metric name replaces the previous collector.
func RegisterGaugeVecFunc(name, help, label string, fn func() map[string]float64) {
	gaugeMu.Lock()
	defer gaugeMu.Unlock()
	for i := range gaugeVecs {
		if gaugeVecs[i].name == name {
			gaugeVecs[i] = gaugeVecFunc{name, help, label, fn}
			return
		}
	}
	gaugeVecs = append(gaugeVecs, gaugeVecFunc{name, help, label, fn})
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
		vectors := make([]gaugeVecFunc, len(gaugeVecs))
		copy(vectors, gaugeVecs)
		gaugeMu.Unlock()
		sort.Slice(gauges, func(i, j int) bool { return gauges[i].name < gauges[j].name })
		for _, g := range gauges {
			fmt.Fprintf(w, "# HELP %s %s\n", g.name, g.help)
			fmt.Fprintf(w, "# TYPE %s gauge\n", g.name)
			fmt.Fprintf(w, "%s %g\n", g.name, g.fn())
		}
		sort.Slice(vectors, func(i, j int) bool { return vectors[i].name < vectors[j].name })
		for _, vector := range vectors {
			fmt.Fprintf(w, "# HELP %s %s\n", vector.name, vector.help)
			fmt.Fprintf(w, "# TYPE %s gauge\n", vector.name)
			values := vector.fn()
			labels := make([]string, 0, len(values))
			for value := range values {
				labels = append(labels, value)
			}
			sort.Strings(labels)
			for _, value := range labels {
				fmt.Fprintf(w, "%s{%s=%s} %g\n",
					vector.name, vector.label, strconv.Quote(value), values[value])
			}
		}
	})
}
