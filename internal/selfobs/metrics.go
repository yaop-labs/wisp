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
	HostCollections           = newCounter("wisp_host_collections_total", "Host metric collection cycles completed.")
	SamplesEmitted            = newCounter("wisp_samples_emitted_total", "Data points emitted by sources into the pipeline.")
	BatchesExported           = newCounter("wisp_batches_exported_total", "Batches successfully shipped by an exporter.")
	ExportFailures            = newCounter("wisp_export_failures_total", "Export attempts that returned an error.")
	ScrapeErrors              = newCounter("wisp_scrape_errors_total", "Scrape attempts that failed (fetch or parse).")
	CardinalityDropped        = newCounter("wisp_cardinality_dropped_total", "Series dropped by the per-target cardinality budget.")
	CardinalityUntracked      = newCounter("wisp_cardinality_untracked_total", "New series admitted un-budgeted because the cardinality tracker is at capacity.")
	LabelLimitDropped         = newCounter("wisp_label_limit_dropped_total", "Series dropped because they exceeded max_labels_per_series.")
	ResetUntracked            = newCounter("wisp_reset_untracked_total", "Counter points not reset-normalized because the reset tracker is at capacity.")
	ResetReordered            = newCounter("wisp_reset_reordered_total", "Counter points dropped because their timestamp was older than the series' last processed point and a correct reset offset could not be reconstructed.")
	SpoolEnqueued             = newCounter("wisp_spool_enqueued_total", "Batches written to the on-disk spool after export failure.")
	SpoolDrained              = newCounter("wisp_spool_drained_total", "Spooled batches successfully re-sent.")
	SpoolDropped              = newCounter("wisp_spool_dropped_total", "Spooled batches dropped because the spool was full.")
	SpoolQuarantined          = newCounter("wisp_spool_quarantined_total", "Spooled batches discarded on drain because downstream rejected them permanently (malformed/oversized).")
	SpoolCorrupt              = newCounter("wisp_spool_corrupt_total", "Spooled files dropped on drain because they could not be decoded (torn by a crash mid-write, or bit-rot).")
	SpoolExpired              = newCounter("wisp_spool_expired_total", "Spooled batches dropped because they exceeded max_age.")
	SpoolWriteErrors          = newCounter("wisp_spool_write_errors_total", "Spool persistence failures (durability layer I/O errors).")
	BackpressureShed          = newCounter("wisp_backpressure_shed_total", "Data points shed at the source because the spool crossed its high-water mark.")
	OTLPReceived              = newCounter("wisp_otlp_received_total", "Data points received over the OTLP receiver.")
	OTLPUnsupported           = newCounter("wisp_otlp_unsupported_total", "Received OTLP points dropped (explicit Histogram / Summary shapes are not modeled; send exponential histograms).")
	OTLPLogsReceived          = newCounter("wisp_otlp_logs_received_total", "Log records durably accepted from OTLP.")
	OTLPLogsChunks            = newCounter("wisp_otlp_logs_chunks_total", "Durable OTLP Logs chunks admitted after bounded splitting.")
	OTLPLogsChunksExported    = newCounter("wisp_otlp_logs_chunks_exported_total", "OTLP Logs chunks successfully exported downstream.")
	OTLPLogsSplitRequests     = newCounter("wisp_otlp_logs_split_requests_total", "Incoming OTLP Logs requests split into multiple durable envelopes.")
	OTLPLogsCompatSplits      = newCounter("wisp_otlp_logs_compat_split_attempts_total", "Exporter-side split attempts for legacy oversized Logs envelopes.")
	OTLPLogsRejected          = newCounter("wisp_otlp_logs_rejected_total", "Log records rejected in an OTLP downstream partial-success response.")
	OTLPTraceSpansReceived    = newCounter("wisp_otlp_trace_spans_received_total", "Trace spans durably accepted from OTLP.")
	OTLPTraceRequestsReceived = newCounter(
		"wisp_otlp_trace_requests_received_total",
		"Non-empty OTLP Traces requests completely processed through durable chunks and explicit oversized-trace rejection.",
	)
	OTLPTraceChunks = newCounter(
		"wisp_otlp_trace_chunks_total",
		"Trace-aware OTLP chunks durably admitted without splitting a trace ID.",
	)
	OTLPTraceSplitRequests = newCounter(
		"wisp_otlp_trace_split_requests_total",
		"Incoming OTLP Traces requests that required trace-aware bounded splitting.",
	)
	OTLPTraceOversizedTraces = newCounter(
		"wisp_otlp_trace_oversized_traces_total",
		"Complete traces rejected because one indivisible trace exceeded the configured request bound.",
	)
	OTLPTraceOversizedSpans = newCounter(
		"wisp_otlp_trace_oversized_spans_total",
		"Spans rejected with their complete trace because that trace exceeded the configured request bound.",
	)
	OTLPTraceRequestsExported = newCounter(
		"wisp_otlp_trace_requests_exported_total",
		"Durable OTLP Traces requests successfully exported downstream.",
	)
	OTLPTraceSpansRejected = newCounter(
		"wisp_otlp_trace_spans_rejected_total",
		"Trace spans rejected in an OTLP downstream partial-success response.",
	)
	OTLPTraceCompatSplits = newCounter(
		"wisp_otlp_trace_compat_split_attempts_total",
		"Exporter-side trace-aware split attempts for legacy oversized Traces envelopes.",
	)
	OTLPTraceChunksExported = newCounter(
		"wisp_otlp_trace_chunks_exported_total",
		"Bounded OTLP Traces chunks successfully exported downstream.",
	)
	OTLPTraceValidationRequests = newCounter(
		"wisp_otlp_trace_validation_requests_total",
		"Non-empty OTLP Traces requests inspected by correlation validation.",
	)
	OTLPTraceValidationFailures = newCounter(
		"wisp_otlp_trace_validation_failures_total",
		"OTLP Traces requests containing at least one correlation validation failure.",
	)
	OTLPTraceInvalidSpans = newCounter(
		"wisp_otlp_trace_invalid_spans_total",
		"OTLP spans containing one or more correlation validation failures.",
	)
	OTLPTraceInvalidTraceIDs = newCounter(
		"wisp_otlp_trace_invalid_trace_ids_total",
		"OTLP spans with a trace ID that was not a non-zero 16-byte identifier.",
	)
	OTLPTraceInvalidSpanIDs = newCounter(
		"wisp_otlp_trace_invalid_span_ids_total",
		"OTLP spans with a span ID that was not a non-zero 8-byte identifier.",
	)
	OTLPTraceInvalidParentIDs = newCounter(
		"wisp_otlp_trace_invalid_parent_ids_total",
		"OTLP spans with a non-empty parent span ID that was not a valid identifier.",
	)
	OTLPTraceInvalidLinks = newCounter(
		"wisp_otlp_trace_invalid_links_total",
		"OTLP span links with an invalid trace or span identifier.",
	)
	OTLPTraceInvalidTraceStates = newCounter(
		"wisp_otlp_trace_invalid_tracestates_total",
		"OTLP spans or links with a tracestate that violates W3C Trace Context syntax.",
	)
	OTLPTraceDuplicateSpanIDs = newCounter(
		"wisp_otlp_trace_duplicate_span_ids_total",
		"Duplicate trace ID and span ID pairs found within one OTLP request.",
	)
	OTLPTraceParentCycleSpans = newCounter(
		"wisp_otlp_trace_parent_cycle_spans_total",
		"OTLP spans participating in a parent cycle visible within one request.",
	)
	OTLPTraceMissingNames = newCounter(
		"wisp_otlp_trace_missing_names_total",
		"OTLP spans with an empty required name.",
	)
	OTLPTraceInvalidTimestamps = newCounter(
		"wisp_otlp_trace_invalid_timestamps_total",
		"OTLP spans with missing timestamps or an end time before the start time.",
	)
	OTLPTraceResourceEnrichedSpans = newCounter(
		"wisp_otlp_trace_resource_enriched_spans_total",
		"OTLP spans durably admitted after applying an explicit trace resource enrichment policy.",
	)
	OTLPTraceResourceConflicts = newCounter(
		"wisp_otlp_trace_resource_conflicts_total",
		"OTLP Traces requests rejected by the explicit resource conflict policy.",
	)
	FileLogRecords           = newCounter("wisp_filelog_records_total", "File log records durably admitted.")
	FileLogBatches           = newCounter("wisp_filelog_batches_total", "File log batches durably admitted.")
	FileLogBytesRead         = newCounter("wisp_filelog_bytes_read_total", "Bytes read while tailing configured files, including retried bytes.")
	FileLogOversized         = newCounter("wisp_filelog_oversized_records_total", "File log records dropped because they exceeded max_line_bytes.")
	FileLogRotations         = newCounter("wisp_filelog_rotations_total", "File identity changes handled as rotations.")
	FileLogRotationMisses    = newCounter("wisp_filelog_rotation_misses_total", "Rotated file identities no longer present when Wisp attempted to drain them.")
	FileLogTruncations       = newCounter("wisp_filelog_truncations_total", "Same-identity file truncations detected by size regression.")
	FileLogCheckpointErrors  = newCounter("wisp_filelog_checkpoint_errors_total", "Atomic file log checkpoint writes that failed.")
	FileLogReadErrors        = newCounter("wisp_filelog_read_errors_total", "File log discovery or tail operations that failed.")
	FileLogAdmissionErrors   = newCounter("wisp_filelog_admission_errors_total", "File log batches that downstream delivery or spool admission did not durably accept.")
	FileLogBackpressure      = newCounter("wisp_filelog_backpressure_total", "File log batches paused by logs spool pressure.")
	FileLogCRIFragments      = newCounter("wisp_filelog_cri_fragments_total", "Valid CRI physical fragments parsed.")
	FileLogCRIParseErrors    = newCounter("wisp_filelog_cri_parse_errors_total", "Malformed CRI physical lines preserved as raw log records.")
	FileLogCRISequenceErrors = newCounter(
		"wisp_filelog_cri_sequence_errors_total",
		"CRI fragment sequences terminated because framing or stream continuity was invalid.",
	)
	FileLogCRIPartialRecords = newCounter(
		"wisp_filelog_cri_partial_records_total",
		"Unterminated CRI fragment sequences flushed while draining a rotated file.",
	)
	FileLogKubernetesEnriched = newCounter(
		"wisp_filelog_kubernetes_enriched_records_total",
		"File log records durably admitted with Kubernetes resource attributes derived from a pod log path.",
	)
	FileLogKubernetesMisses = newCounter(
		"wisp_filelog_kubernetes_enrichment_misses_total",
		"File log records durably admitted without path-derived Kubernetes attributes while enrichment was enabled.",
	)
	FileLogKubernetesAPICacheHits = newCounter(
		"wisp_filelog_kubernetes_api_cache_hits_total",
		"Kubernetes API metadata cache hits.",
	)
	FileLogKubernetesAPICacheMisses = newCounter(
		"wisp_filelog_kubernetes_api_cache_misses_total",
		"Kubernetes API metadata cache misses.",
	)
	FileLogKubernetesAPIStaleHits = newCounter(
		"wisp_filelog_kubernetes_api_stale_hits_total",
		"Stale Kubernetes API metadata used while an asynchronous refresh was scheduled.",
	)
	FileLogKubernetesAPIRefreshes = newCounter(
		"wisp_filelog_kubernetes_api_refreshes_total",
		"Successful Kubernetes API pod metadata refreshes.",
	)
	FileLogKubernetesAPIEnriched = newCounter(
		"wisp_filelog_kubernetes_api_enriched_records_total",
		"File log records durably admitted with metadata from the Kubernetes API cache.",
	)
	FileLogKubernetesAPIErrors = newCounter(
		"wisp_filelog_kubernetes_api_errors_total",
		"Failed Kubernetes API pod metadata refreshes.",
	)
	FileLogKubernetesAPIOwnerErrors = newCounter(
		"wisp_filelog_kubernetes_api_owner_errors_total",
		"Failed optional Kubernetes workload-owner lookups.",
	)
	FileLogKubernetesAPIUIDMismatches = newCounter(
		"wisp_filelog_kubernetes_api_uid_mismatches_total",
		"Kubernetes API pod responses rejected because UID did not match the log path.",
	)
	FileLogKubernetesAPIQueueDrops = newCounter(
		"wisp_filelog_kubernetes_api_queue_drops_total",
		"Kubernetes API refresh requests not scheduled because the bounded queue was full.",
	)
	FileLogKubernetesAPIEvictions = newCounter(
		"wisp_filelog_kubernetes_api_evictions_total",
		"Kubernetes API cache entries evicted at the configured pod bound.",
	)
	FileLogRedactionMatches = newCounter(
		"wisp_filelog_redaction_matches_total",
		"File log content regex matches replaced before durable admission, including retried reads.",
	)
	FileLogRedactionDropped = newCounter(
		"wisp_filelog_redaction_dropped_records_total",
		"File log records intentionally dropped because redaction expansion exceeded max_line_bytes.",
	)
	FileLogMultilineForcedFlushes = newCounter(
		"wisp_filelog_multiline_forced_flushes_total",
		"Multiline records completed by inactivity timeout or rotated-file drain.",
	)
	FileLogMultilineOversized = newCounter(
		"wisp_filelog_multiline_oversized_records_total",
		"Multiline records dropped after exceeding content, line-count, or read-span bounds.",
	)
	FileLogTimestampParsed = newCounter(
		"wisp_filelog_timestamp_parsed_total",
		"Text file log records whose configured event timestamp was parsed successfully, including retried reads.",
	)
	FileLogTimestampErrors = newCounter(
		"wisp_filelog_timestamp_errors_total",
		"Text file log timestamp captures that were absent, malformed, or outside the OTLP range, including retried reads.",
	)
	JournaldRecords = newCounter(
		"wisp_journald_records_total",
		"Journald records durably admitted.",
	)
	JournaldBatches = newCounter(
		"wisp_journald_batches_total",
		"Journald batches durably admitted.",
	)
	JournaldReadErrors = newCounter(
		"wisp_journald_read_errors_total",
		"Journald subprocess, permission, or export parsing failures.",
	)
	JournaldCheckpointErrors = newCounter(
		"wisp_journald_checkpoint_errors_total",
		"Atomic journald cursor checkpoint writes that failed.",
	)
	JournaldAdmissionErrors = newCounter(
		"wisp_journald_admission_errors_total",
		"Journald batches downstream delivery or spool admission did not durably accept.",
	)
	JournaldBackpressure = newCounter(
		"wisp_journald_backpressure_total",
		"Journald batches paused by logs spool pressure.",
	)
	JournaldOversizedMessages = newCounter(
		"wisp_journald_oversized_messages_total",
		"Journald MESSAGE fields omitted because they exceeded max_field_bytes, including retried reads.",
	)
	JournaldOversizedRecords = newCounter(
		"wisp_journald_oversized_records_total",
		"Journald records replaced by explicit markers because their encoded record exceeded max_batch_bytes, including retried reads.",
	)
	JournaldRedactionMatches = newCounter(
		"wisp_journald_redaction_matches_total",
		"Journald MESSAGE regex matches replaced before durable admission, including retries.",
	)
	JournaldRedactionDropped = newCounter(
		"wisp_journald_redaction_dropped_records_total",
		"Journald records intentionally dropped because redaction expansion exceeded max_field_bytes.",
	)
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
