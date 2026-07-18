# OTLP Traces path

Status: durable passthrough implemented in `v0.8.x`; correlation validation,
explicit resource enrichment, bounded complete-trace batching, and opt-in
whole-trace admission sampling implemented in `v0.10.x`.

Wisp accepts OTLP Traces on the same configured receiver listeners as metrics
and logs:

- gRPC `opentelemetry.proto.collector.trace.v1.TraceService/Export`;
- HTTP `POST /v1/traces` with `application/x-protobuf`.

Every non-empty request is validated and grouped into bounded durability
envelopes containing complete traces. Wisp does not convert spans into its
metric model, run metric processors on them, or sample them. Validation in the
default `report` mode does not rewrite resource, scope, span, event, link,
status, timing, or protobuf unknown fields. Explicit resource enrichment is
the only payload mutation in this milestone.

A bounded common string resource identity is duplicated into envelope metadata
only when every ResourceSpans entry agrees; the complete OTLP resource remains
in the payload.

## Correlation validation

Validation mode is configured under `sources.otlp.traces.validation`:

- `report` (default) checks each non-empty request, records fixed-cardinality
  reason counters, and durably forwards the original request;
- `reject` performs the same checks and atomically rejects the complete request
  as permanent bad data when any check fails;
- `off` preserves the earlier no-validation path.

Validation checks:

- trace IDs are exactly 16 bytes and non-zero, following the
  [OpenTelemetry SpanContext contract](https://opentelemetry.io/docs/specs/otel/trace/api/#spancontext);
- span IDs and non-empty parent span IDs are exactly 8 bytes and non-zero;
- link trace/span IDs are valid;
- span and link tracestate follows
  [W3C Trace Context](https://www.w3.org/TR/trace-context/#tracestate-header)
  syntax, including unique keys and the 32-member bound;
- the span name and both timestamps are present, and end is not before start;
- a `(trace_id, span_id)` pair is unique within the request;
- parent relationships visible in the same request do not form a cycle.

An unresolved parent is valid: upstream sampling, batching, and distributed
delivery routinely make a parent unavailable in the current request. Wisp
does not keep an unbounded cross-request trace index.

Strict mode rejects the whole request instead of deleting individual spans.
This preserves an explicit atomic admission boundary and avoids acknowledging
a partially rewritten trace. gRPC returns `INVALID_ARGUMENT`; HTTP returns
`400` with a protobuf `google.rpc.Status` body. Report mode is the compatibility
default and never turns validation findings into backpressure or retries.
These responses follow the
[OTLP partial-success and failure contract](https://opentelemetry.io/docs/specs/otlp/#partial-success).

## Explicit resource enrichment

Trace resource enrichment is configured independently from Wisp's own
`resource.attributes`. Agent identity is never copied into application traces:

```yaml
sources:
  otlp:
    grpc: "0.0.0.0:4317"
    traces:
      validation: report
      resource:
        conflict: preserve
        attributes:
          deployment.environment.name: production
          service.namespace: shop
```

At most 32 configured string attributes are allowed. Keys are bounded to 256
bytes and values to 4096 bytes; both must be printable valid UTF-8. Attributes
are applied only to ResourceSpans that contain spans:

- `preserve` (default) adds missing keys and keeps every existing value;
- `replace` removes all existing occurrences of a configured key and inserts
  the configured string value;
- `reject` adds missing keys, but atomically rejects the request if an existing
  occurrence is not the same string value.

Enrichment clones the request before mutation, preserves protobuf unknown
fields and ordering outside the configured keys, and recomputes the bounded
envelope resource identity from the enriched payload.

## Delivery and duplicate boundary

- A successful receiver response without partial success means every trace in
  the request was exported or fsync'd to the shared spool.
- A successful partial-success response means every accepted trace was
  exported or fsync'd and the reported oversized spans were not accepted.
- Global or traces-specific pressure returns gRPC `RESOURCE_EXHAUSTED` or HTTP
  `429` before admission.
- OTLP/HTTP errors use protobuf `google.rpc.Status` response bodies; bad trace
  data is non-retryable while `429`, `502`, `503`, and `504` remain the OTLP
  retryable status family.
- Transient downstream failures are retried with the configured exporter
  backoff and then spooled.
- Invalid durable envelopes and unambiguously permanent downstream responses
  are rejected instead of occupying the queue.
- `x-wisp-envelope-id` and `x-wisp-signal-kind: traces` accompany every
  downstream gRPC or HTTP delivery.

Each bounded chunk is an independent durability and retry unit with its own
stable envelope ID. If downstream accepts a chunk but Wisp loses the response,
or Wisp accepts chunks durably but the upstream client loses Wisp's response,
the same chunk or upstream request can be delivered again. A failure while
admitting a later chunk causes the request to fail; a client retry can
therefore duplicate earlier chunks that were already made durable. Coral may
use the stable envelope ID as a bounded, tenant-aware deduplication key. It is
delivery metadata, not authentication.

Wisp treats an OTLP partial-success response as protocol success because
retrying the whole request would duplicate accepted spans. Rejected spans
increment `wisp_otlp_trace_spans_rejected_total` and a bounded warning records
the downstream message.

## Bounded complete-trace batching

The receiver bounds protobuf bodies at 16 MiB. The chunk target defaults to
3 MiB and is configured as
`exporter.otlp.max_trace_request_bytes`; Wisp automatically narrows it when the
global or traces-specific spool budget cannot safely fit that envelope plus
durability metadata. The configured value must be between 64 KiB and 16 MiB:

```yaml
exporter:
  otlp:
    max_trace_request_bytes: 3145728
```

Wisp groups all spans with the same valid trace ID across ResourceSpans and
ScopeSpans boundaries. Traces retain first-seen order, spans retain their
original order and metadata, and one trace is never split. Invalid trace IDs
are separate indivisible units in validation `report` mode so compatibility
remains lossless. Request-level protobuf unknown fields are retained on exactly
one chunk; if they cannot fit alongside any accepted trace, the request is
atomically rejected before any chunk is emitted.

An indivisible trace larger than the chunk target is excluded while smaller
traces continue. The receiver returns OTLP partial success with the exact
rejected span count, including when every trace is oversized. Per the OTLP
contract, partial success is not retryable; operators must increase the bound
or reduce trace size to accept such traces.

Old whole-request v1 spool envelopes remain readable. The exporter
compatibility-splits them using deterministic child delivery IDs. It first
preflights the complete legacy payload: an indivisible oversized trace or
unplaceable request metadata rejects/quarantines the envelope before any chunk
is sent, preventing a partially exported legacy record.

## Optional whole-trace admission sampling

Sampling is disabled when the `sampling` block is absent. Enabling it requires
an explicit mode and percentage:

```yaml
sources:
  otlp:
    traces:
      sampling:
        mode: hash_seed
        sampling_percentage: 10
        hash_seed: 42
```

`sampling_percentage` is a float from 0 through 100. Zero intentionally drops
every valid trace; 100 keeps every valid trace. Non-zero values below the
14-bit `hash_seed` resolution are rejected instead of silently behaving as
zero. All Wisp replicas in one sampling tier should use the same seed.

The decision function matches the
[OpenTelemetry Collector `hash_seed` selection](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/probabilisticsamplerprocessor/README.md#hash-seed):
FNV-1a hashes the little-endian 32-bit seed followed by the 16-byte trace ID,
and its low 14 bits are compared with the configured percentage threshold.
The decision is deterministic and nested: with the same seed, every trace
selected at a lower percentage is also selected at a higher percentage. All
spans for one valid trace ID receive one decision across requests, resources,
scopes, restarts, and replicas.
The seed is an operational consistency value, not a secret or a security
boundary; `hash_seed` is not intended to resist adversarially chosen trace IDs.

Sampling runs after correlation validation and explicit enrichment but before
size admission and spool durability. A sampled-out trace is intentionally
acknowledged as protocol success, is not reported as OTLP partial success, and
never reaches disk or the exporter. Invalid trace IDs cannot receive a stable
whole-trace decision, so validation `report` preserves them without sampling;
use validation `reject` to atomically refuse them.

This is a stateless edge admission gate, not SDK sampling or tail sampling.
Wisp does not inspect `sampling.priority`, change trace flags, or rewrite
`tracestate` threshold/randomness fields. Consequently, it does not advertise
an adjusted count for trace-derived statistical aggregation. Use
[SDK sampling](https://opentelemetry.io/docs/specs/otel/trace/sdk/#sampling) or
an OpenTelemetry proportional/equalizing sampler when propagated sampling
probability is required. Attribute, latency, or error-aware
[tail sampling](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/tailsamplingprocessor/README.md)
requires sticky trace routing, bounded decision state, late-span policy, and a
separate durability design; it is not simulated here.

The config additions are optional and the envelope disk format is unchanged.
The default path remains lossless.

Self-observability includes:

- `wisp_otlp_trace_spans_received_total`;
- `wisp_otlp_trace_requests_received_total`;
- `wisp_otlp_trace_chunks_total`;
- `wisp_otlp_trace_split_requests_total`;
- `wisp_otlp_trace_oversized_traces_total`;
- `wisp_otlp_trace_oversized_spans_total`;
- `wisp_otlp_trace_compat_split_attempts_total`;
- `wisp_otlp_trace_chunks_exported_total`;
- `wisp_otlp_trace_requests_exported_total`;
- `wisp_otlp_trace_spans_rejected_total`;
- `wisp_otlp_trace_validation_requests_total`;
- `wisp_otlp_trace_validation_failures_total`;
- fixed correlation reason counters under
  `wisp_otlp_trace_invalid_*`, plus duplicate and parent-cycle counters;
- `wisp_otlp_trace_resource_enriched_spans_total`;
- `wisp_otlp_trace_resource_conflicts_total`;
- `wisp_otlp_trace_sampling_requests_total`;
- `wisp_otlp_trace_sampling_kept_traces_total`;
- `wisp_otlp_trace_sampling_kept_spans_total`;
- `wisp_otlp_trace_sampling_dropped_traces_total`;
- `wisp_otlp_trace_sampling_dropped_spans_total`;
- `wisp_otlp_trace_sampling_invalid_units_bypassed_total`;
- shared `wisp_spool_signal_*{signal="traces"}` gauges.
