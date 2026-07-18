# OTLP Traces path

Status: durable passthrough implemented in `v0.8.x`; correlation validation,
explicit resource enrichment, and bounded complete-trace batching implemented
in `v0.10.x`.

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

The envelope disk format is unchanged and the new config field is additive.
Explicit optional sampling remains future work and must not silently change
the default lossless semantics.

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
- shared `wisp_spool_signal_*{signal="traces"}` gauges.
