# OTLP Traces path

Status: durable passthrough implemented in `v0.8.x`; correlation validation
and explicit resource enrichment implemented in `v0.10.x`.

Wisp accepts OTLP Traces on the same configured receiver listeners as metrics
and logs:

- gRPC `opentelemetry.proto.collector.trace.v1.TraceService/Export`;
- HTTP `POST /v1/traces` with `application/x-protobuf`.

Every non-empty request is deterministically serialized into one `traces`
durability envelope. Wisp does not convert spans into its metric model, run
metric processors on them, or sample them. Validation in the default `report`
mode does not rewrite resource, scope, span, event, link, status, timing, or
protobuf unknown fields. Explicit resource enrichment is the only mutation in
this increment.

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

- A successful receiver response means the complete request was exported or
  fsync'd to the shared spool.
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

The whole request is the durability and retry unit. If downstream accepts the
request but Wisp loses the response, or Wisp accepts it durably but the
upstream client loses Wisp's response, the same envelope or upstream request
can be delivered again. Coral may use the stable envelope ID as a bounded,
tenant-aware deduplication key. It is delivery metadata, not authentication.

Wisp treats an OTLP partial-success response as protocol success because
retrying the whole request would duplicate accepted spans. Rejected spans
increment `wisp_otlp_trace_spans_rejected_total` and a bounded warning records
the downstream message.

## Bounds and future trace processing

The receiver bounds protobuf bodies at 16 MiB. In `v0.8.x`, one incoming trace
request remains one envelope: Wisp intentionally does not split a trace across
an arbitrary span boundary because that can separate parents, children, links,
and trace-level processing state.

Operators using a traces-specific spool cap should make it larger than the
largest request they expect to survive during an outage, including envelope
metadata. If one envelope cannot fit the configured global or traces cap,
Wisp does not acknowledge it as durable.

Trace-aware batching, oversized-trace handling, and explicit optional sampling
remain in this milestone. They must preserve the current default of lossless
admission and must not silently change trace semantics.

Self-observability includes:

- `wisp_otlp_trace_spans_received_total`;
- `wisp_otlp_trace_requests_received_total`;
- `wisp_otlp_trace_requests_exported_total`;
- `wisp_otlp_trace_spans_rejected_total`;
- `wisp_otlp_trace_validation_requests_total`;
- `wisp_otlp_trace_validation_failures_total`;
- fixed correlation reason counters under
  `wisp_otlp_trace_invalid_*`, plus duplicate and parent-cycle counters;
- `wisp_otlp_trace_resource_enriched_spans_total`;
- `wisp_otlp_trace_resource_conflicts_total`;
- shared `wisp_spool_signal_*{signal="traces"}` gauges.
