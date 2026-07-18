# OTLP Traces path

Status: implemented in the `v0.8.x` development line.

Wisp accepts OTLP Traces on the same configured receiver listeners as metrics
and logs:

- gRPC `opentelemetry.proto.collector.trace.v1.TraceService/Export`;
- HTTP `POST /v1/traces` with `application/x-protobuf`.

Every non-empty request is deterministically serialized into one `traces`
durability envelope. Wisp does not convert spans into its metric model, run
metric processors on them, sample them, or rewrite their resource, scope,
event, link, status, or timing fields. A bounded common string resource
identity is duplicated into envelope metadata only when every ResourceSpans
entry agrees; the complete OTLP resource remains in the payload.

## Delivery and duplicate boundary

- A successful receiver response means the complete request was exported or
  fsync'd to the shared spool.
- Global or traces-specific pressure returns gRPC `RESOURCE_EXHAUSTED` or HTTP
  `429` before admission.
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

Trace-aware batching, oversized-trace handling, correlation policy, and
explicit optional sampling belong to the later trace-processing milestone.
They must preserve the current default of lossless passthrough and must not
silently change trace semantics.

Self-observability includes:

- `wisp_otlp_trace_spans_received_total`;
- `wisp_otlp_trace_requests_received_total`;
- `wisp_otlp_trace_requests_exported_total`;
- `wisp_otlp_trace_spans_rejected_total`;
- shared `wisp_spool_signal_*{signal="traces"}` gauges.
