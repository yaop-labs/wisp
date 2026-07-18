# OTLP Logs path

Status: implemented in the `v0.8.x` development line.

Wisp accepts OTLP Logs on the same configured receiver listeners as metrics:

- gRPC `opentelemetry.proto.collector.logs.v1.LogsService/Export`;
- HTTP `POST /v1/logs` with `application/x-protobuf`.

The request is validated as protobuf, deterministically serialized into a
`logs` durability envelope, and routed directly to the OTLP Logs exporter.
There is no conversion into the metric model and metric processors do not run
on logs. Every log record and its associated resource/scope metadata is
retained. A bounded common string resource identity is duplicated into the
envelope only when every ResourceLogs entry agrees.

## Delivery and errors

- A successful receiver response means the request was exported or durably
  fsync'd to the shared spool.
- Global or logs-specific pressure returns gRPC `RESOURCE_EXHAUSTED` or HTTP
  `429`, so an OTLP SDK can retry without Wisp admitting more data.
- Transient downstream failures are retried with the configured exporter
  backoff and then spooled.
- Invalid envelopes and unambiguously permanent downstream failures are not
  written to disk.
- A downstream OTLP partial-success response is treated as protocol success:
  retrying the complete request would duplicate the records already accepted.
  Rejected records increment `wisp_otlp_logs_rejected_total` and produce a
  bounded warning.

The receiver admits bodies up to 16 MiB, then splits them in resource/scope/log
order before durability admission. Each protobuf request defaults to at most
3 MiB (`exporter.otlp.max_log_request_bytes`) so it fits common 4 MiB gRPC
receiver limits. Wisp automatically lowers that value when necessary to fit the
global or logs-specific spool cap, reserving space for envelope metadata.

Each chunk:

- preserves ResourceLogs and ScopeLogs metadata plus log-record order;
- receives an independent durable envelope ID before entering the spool;
- is retried, drained, and removed independently;
- is sent with `x-wisp-envelope-id` and `x-wisp-signal-kind` metadata over both
  gRPC and HTTP.

Therefore a downstream outage after one chunk succeeds does not retain or
replay that successful chunk: only failed chunks remain on disk. A durability
failure during admission can still make an upstream SDK retry the original
request, so the accepted prefix is the documented at-least-once duplicate
boundary.

For `.envelope` records created before receiver-side splitting, the exporter
performs a compatibility split. If a later compatibility chunk fails, earlier
chunks can be retried; their delivery IDs are deterministically derived from
the durable envelope ID and chunk index so Coral can deduplicate them. A single
log record plus its resource/scope metadata larger than the configured limit is
rejected permanently because its semantics cannot be split safely.

Splitting is observable through:

- `wisp_otlp_logs_chunks_total`;
- `wisp_otlp_logs_chunks_exported_total`;
- `wisp_otlp_logs_split_requests_total`;
- `wisp_otlp_logs_compat_split_attempts_total`.

## Per-signal capacity

Optional `exporter.spool.signal_limits` caps noisy signals independently:

```yaml
exporter:
  otlp:
    max_log_request_bytes: 3145728
  spool:
    dir: /var/lib/wisp/spool
    max_bytes: 536870912
    signal_limits:
      metrics:
        max_bytes: 268435456
      logs:
        max_bytes: 268435456
        high_watermark: 214748364
        low_watermark: 134217728
```

Omitted signal watermarks default to 80%/50% of that signal's cap. The global
spool cap and pressure band still apply.
