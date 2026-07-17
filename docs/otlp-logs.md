# OTLP Logs path

Status: implemented in the `v0.8.x` development line.

Wisp accepts OTLP Logs on the same configured receiver listeners as metrics:

- gRPC `opentelemetry.proto.collector.logs.v1.LogsService/Export`;
- HTTP `POST /v1/logs` with `application/x-protobuf`.

The request is validated as protobuf, deterministically serialized into a
`logs` durability envelope, and routed directly to the OTLP Logs exporter.
There is no conversion into the metric model and metric processors do not run
on logs. The complete OTLP ResourceLogs payload is retained. A bounded common
string resource identity is duplicated into the envelope only when every
ResourceLogs entry agrees.

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

The current admission body limit is 16 MiB. Fine-grained request splitting is
the next v0.8 increment; until then a downstream with a smaller receive limit
may permanently reject a large request.

## Per-signal capacity

Optional `exporter.spool.signal_limits` caps noisy signals independently:

```yaml
exporter:
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
