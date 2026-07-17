# ADR 0001: Signal-extensible core

- Status: accepted
- Date: 2026-07-17

## Context

Wisp currently moves metric-specific `model.Batch` values. The platform plan
adds OTLP logs and traces, and may add continuous profiles later. Encoding a
closed assumption that telemetry always means exactly metrics, logs, or traces
would force another pipeline and spool migration when profiles arrive.

Profiles also differ operationally: they are larger and burstier, need build
and executable identity for symbolization, and require independent quotas.
They must not share metric processors or starve higher-priority telemetry.

## Decision

The multi-signal work will introduce a versioned envelope with:

- an open string signal kind;
- envelope and payload schema versions;
- encoding and content type;
- capture time and stable batch identity;
- resource identity;
- opaque payload bytes and checksum.

Sources emit envelopes instead of depending on the metric model. Processors
declare which signal kinds they support. The spool persists envelopes without
interpreting their payload and maintains independent quotas, pressure, and
observability per signal kind.

Known initial kinds are `metrics`, `logs`, and `traces`. `profiles` is a
reserved architectural capability, not an enabled source or accepted endpoint.
An unknown kind must never be decoded as another signal or forwarded to an
exporter that has not advertised support.

Resource identity will preserve at least service, service instance, host,
process, cgroup/container, workload, executable, and build identity when
available. This permits future correlation and symbolization without changing
the durability envelope.

## Consequences

- Adding profiles will require a source, processors, and transport adapter, but
  not a new pipeline or disk queue.
- Metrics keep their typed internal model behind a metric-specific adapter.
- Per-signal limits prevent logs or profiles from exhausting the entire spool.
- The first envelope migration must define compatibility with existing
  metric-only spool files and include crash/restart tests.
- No profiling config, BPF sampler, or symbolizer is implemented until its own
  design and release milestone are accepted.
