# Spool envelope v1

Status: implemented foundation in the `v0.8.x` development line.

## Record layout

All integer fields are unsigned big-endian:

```text
WISPENV1                  8-byte magic
header length             uint32
payload length            uint64
header                    UTF-8 JSON
payload                   opaque bytes
checksum                  SHA-256 of every preceding byte
```

The header contains:

- envelope version;
- random 128-bit lowercase hexadecimal batch ID;
- open signal kind;
- payload schema and encoding;
- capture time in Unix nanoseconds;
- optional common resource identity.

The default payload admission limit is 256 MiB and the header limit is 1 MiB.
Decoders verify lengths before allocating or decoding metadata, reject trailing
bytes, verify the checksum, reject unknown header fields, and validate identity
limits. Signal-specific adapters must additionally verify kind, schema, and
encoding before interpreting the opaque payload.

`profiles` is a valid architectural signal kind but no receiver/exporter claims
that capability yet.

## Metric migration

The first adapter wraps the existing metric `model.Batch` gob payload in a
checksummed `metrics` envelope:

```text
kind:      metrics
schema:    wisp.metric-batch.gob/v1
encoding:  application/x-gob
```

New writes use `.envelope`. Existing `.batch` files remain readable and are
drained in timestamp order without being rewritten in place. This makes
upgrade recovery one-way and crash-safe:

1. an old process may leave legacy `.batch` entries;
2. a new process counts both formats toward limits and pressure;
3. the new process decodes and forwards legacy entries normally;
4. all newly admitted batches use v1 envelopes;
5. after successful drain only the new format remains.

Unsupported signal kinds or payload schemas are never decoded as metrics.
Corrupt/checksum-invalid records follow the existing corrupt-spool path and
cannot wedge newer entries.

OTLP Logs use a protobuf-native adapter with no intermediate Wisp log model:

```text
kind:      logs
schema:    opentelemetry.proto.collector.logs.v1.ExportLogsServiceRequest/v1
encoding:  application/x-protobuf
```

This preserves OTLP fields and protobuf unknown fields across admission,
restart, and export. Metric-only relabel/reset/cardinality processors never see
or mutate log records.

## Signal-neutral queue

The durability core accepts validated envelopes through a signal-neutral
sender interface. The existing metric `pipeline.Exporter` is now an adapter:
it owns gob conversion, while the queue never interprets a current-format
payload.

New filenames include the signal kind for O(1) classification during steady
state. Records written by the first v1 implementation did not include that
suffix; they are classified from their checksummed header on startup and remain
fully drainable.

The queue maintains global depth plus independent depth, optional byte limits,
and pressure hysteresis for each signal. Capacity eviction is oldest-first.
Drain is FIFO within each signal and round-robin across signals. A transient
failure blocks only that signal for the current pass, so a metrics outage cannot
strand logs (or the reverse). A permanent rejection is not admitted on the
live path and is quarantined if discovered while draining an older record.

Current self-observability retains the original aggregate gauges and adds:

- `wisp_spool_signal_bytes{signal=...}`;
- `wisp_spool_signal_envelopes{signal=...}`;
- `wisp_spool_signal_pressure_active{signal=...}`.

## Resource identity

The envelope duplicates only a bounded allowlist of correlation and future
symbolization identity (service, host, process, executable/build, container,
and Kubernetes workload). The full resource remains in the payload.

Identity is omitted for mixed-resource batches, duplicate keys, invalid UTF-8,
control characters, or oversized values. Optional metadata must never make an
otherwise valid telemetry batch non-durable.

## Next migration

Gob remains an adapter payload only during the metric pipeline transition.
Later milestones replace it with signal-native protobuf without changing the
outer record layout or legacy-read guarantee.
