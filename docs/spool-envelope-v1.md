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
