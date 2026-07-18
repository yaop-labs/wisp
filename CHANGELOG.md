# Changelog

All notable changes to Wisp are documented here. Wisp follows semantic
versioning without treating `v1.0.0` as a schedule target.

## Unreleased

### Added

- versioned, checksummed, signal-neutral durability envelope with bounded
  decoding and open signal kinds;
- documented compatibility path for legacy metric `.batch` spool files;
- signal-neutral durability queue with per-signal depth, optional byte limits,
  pressure hysteresis, fair drain, and labelled self-observability gauges;
- lossless OTLP Logs receive/export over gRPC and HTTP/protobuf;
- configurable per-signal spool limits and logs receive/rejection counters;
- bounded OTLP Logs splitting with independent durable chunks and stable
  downstream delivery IDs.
- lossless OTLP Traces receive/export over gRPC and HTTP/protobuf with durable
  whole-request envelopes, stable delivery IDs, and partial-success counters.

### Changed

- new metric spool writes use `.envelope` records while existing `.batch`
  records remain readable and drain normally;
- the metric pipeline now uses a compatibility adapter over the generic queue;
- transient drain failures block only their signal, while permanent live
  rejections return immediately instead of consuming spool capacity;
- OTLP Logs bypass metric-only processors and share the same durability queue;
- log request size is automatically constrained by its spool budget; legacy
  oversized log envelopes use compatibility splitting on export.
- OTLP Traces bypass metric-only processors and use the shared signal-neutral
  queue with independent pressure and capacity controls.

## v0.7.0 — 2026-07-17

### Added

- Gyre operational endpoints and generation-aware runtime reload;
- build-time version, commit, and date metadata;
- CI and release automation;
- architecture decision for a signal-extensible core and future profiles.

### Changed

- Gyre is consumed through the published `v0.5.0` module;
- spool failures now affect readiness/degraded state instead of liveness;
- unsupported live configuration changes are rejected and preserve the active
  generation;
- YAML parsing rejects unknown fields, multiple documents, and unsupported
  processors instead of silently ignoring operator mistakes;
- `golang.org/x/net`, `x/sys`, and `x/text` were updated to remove known
  vulnerable versions from the module graph.
