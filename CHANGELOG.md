# Changelog

All notable changes to Wisp are documented here. Wisp follows semantic
versioning without treating `v1.0.0` as a schedule target.

## Unreleased

### Added

- versioned, checksummed, signal-neutral durability envelope with bounded
  decoding and open signal kinds;
- documented compatibility path for legacy metric `.batch` spool files.

### Changed

- new metric spool writes use `.envelope` records while existing `.batch`
  records remain readable and drain normally.

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
