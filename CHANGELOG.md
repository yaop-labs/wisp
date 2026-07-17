# Changelog

All notable changes to Wisp are documented here. Wisp follows semantic
versioning without treating `v1.0.0` as a schedule target.

## Unreleased

### Added

- Gyre operational endpoints and generation-aware runtime reload;
- build-time version, commit, and date metadata;
- CI and release automation;
- architecture decision for a signal-extensible core and future profiles.

### Changed

- Gyre is consumed through the published `v0.5.0` module;
- spool failures now affect readiness/degraded state instead of liveness;
- unsupported live configuration changes are rejected and preserve the active
  generation.

## v0.7.0

The release section will be cut from `Unreleased` only after the branch is
merged, all verification gates pass, and the release tag points at that commit.
