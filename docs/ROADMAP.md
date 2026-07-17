# Wisp roadmap

Version numbers describe completed capability increments. They are not a
countdown to `v1.0.0`, and any milestone may be split into additional minor or
patch releases when that improves reviewability or operational safety.

## v0.7.x — operational baseline

- publish and consume versioned Reef/Gyre dependencies;
- run the production binary through the Gyre lifecycle;
- expose liveness, readiness, status, and config generation;
- reject unsupported live changes while preserving last-known-good config;
- embed release metadata;
- establish CI, changelog, and reproducible release artifacts.

## v0.8.x — durable multi-signal core

- versioned, checksummed, signal-neutral envelope — implemented;
- disk-format migration from metric-only spool records — implemented;
- signal-neutral queue, per-signal quotas, pressure, fair scheduling, and
  self-observability — implemented in the core; config exposure follows with
  the first additional signal;
- OTLP metrics, logs, and traces receiver/exporter registration;
- payload splitting and permanent/transient response semantics.

The design must satisfy ADR 0001 so a future `profiles` kind does not require a
second pipeline rewrite.

## v0.9.x — log collection

- OTLP logs, journald, file tailing, and Kubernetes CRI logs;
- durable file identity and checkpoints across rotate/truncate/restart;
- multiline parsing, timestamps, size bounds, redaction, and enrichment;
- documented at-least-once behavior and duplicate boundary.

## v0.10.x — trace path

- lossless OTLP trace passthrough and correlation attributes;
- oversized-trace handling and fair batching;
- explicit optional sampling, with no hidden semantic rewriting.

## v0.11.x — Linux host depth

- disk/filesystem, cgroup v2, PSI, socket, uptime, and kernel metadata;
- host/container/workload resource detection;
- collector-specific time bounds and self-observability.

## v0.12+ — eBPF and later profiles

- L4 network telemetry and workload attribution first;
- HTTP/gRPC RED telemetry where protocol and TLS visibility are reliable;
- SQL only after a separate feasibility and privacy review;
- continuous profiling as an independent future source with separate BPF
  programs, quotas, privacy controls, and symbolization architecture.

Every milestone requires race-clean tests, lint, recovery/failure-injection
coverage proportional to risk, updated documentation, and an explicit
compatibility statement for config and disk formats.
