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
  self-observability — implemented;
- lossless OTLP Logs and Traces receiver/exporter registration — implemented;
- bounded OTLP Logs splitting, stable delivery identity, and
  permanent/transient response semantics — implemented.

The design must satisfy ADR 0001 so a future `profiles` kind does not require a
second pipeline rewrite.

## v0.9.x — log collection

- OTLP logs — implemented;
- bounded newline-delimited file tailing — implemented;
- durable Linux file identity and atomic checkpoints across
  rotate/truncate/restart — implemented;
- Kubernetes CRI framing, timestamps, streams, and bounded partial assembly —
  implemented;
- API-free Kubernetes pod/container resource enrichment from kubelet log paths
  — implemented;
- bounded ordered content redaction before OTLP/spool durability — implemented;
- bounded start-pattern multiline framing with timeout/rotation boundaries and
  restart-safe oversized continuation state — implemented;
- explicit bounded non-CRI timestamp extraction for RFC3339 and Unix units —
  implemented;
- journald collection;
- optional API-backed Kubernetes workload, node, label, and image enrichment;
- documented at-least-once behavior and duplicate boundary.

## v0.10.x — trace processing depth

- correlation validation and explicit resource enrichment;
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
