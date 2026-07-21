# Changelog

All notable changes to Wisp are documented here. Wisp follows semantic
versioning without treating `v1.0.0` as a schedule target.

## Unreleased

No changes yet.

## v0.11.0 — 2026-07-18

### Added

- configurable read-only procfs, sysfs, rootfs, and cgroupfs roots for
  containerized host collection without a later configuration-shape migration;
- bounded Linux uptime, boot-time, PSI, and UTS metadata collectors;
- bounded exact Linux disk I/O counters across base, discard, and flush
  diskstats layouts;
- local filesystem capacity, availability, inode, read-only, and per-mount
  error gauges with escaped mountinfo parsing and deterministic overmount
  selection;
- explicitly scoped cgroup v2 CPU usage/throttling, quota, memory/swap,
  event, PID, and per-device I/O telemetry for the configured cgroupfs
  root, including explicit unlimited-limit gauges;
- privacy-safe aggregate IPv4/IPv6 socket occupancy and memory plus allowlisted
  TCP/UDP opens, resets, retransmits, errors, drops, and datagram counters for
  the visible network namespace;
- mount-aware fail-open host hostname, architecture, and OS resource detection
  that fills only missing attributes, with privacy-sensitive stable machine ID
  detection disabled unless explicitly enabled;
- parallel host collector execution with a configurable cycle deadline and
  one-in-flight supervision that prevents repeated workers behind a stuck
  kernel or filesystem syscall;
- per-collector duration/success gauges plus host collection, unsupported,
  failure, emitted-series, and pipeline-admission counters;
- deterministic procfs fixtures covering alternate mounts, malformed data,
  unsupported kernels, partial collector failure, and metric contracts.

### Changed

- host collector names, duplicates, intervals, and virtual-filesystem paths are
  validated at startup;
- existing procfs collectors use bounded reads and report malformed or empty
  kernel data while allowing healthy collectors and partial valid series to
  continue;
- the default host collector set now also includes uptime, PSI, and UTS
  metadata, disk I/O, and local filesystems; missing optional support is
  classified separately from collection errors and repeated state logs are
  suppressed; cgroup v2 is added without claiming that a container namespace
  root represents the entire host, and socket telemetry likewise labels the
  visible network namespace rather than assuming host networking;
- remote, automounted, and FUSE filesystem `statfs` calls are excluded until a
  stuck-mount supervisor can bound blocking syscalls without accumulating
  abandoned workers;
- host metrics gain missing standard host/OS resource attributes by default;
  explicit resource values remain authoritative and deployments can disable
  detection entirely;
- a timed-out host collector no longer stalls healthy collectors or shutdown;
  repeated cycles do not spawn duplicate work while its original syscall
  remains blocked;
- journald command failures retain bounded stderr diagnostics reliably instead
  of racing process cleanup against an asynchronous pipe reader.

## v0.10.0 — 2026-07-18

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
- bounded Linux file log tailing with device/inode identity, atomic versioned
  checkpoints, restart/rotation recovery, and explicit oversized-line policy.
- Kubernetes CRI log framing with event timestamps, stdout/stderr metadata,
  bounded `P…F` assembly, malformed-input preservation, and restart-safe
  oversized-sequence handling.
- opt-in Kubernetes resource enrichment from validated kubelet pod log paths,
  including namespace, pod, UID, container, and integer restart count without
  requiring Kubernetes API access.
- bounded ordered file-log content redaction before OTLP encoding or durable
  spool admission, covering text, assembled/partial CRI, and malformed CRI
  records without regex backtracking.
- bounded start-pattern multiline text framing with inactivity and rotation
  boundaries, redaction after assembly, restart-safe pending replay, and
  automatic recovery after oversized records.
- explicit bounded text timestamp capture for RFC3339 and Unix epoch units,
  parsed after framing and before redaction without dropping records on
  timestamp errors.
- bounded journald collection through binary-safe Journal Export Format with
  durable cursors, start boundaries, unit/identifier filters, syslog severity
  mapping, pre-spool redaction, explicit oversized-message markers, and
  readiness/self-observability coverage.
- optional fail-open Kubernetes API enrichment for CRI file logs with
  UID-verified bounded asynchronous caching, stale/failure policy, workload
  owner resolution, node/container image identity, label allowlists, projected
  token rotation, and explicit RBAC.
- bounded OTLP trace correlation validation with lossless report mode,
  atomic strict rejection, W3C tracestate checks, duplicate/cycle detection,
  and fixed-cardinality reason metrics.
- explicit OTLP trace resource enrichment with preserve, replace, and reject
  conflict policies that never inherit the agent's own resource identity.
- bounded complete-trace batching across resource and scope boundaries, exact
  oversized-trace partial success, and fixed-cardinality split telemetry.
- explicit stateless whole-trace `hash_seed` admission sampling with
  Collector-compatible deterministic decisions, invalid-ID fail-open
  behavior, and fixed-cardinality decision telemetry.

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
- OTLP/HTTP trace failures now return protobuf `google.rpc.Status` bodies
  alongside their protocol-defined HTTP status codes.
- trace request size is automatically constrained by its spool budget; legacy
  whole-request envelopes are compatibility-split with deterministic child
  IDs after an atomic oversized-trace preflight.
- sampled-out traces are acknowledged without OTLP partial success and never
  reach spool durability; sampling remains disabled when its config block is
  absent and does not rewrite trace flags or `tracestate`.
- file checkpoints advance only after downstream delivery or spool fsync, so
  admission failures retry without data loss and crashes have an explicit
  at-least-once duplicate boundary.
- filelog checkpoint v1 remains readable and is upgraded to v2 on write; v2
  records bounded CRI oversized-sequence continuation state.
- path-derived Kubernetes identity overrides conflicting global resource
  values for that file; enrichment misses preserve records and remain
  observable.
- redaction replacements are literal and bounded by `max_line_bytes`; records
  whose replacement expansion exceeds the bound are intentionally dropped
  without falling back to secret-bearing content.
- filelog checkpoint versions 1 and 2 remain readable and upgrade to version 3
  on write; v3 records multiline oversized-continuation state.
- journald cursor checkpoints advance only after delivery or spool fsync;
  crashes at the admission/checkpoint boundary may duplicate the final batch
  but do not silently skip it.

## v0.7.0 — 2026-07-17

### Added

- Gyre operational endpoints and generation-aware runtime reload;
- build-time version, commit, and date metadata;
- CI and release automation.

### Changed

- Gyre is consumed through the published `v0.5.0` module;
- spool failures now affect readiness/degraded state instead of liveness;
- unsupported live configuration changes are rejected and preserve the active
  generation;
- YAML parsing rejects unknown fields, multiple documents, and unsupported
  processors instead of silently ignoring operator mistakes;
- `golang.org/x/net`, `x/sys`, and `x/text` were updated to remove known
  vulnerable versions from the module graph.
