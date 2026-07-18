# Linux host metrics

Wisp reads Linux kernel virtual files directly and emits cumulative host
telemetry through the normal metrics pipeline. Host collection is independent
per collector: one unavailable or malformed kernel interface does not suppress
healthy metrics from the same cycle.

## Configuration

```yaml
sources:
  host:
    interval: 15s
    collectors: [cpu, load, memory, network, uptime, pressure, uname]
    # For a containerized agent, point these at read-only host mounts.
    procfs_path: /host/proc
    sysfs_path: /host/sys
    rootfs_path: /host/root
    cgroupfs_path: /host/sys/fs/cgroup
```

An empty `collectors` list enables every collector. Collector names are
validated at startup; unknown and duplicate names are rejected. The interval
must be at least `100ms`. Filesystem roots must be clean absolute paths.

The default roots are `/proc`, `/sys`, `/`, and `/sys/fs/cgroup`. Only
`procfs_path` is consumed by the collectors currently implemented. The other
roots are an explicit compatibility surface for the upcoming filesystem,
disk, and cgroup increments, so deployments do not need a later configuration
shape migration.

Mount alternate roots read-only. Wisp does not write to procfs, sysfs, the
host root, or cgroupfs. A typical container needs host PID visibility and
read-only bind mounts; the exact runtime flags remain an operator decision.
`uname` describes the UTS namespace visible to the Wisp process, which may
differ from the host UTS namespace if the container is isolated.

## Metric contract

| Collector | Metrics | Attributes and units |
| --- | --- | --- |
| `load` | `node_load1`, `node_load5`, `node_load15` | gauges |
| `memory` | selected `node_memory_*_bytes` | gauges, `bytes` |
| `cpu` | `node_cpu_milliseconds_total` | monotonic sum, `ms`; `cpu`, `mode` |
| `network` | `node_network_receive_bytes_total`, `node_network_transmit_bytes_total` | monotonic sums, `bytes`; `device` |
| `uptime` | `node_uptime_seconds`, `node_boot_time_seconds` | gauges, `s` |
| `pressure` | `node_pressure_<resource>_<scope>_microseconds_total` | monotonic sum, `us` |
| `pressure` | `node_pressure_<resource>_<scope>_ratio` | gauge, unit `1`; `window=10s|60s|300s` |
| `uname` | `node_uname_info` | constant gauge; bounded `sysname`, `nodename`, `release`, `version`, `machine`, `domainname` |

PSI resources are `cpu`, `memory`, and `io`. Kernel `some` pressure maps to
the `waiting` metric scope and `full` pressure maps to `stalled`. PSI average
percentages are exported as ratios from `0` through `1`. CPU PSI legitimately
has no `full` line on kernels that expose only `some`.

Integer kernel counters use integer OTLP points to preserve exact values.
This is why CPU and PSI totals use milliseconds and microseconds instead of
floating-point seconds. Queries must account for those units when calculating
rates.

Every emitted series receives the configured agent resource attributes.
Future host/container/workload resource detection will be additive and will
have an explicit conflict policy; it is not inferred silently today.

## Failure and compatibility behavior

- Kernel virtual-file reads are size-bounded. Missing mandatory files,
  malformed values, and oversized virtual files fail only their collector.
- Missing PSI files are classified as unsupported rather than an operational
  error. This allows Wisp to run on kernels without PSI.
- Partially readable collectors emit valid series and report the attempt as
  failed, so data remains available without hiding corruption.
- Host metrics use the existing at-most-one in-memory collection cycle and
  the shared metrics export/spool durability path. Restarting Wisp does not
  synthesize missed host samples.
- Existing configurations remain compatible. Omitting all new fields retains
  the prior paths and interval behavior; the default collector set gains
  `uptime`, `pressure`, and `uname`.

Wisp exposes the following fixed-cardinality self-observability:

- `wisp_host_collector_duration_seconds{collector}`;
- `wisp_host_collector_success{collector}`;
- `wisp_host_collector_errors_total`;
- `wisp_host_collector_unsupported_total`;
- `wisp_host_collections_total`;
- `wisp_host_series_emitted_total`;
- `wisp_host_emit_errors_total`.

Collector failure logs are transition-aware: the first failure or unsupported
state is logged, repeated cycles do not create log storms, and recovery is
logged once.

