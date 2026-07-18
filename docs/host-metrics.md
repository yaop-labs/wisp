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
    collectors: [cpu, load, memory, network, socket, disk, filesystem, cgroup, uptime, pressure, uname]
    # For a containerized agent, point these at read-only host mounts.
    procfs_path: /host/proc
    sysfs_path: /host/sys
    rootfs_path: /host/root
    cgroupfs_path: /host/sys/fs/cgroup
```

An empty `collectors` list enables every collector. Collector names are
validated at startup; unknown and duplicate names are rejected. The interval
must be at least `100ms`. Filesystem roots must be clean absolute paths.

The default roots are `/proc`, `/sys`, `/`, and `/sys/fs/cgroup`.
`procfs_path` supplies kernel counters and mountinfo. `rootfs_path` supplies
the paths used for local filesystem `statfs` calls. `sysfs_path` and
`cgroupfs_path` is the exact cgroup v2 root observed by the cgroup collector.
`sysfs_path` remains an explicit compatibility surface for upcoming device
metadata, so deployments do not need a later configuration shape migration.

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
| `socket` | `node_socket_used`, `node_socket_inuse`, `node_socket_orphan`, `node_socket_time_wait`, `node_socket_allocated` | integer gauges; `family`, `protocol`, `network.scope=visible_namespace` |
| `socket` | `node_socket_memory_pages`, `node_socket_memory_bytes`, `node_socket_reassembly_memory_bytes` | integer gauges; pages or `bytes`; `family`, `protocol`, `network.scope` |
| `socket` | allowlisted `node_netstat_tcp_*` and `node_netstat_udp_*` | monotonic counters except current established; `network.scope=visible_namespace` |
| `disk` | `node_disk_reads_completed_total`, `node_disk_reads_merged_total`, `node_disk_writes_completed_total`, `node_disk_writes_merged_total` | monotonic sums; `device`, `major`, `minor` |
| `disk` | `node_disk_read_bytes_total`, `node_disk_written_bytes_total` | monotonic sums, `bytes`; `device`, `major`, `minor` |
| `disk` | `node_disk_read_milliseconds_total`, `node_disk_write_milliseconds_total`, `node_disk_io_milliseconds_total`, `node_disk_io_weighted_milliseconds_total` | monotonic sums, `ms`; `device`, `major`, `minor` |
| `disk` | `node_disk_io_now` | integer gauge; `device`, `major`, `minor` |
| `disk` | optional discard and flush metrics | kernels exposing those diskstats fields; exact `bytes`, `ms`, or operation counts |
| `filesystem` | `node_filesystem_size_bytes`, `node_filesystem_free_bytes`, `node_filesystem_avail_bytes` | integer gauges, `bytes`; `device`, `fstype`, `mountpoint` |
| `filesystem` | `node_filesystem_files`, `node_filesystem_files_free`, `node_filesystem_readonly`, `node_filesystem_device_error` | integer gauges; `device`, `fstype`, `mountpoint` |
| `cgroup` | `node_cgroup_v2_info` | constant gauge; `cgroup.scope=configured_root` |
| `cgroup` | `node_cgroup_cpu_*` | exact cumulative CPU usage/throttling counters and quota/period/weight gauges, `us` where applicable |
| `cgroup` | `node_cgroup_memory_*` | current/limit/swap byte gauges and event counters |
| `cgroup` | `node_cgroup_pids_*` | current and limit gauges |
| `cgroup` | `node_cgroup_io_*` | per-device byte and operation counters; `device`, `cgroup.scope` |
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

Linux diskstats sectors are converted using the kernel ABI's fixed 512-byte
sector unit, independent of a device's physical or logical block size. Wisp
supports the base, discard, and flush field layouts and ignores unknown future
trailing fields after validating the known prefix.

The filesystem collector reads PID 1 mountinfo first, then falls back to the
Wisp process mountinfo when PID 1 is hidden. Overmounts are deduplicated by
mountpoint, keeping the newest mount ID. Pseudo filesystems and remote,
automounted, and FUSE filesystems are intentionally excluded from `statfs`:
those calls can block indefinitely when their backing service is unavailable.
They will become opt-in only after the planned stuck-mount supervisor can
enforce time bounds without leaking a goroutine every interval. Local
`ext4`, `xfs`, `btrfs`, `overlay`, `tmpfs`, and other non-excluded filesystem
types are collected. A failed local mount emits
`node_filesystem_device_error=1` while healthy mounts remain available.

The cgroup collector never guesses whether a cgroup namespace represents the
whole machine. It observes exactly `cgroupfs_path` and labels every series
`cgroup.scope=configured_root`. On a host install the default cgroup2 root is
normally host-wide. Inside a container it is commonly a delegated container
root unless the operator supplies a read-only host cgroup2 mount. The collector
detects cgroup v2 through `cgroup.controllers`; cgroup v1 is reported as
unsupported. It exports exact CPU usage/throttling, CPU quota and period,
memory/swap current and limit, memory events, PID current and limit,
and per-device I/O counters. Unlimited `max` values use explicit
`*_unlimited=1` gauges instead of fabricated numeric limits.

Wisp intentionally does not enumerate descendant workload cgroups yet. Doing
that safely requires a cardinality budget, cgroup lifecycle handling, and
container/workload resource attribution so a filesystem path is not exposed as
an accidental identity.

The socket collector reads aggregate `/proc/net/sockstat`, optional
`sockstat6`, and an explicit TCP/UDP allowlist from `/proc/net/snmp`. Every
series is marked `network.scope=visible_namespace`: inside a container this is
the container's network namespace unless Wisp runs with host networking.
Binding a host procfs path alone does not imply host network-namespace
visibility because Linux exposes `/proc/net` through the reader's namespace.
Socket memory reported in pages is also converted with the runtime kernel page
size; reassembly `memory` values are already bytes. No individual connection,
address, or port is read or exported, keeping both privacy exposure and metric
cardinality fixed.

Every emitted series receives the configured agent resource attributes.
Future host/container/workload resource detection will be additive and will
have an explicit conflict policy; it is not inferred silently today.

## Failure and compatibility behavior

- Kernel virtual-file reads are size-bounded. Missing mandatory files,
  malformed values, and oversized virtual files fail only their collector.
- Diskstats input is bounded to 4,096 devices. Mountinfo input is bounded to
  8,192 records and at most 4,096 eligible local mounts are probed.
- Missing PSI files are classified as unsupported rather than an operational
  error. This allows Wisp to run on kernels without PSI.
- Partially readable collectors emit valid series and report the attempt as
  failed, so data remains available without hiding corruption.
- Host metrics use the existing at-most-one in-memory collection cycle and
  the shared metrics export/spool durability path. Restarting Wisp does not
  synthesize missed host samples.
- Existing configurations remain compatible. Omitting all new fields retains
  the prior paths and interval behavior; the default collector set gains
  `disk`, `filesystem`, `cgroup`, `socket`, `uptime`, `pressure`, and `uname`.

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
