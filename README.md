# Wisp

Wisp is the edge observability agent for the YAOP stack. It collects and
processes telemetry close to its source, persists batches across downstream
outages, and exports them to Coral over OTLP.

The current implementation has a typed metrics path plus durable OTLP Logs and
Traces paths:

- Prometheus/OpenMetrics scraping with static, file, DNS, and Kubernetes
  discovery;
- OTLP metrics, logs, and traces receive/export over gRPC and HTTP/protobuf;
- bounded OTLP trace correlation validation with lossless report mode, explicit
  strict rejection, conflict-controlled resource enrichment, complete-trace
  batching, oversized-trace partial success, and opt-in deterministic
  whole-trace admission sampling;
- bounded text and Kubernetes CRI file tailing with crash-safe checkpoints,
  CRI timestamp/fragment assembly, path-derived Kubernetes resource identity,
  bounded multiline assembly, explicit text timestamps, pre-spool content
  redaction, and rotate/truncate detection;
- optional fail-open Kubernetes API metadata caching with UID verification,
  workload/container identity, and label allowlists;
- bounded journald collection through binary-safe Journal Export Format with
  durable cursors, filters, redaction, and explicit oversized-message handling;
- bounded Linux host metrics from configurable virtual-filesystem roots,
  including CPU, memory, interfaces, aggregate socket/TCP/UDP health, load,
  uptime, PSI, UTS metadata, disk I/O, local filesystem capacity, inode usage,
  mount health, scoped cgroup v2 CPU/memory/PID/I/O limits and usage, and
  mount-aware host/OS resource detection with opt-in stable machine identity;
- relabel, counter-reset, and cardinality processors;
- OTLP gRPC/HTTP export with retry, bounded crash-safe spool, and backpressure;
- Reef TLS, mTLS, and bearer authentication on ingress and egress;
- Gyre lifecycle, readiness, status, and generation-aware reload.

The configured eBPF source currently performs capability detection only and
does not emit telemetry.

## Build and test

Wisp requires the Go version declared in `go.mod`.

```bash
make build
./wisp -version
make test
make lint
```

Run the agent with an explicit configuration:

```bash
./wisp -config configs/wisp.example.yaml
```

The self-observability listener exposes:

- `GET /metrics` — Prometheus metrics;
- `GET /healthz` — cheap process liveness;
- `GET /readyz` — dependency and durability readiness;
- `GET /status` — Gyre component state, version, and config generation.

`SIGHUP` reloads the safe scrape surface. Listener, exporter, spool, processor,
resource, and security changes are rejected without advancing the active
generation; they require a restart.

## Delivery semantics

The on-disk spool is bounded by default and fsyncs accepted batches before
acknowledging durability. Backpressure is applied before the spool fills.
Malformed or permanently rejected batches are quarantined from the drain path
so they cannot block newer telemetry. The disk queue is signal-neutral: it
tracks per-signal depth and pressure and drains signals fairly, so an outage on
one telemetry path cannot head-of-line block another.

## Security

Reef owns the transport-security contract. Non-loopback plaintext listeners
and exporters require an explicit insecure opt-in. Bearer credentials over
plaintext require a separate danger opt-in. Secrets are never included in
Gyre status or normal logs.

## License

Apache License 2.0.
