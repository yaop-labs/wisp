# Wisp

Wisp is the edge observability agent for the YAOP stack. It collects and
processes telemetry close to its source, persists batches across downstream
outages, and exports them to Coral over OTLP.

The current implementation has a typed metrics path plus lossless OTLP Logs
and Traces passthrough:

- Prometheus/OpenMetrics scraping with static, file, DNS, and Kubernetes
  discovery;
- OTLP metrics, logs, and traces receive/export over gRPC and HTTP/protobuf;
- bounded text and Kubernetes CRI file tailing with crash-safe checkpoints,
  CRI timestamp/fragment assembly, path-derived Kubernetes resource identity,
  bounded multiline assembly, explicit text timestamps, pre-spool content
  redaction, and rotate/truncate detection;
- bounded journald collection through binary-safe Journal Export Format with
  durable cursors, filters, redaction, and explicit oversized-message handling;
- Linux host metrics from `/proc`;
- relabel, counter-reset, and cardinality processors;
- OTLP gRPC/HTTP export with retry, bounded crash-safe spool, and backpressure;
- Reef TLS, mTLS, and bearer authentication on ingress and egress;
- Gyre lifecycle, readiness, status, and generation-aware reload.

Trace-aware batching/sampling and the actual eBPF backend are planned, not
silently simulated.
See [the roadmap](docs/ROADMAP.md) and
[the signal extensibility ADR](docs/adr/0001-signal-extensible-core.md).

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
