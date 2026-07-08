# wisp

Lightweight, powerful edge observability agent for the yaop stack. One binary
collects metrics from every side — **pull** (Prometheus/OpenMetrics scrape),
**push** (OTLP receive), **probe** (host `/proc`,`/sys` + eBPF) — processes them
at the edge, and ships them over OTLP to [coral](../collector), which enriches
and stores them in [amber](../amber).

Not yet: the eBPF zero-instrumentation probe — the source detects host
capability and no-ops until the BPF backend is compiled in.

## Quick start

```bash
make build
./wisp -config configs/wisp.example.yaml
```

## License

Apache License 2.0
