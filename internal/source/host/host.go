// Package host collects node metrics from /proc and /sys. v0 collectors: load,
// memory, cpu, network. A parse error on one metric skips it rather than
// failing the cycle.
package host

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"log/slog"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
)

// userHZ is the assumed clock tick for /proc/stat (jiffies -> time). 100 is the
// near-universal Linux default; reading sysconf(_SC_CLK_TCK) needs cgo.
const userHZ = 100

// Source periodically collects host metrics and emits them into the pipeline.
type Source struct {
	interval   time.Duration
	collectors map[string]bool
	resource   model.Labels
	logger     *slog.Logger
}

// New builds a host Source. enabled lists the collectors to run; empty means all.
func New(interval time.Duration, enabled []string, resource model.Labels, logger *slog.Logger) *Source {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	set := make(map[string]bool, len(enabled))
	for _, c := range enabled {
		set[c] = true
	}
	return &Source{interval: interval, collectors: set, resource: resource, logger: logger}
}

func (s *Source) enabled(name string) bool {
	if len(s.collectors) == 0 {
		return true
	}
	return s.collectors[name]
}

// Start runs the collection loop until ctx is canceled.
func (s *Source) Start(ctx context.Context, emit func(context.Context, model.Batch) error) error {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	// Collect once immediately so the first sample doesn't wait a full interval.
	s.collectAndEmit(ctx, emit)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.collectAndEmit(ctx, emit)
		}
	}
}

func (s *Source) Stop(context.Context) error { return nil }

func (s *Source) collectAndEmit(ctx context.Context, emit func(context.Context, model.Batch) error) {
	now := uint64(time.Now().UnixNano())
	var series []model.Series
	for _, c := range []struct {
		name    string
		collect func(uint64) []model.Series
	}{
		{"load", s.load},
		{"memory", s.memory},
		{"cpu", s.cpu},
		{"network", s.network},
	} {
		if s.enabled(c.name) {
			series = append(series, c.collect(now)...)
		}
	}
	for i := range series {
		series[i].Resource = s.resource
	}
	selfobs.HostCollections.Inc()
	batch := model.Batch{Series: series}
	if err := emit(ctx, batch); pipeline.IsLoggableEmitError(ctx, err) {
		s.logger.Warn("host emit failed", "err", err)
	}
}

func gauge(name, unit string, ts uint64, v float64, attrs model.Labels) model.Series {
	return model.Series{
		Name: name, Unit: unit, Type: model.MetricGauge, Attrs: attrs,
		Points: []model.Point{{TimeUnixNano: ts, FloatValue: v, IsFloat: true}},
	}
}

func counterInt(name, unit string, ts uint64, v int64, attrs model.Labels) model.Series {
	return model.Series{
		Name: name, Unit: unit, Type: model.MetricSum, Monotonic: true, Attrs: attrs,
		Points: []model.Point{{TimeUnixNano: ts, IntValue: v}},
	}
}

// load reads /proc/loadavg -> node_load1/5/15.
func (s *Source) load(ts uint64) []model.Series {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		s.logger.Debug("load: read failed", "err", err)
		return nil
	}
	f := strings.Fields(string(data))
	if len(f) < 3 {
		return nil
	}
	var out []model.Series
	for i, name := range []string{"node_load1", "node_load5", "node_load15"} {
		if v, err := strconv.ParseFloat(f[i], 64); err == nil {
			out = append(out, gauge(name, "", ts, v, nil))
		}
	}
	return out
}

// memory reads /proc/meminfo -> a subset of node_memory_*_bytes gauges.
func (s *Source) memory(ts uint64) []model.Series {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		s.logger.Debug("memory: open failed", "err", err)
		return nil
	}
	defer file.Close()

	want := map[string]string{
		"MemTotal":     "node_memory_MemTotal_bytes",
		"MemFree":      "node_memory_MemFree_bytes",
		"MemAvailable": "node_memory_MemAvailable_bytes",
		"Cached":       "node_memory_Cached_bytes",
		"Buffers":      "node_memory_Buffers_bytes",
	}
	var out []model.Series
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		name, wanted := want[key]
		if !ok || !wanted {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(f[0], 64)
		if err != nil {
			continue
		}
		// meminfo is in kB unless a unit says otherwise.
		if len(f) > 1 && f[1] == "kB" {
			v *= 1024
		}
		out = append(out, gauge(name, "bytes", ts, v, nil))
	}
	if err := sc.Err(); err != nil {
		s.logger.Debug("memory: scan failed", "err", err)
	}
	return out
}

// cpu reads /proc/stat per-CPU lines -> node_cpu_seconds_total{cpu,mode}.
func (s *Source) cpu(ts uint64) []model.Series {
	file, err := os.Open("/proc/stat")
	if err != nil {
		s.logger.Debug("cpu: open failed", "err", err)
		return nil
	}
	defer file.Close()

	modes := []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"}
	var out []model.Series
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		// Only per-CPU lines ("cpu0", "cpu1", ...); skip the "cpu" aggregate.
		if len(f) < 2 || !strings.HasPrefix(f[0], "cpu") || f[0] == "cpu" {
			continue
		}
		cpuNum := strings.TrimPrefix(f[0], "cpu")
		for i, mode := range modes {
			if i+1 >= len(f) {
				break
			}
			jiffies, err := strconv.ParseInt(f[i+1], 10, 64)
			if err != nil {
				continue
			}
			// Emit integer milliseconds rather than float seconds: amber stores
			// it exactly (no scale factor), so rate() returns true-scale ms/s instead
			// of float-scaled values. See the wisp/coral/amber metric contract value model.
			ms := jiffies * 1000 / userHZ
			out = append(out, counterInt("node_cpu_milliseconds_total", "ms", ts, ms,
				model.Labels{{Name: "cpu", Value: cpuNum}, {Name: "mode", Value: mode}}))
		}
	}
	if err := sc.Err(); err != nil {
		s.logger.Debug("cpu: scan failed", "err", err)
	}
	return out
}

// network reads /proc/net/dev -> node_network_{receive,transmit}_bytes_total{device}.
func (s *Source) network(ts uint64) []model.Series {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		s.logger.Debug("network: open failed", "err", err)
		return nil
	}
	defer file.Close()

	var out []model.Series
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := sc.Text()
		dev, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue // header lines have no colon
		}
		dev = strings.TrimSpace(dev)
		f := strings.Fields(rest)
		// Columns: rx_bytes(0) ... 8 rx fields, then tx_bytes(8).
		if len(f) < 9 {
			continue
		}
		// Give each series its own device slice: downstream processors (relabel)
		// mutate Attrs after a shallow Series copy, so a shared slice would let a
		// rewrite of one series corrupt the other.
		if rx, err := strconv.ParseInt(f[0], 10, 64); err == nil {
			out = append(out, counterInt("node_network_receive_bytes_total", "bytes", ts, rx,
				model.Labels{{Name: "device", Value: dev}}))
		}
		if tx, err := strconv.ParseInt(f[8], 10, 64); err == nil {
			out = append(out, counterInt("node_network_transmit_bytes_total", "bytes", ts, tx,
				model.Labels{{Name: "device", Value: dev}}))
		}
	}
	if err := sc.Err(); err != nil {
		s.logger.Debug("network: scan failed", "err", err)
	}
	return out
}
