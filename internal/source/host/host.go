// Package host collects bounded Linux node metrics from procfs, sysfs, and
// cgroupfs. One collector failure does not block the other collectors.
package host

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"log/slog"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
)

// userHZ is the assumed clock tick for /proc/stat (jiffies -> time). 100 is the
// near-universal Linux default; reading sysconf(_SC_CLK_TCK) needs cgo.
const userHZ = 100

// ErrUnsupported marks an optional kernel interface that is unavailable on the
// running host. It is observable but does not count as a collection error.
var ErrUnsupported = errors.New("host collector unsupported")

// Paths are read-only Linux virtual-filesystem roots. Alternate roots support
// a containerized Wisp with host /proc, /sys, /, and cgroup2 mounts.
type Paths struct {
	ProcFS   string
	SysFS    string
	RootFS   string
	CgroupFS string
}

// DefaultPaths returns the Linux virtual-filesystem roots used on a host
// installation.
func DefaultPaths() Paths {
	return Paths{
		ProcFS:   "/proc",
		SysFS:    "/sys",
		RootFS:   "/",
		CgroupFS: "/sys/fs/cgroup",
	}
}

func normalizedPaths(paths Paths) Paths {
	defaults := DefaultPaths()
	if paths.ProcFS == "" {
		paths.ProcFS = defaults.ProcFS
	}
	if paths.SysFS == "" {
		paths.SysFS = defaults.SysFS
	}
	if paths.RootFS == "" {
		paths.RootFS = defaults.RootFS
	}
	if paths.CgroupFS == "" {
		paths.CgroupFS = defaults.CgroupFS
	}
	return paths
}

// Source periodically collects host metrics and emits them into the pipeline.
type Source struct {
	interval   time.Duration
	collectors map[string]bool
	resource   model.Labels
	logger     *slog.Logger
	paths      Paths

	statsMu   sync.RWMutex
	durations map[string]float64
	success   map[string]float64
	states    map[string]string
}

// New builds a host Source. enabled lists the collectors to run; empty means all.
func New(interval time.Duration, enabled []string, resource model.Labels, logger *slog.Logger) *Source {
	return NewWithPaths(
		interval,
		enabled,
		resource,
		DefaultPaths(),
		logger,
	)
}

// NewWithPaths builds a Source against explicit read-only filesystem roots.
func NewWithPaths(
	interval time.Duration,
	enabled []string,
	resource model.Labels,
	paths Paths,
	logger *slog.Logger,
) *Source {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	set := make(map[string]bool, len(enabled))
	for _, c := range enabled {
		set[c] = true
	}
	source := &Source{
		interval: interval, collectors: set,
		resource: resource, logger: logger,
		paths:     normalizedPaths(paths),
		durations: make(map[string]float64),
		success:   make(map[string]float64),
		states:    make(map[string]string),
	}
	for _, collector := range source.collectorRegistry() {
		if source.enabled(collector.name) {
			source.durations[collector.name] = 0
			source.success[collector.name] = 0
		}
	}
	selfobs.RegisterGaugeVecFunc(
		"wisp_host_collector_duration_seconds",
		"Wall-clock duration of the latest host collector attempt.",
		"collector",
		source.durationSnapshot,
	)
	selfobs.RegisterGaugeVecFunc(
		"wisp_host_collector_success",
		"Whether the latest host collector attempt succeeded (1) or failed/was unsupported (0).",
		"collector",
		source.successSnapshot,
	)
	return source
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

type collectorEntry struct {
	name    string
	collect func(uint64) ([]model.Series, error)
}

func (s *Source) collectorRegistry() []collectorEntry {
	return []collectorEntry{
		{"load", s.load},
		{"memory", s.memory},
		{"cpu", s.cpu},
		{"network", s.network},
		{"uptime", s.uptime},
		{"pressure", s.pressure},
		{"uname", s.uname},
	}
}

func (s *Source) collectAndEmit(ctx context.Context, emit func(context.Context, model.Batch) error) {
	now := uint64(time.Now().UnixNano())
	var series []model.Series
	for _, collector := range s.collectorRegistry() {
		if s.enabled(collector.name) {
			started := time.Now()
			collected, err := collector.collect(now)
			s.recordCollectorResult(
				collector.name,
				time.Since(started),
				err,
			)
			series = append(series, collected...)
		}
	}
	for i := range series {
		series[i].Resource = s.resource
	}
	selfobs.HostCollections.Inc()
	selfobs.HostSeriesEmitted.Add(uint64(len(series)))
	batch := model.Batch{Series: series}
	if err := emit(ctx, batch); pipeline.IsLoggableEmitError(ctx, err) {
		selfobs.HostEmitErrors.Inc()
		s.logger.Warn("host emit failed", "err", err)
	}
}

func (s *Source) recordCollectorResult(
	name string,
	duration time.Duration,
	err error,
) {
	state := "ok"
	if errors.Is(err, ErrUnsupported) {
		state = "unsupported"
		selfobs.HostCollectorUnsupported.Inc()
	} else if err != nil {
		state = "error"
		selfobs.HostCollectorErrors.Inc()
	}

	s.statsMu.Lock()
	previous := s.states[name]
	s.states[name] = state
	s.durations[name] = duration.Seconds()
	if state == "ok" {
		s.success[name] = 1
	} else {
		s.success[name] = 0
	}
	s.statsMu.Unlock()

	if previous == state {
		return
	}
	switch state {
	case "error":
		s.logger.Warn(
			"host collector failed",
			"collector",
			name,
			"err",
			err,
		)
	case "unsupported":
		s.logger.Debug(
			"host collector unsupported",
			"collector",
			name,
			"err",
			err,
		)
	case "ok":
		if previous != "" {
			s.logger.Info(
				"host collector recovered",
				"collector",
				name,
				"previous_state",
				previous,
			)
		}
	}
}

func (s *Source) durationSnapshot() map[string]float64 {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()
	return cloneFloatMap(s.durations)
}

func (s *Source) successSnapshot() map[string]float64 {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()
	return cloneFloatMap(s.success)
}

func cloneFloatMap(values map[string]float64) map[string]float64 {
	cloned := make(map[string]float64, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func (s *Source) procPath(elements ...string) string {
	return filepath.Join(append([]string{s.paths.ProcFS}, elements...)...)
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
func (s *Source) load(ts uint64) ([]model.Series, error) {
	data, err := readBoundedFile(s.procPath("loadavg"), 4<<10)
	if err != nil {
		return nil, fmt.Errorf("read loadavg: %w", err)
	}
	f := strings.Fields(string(data))
	if len(f) < 3 {
		return nil, fmt.Errorf("parse loadavg: expected at least 3 fields")
	}
	var out []model.Series
	for i, name := range []string{"node_load1", "node_load5", "node_load15"} {
		v, err := strconv.ParseFloat(f[i], 64)
		if err != nil || math.IsNaN(v) ||
			math.IsInf(v, 0) || v < 0 {
			return out, fmt.Errorf(
				"parse loadavg field %d %q: invalid non-negative number",
				i,
				f[i],
			)
		}
		out = append(out, gauge(name, "", ts, v, nil))
	}
	return out, nil
}

// memory reads /proc/meminfo -> a subset of node_memory_*_bytes gauges.
func (s *Source) memory(ts uint64) ([]model.Series, error) {
	data, err := readBoundedFile(
		s.procPath("meminfo"),
		maxHostVirtualFileBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("read meminfo: %w", err)
	}

	want := map[string]string{
		"MemTotal":     "node_memory_MemTotal_bytes",
		"MemFree":      "node_memory_MemFree_bytes",
		"MemAvailable": "node_memory_MemAvailable_bytes",
		"Cached":       "node_memory_Cached_bytes",
		"Buffers":      "node_memory_Buffers_bytes",
	}
	var out []model.Series
	var parseErrors []error
	for _, line := range strings.Split(string(data), "\n") {
		key, rest, ok := strings.Cut(line, ":")
		name, wanted := want[key]
		if !ok || !wanted {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			parseErrors = append(
				parseErrors,
				fmt.Errorf("meminfo %s has no value", key),
			)
			continue
		}
		v, err := strconv.ParseFloat(f[0], 64)
		if err != nil || math.IsNaN(v) ||
			math.IsInf(v, 0) || v < 0 {
			parseErrors = append(
				parseErrors,
				fmt.Errorf("parse meminfo %s value %q", key, f[0]),
			)
			continue
		}
		// meminfo is in kB unless a unit says otherwise.
		if len(f) > 1 && f[1] == "kB" {
			v *= 1024
		}
		out = append(out, gauge(name, "bytes", ts, v, nil))
	}
	if len(out) == 0 && len(parseErrors) == 0 {
		parseErrors = append(
			parseErrors,
			errors.New("meminfo contains no supported fields"),
		)
	}
	return out, errors.Join(parseErrors...)
}

// cpu reads /proc/stat per-CPU lines -> node_cpu_milliseconds_total{cpu,mode}.
func (s *Source) cpu(ts uint64) ([]model.Series, error) {
	data, err := readBoundedFile(s.procPath("stat"), 8<<20)
	if err != nil {
		return nil, fmt.Errorf("read stat: %w", err)
	}

	modes := []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"}
	var out []model.Series
	var parseErrors []error
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
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
			if err != nil || jiffies < 0 {
				parseErrors = append(
					parseErrors,
					fmt.Errorf(
						"parse stat %s %s value %q",
						f[0],
						mode,
						f[i+1],
					),
				)
				continue
			}
			// Emit integer milliseconds rather than float seconds: amber stores
			// it exactly (no scale factor), so rate() returns true-scale ms/s instead
			// of float-scaled values.
			ms := jiffies * 1000 / userHZ
			out = append(out, counterInt("node_cpu_milliseconds_total", "ms", ts, ms,
				model.Labels{{Name: "cpu", Value: cpuNum}, {Name: "mode", Value: mode}}))
		}
	}
	if len(out) == 0 && len(parseErrors) == 0 {
		parseErrors = append(
			parseErrors,
			errors.New("stat contains no per-CPU values"),
		)
	}
	return out, errors.Join(parseErrors...)
}

// network reads /proc/net/dev -> node_network_{receive,transmit}_bytes_total{device}.
func (s *Source) network(ts uint64) ([]model.Series, error) {
	data, err := readBoundedFile(
		s.procPath("net", "dev"),
		maxHostVirtualFileBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("read net/dev: %w", err)
	}

	var out []model.Series
	var parseErrors []error
	for _, line := range strings.Split(string(data), "\n") {
		dev, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue // header lines have no colon
		}
		dev = strings.TrimSpace(dev)
		f := strings.Fields(rest)
		// Columns: rx_bytes(0) ... 8 rx fields, then tx_bytes(8).
		if len(f) < 9 {
			parseErrors = append(
				parseErrors,
				fmt.Errorf(
					"parse net/dev %s: expected at least 9 fields",
					dev,
				),
			)
			continue
		}
		// Give each series its own device slice: downstream processors (relabel)
		// mutate Attrs after a shallow Series copy, so a shared slice would let a
		// rewrite of one series corrupt the other.
		if rx, err := strconv.ParseInt(f[0], 10, 64); err == nil && rx >= 0 {
			out = append(out, counterInt("node_network_receive_bytes_total", "bytes", ts, rx,
				model.Labels{{Name: "device", Value: dev}}))
		} else {
			parseErrors = append(
				parseErrors,
				fmt.Errorf(
					"parse net/dev %s receive value %q",
					dev,
					f[0],
				),
			)
		}
		if tx, err := strconv.ParseInt(f[8], 10, 64); err == nil && tx >= 0 {
			out = append(out, counterInt("node_network_transmit_bytes_total", "bytes", ts, tx,
				model.Labels{{Name: "device", Value: dev}}))
		} else {
			parseErrors = append(
				parseErrors,
				fmt.Errorf(
					"parse net/dev %s transmit value %q",
					dev,
					f[8],
				),
			)
		}
	}
	if len(out) == 0 && len(parseErrors) == 0 {
		parseErrors = append(
			parseErrors,
			errors.New("net/dev contains no device counters"),
		)
	}
	return out, errors.Join(parseErrors...)
}
