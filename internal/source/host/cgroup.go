package host

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/yaop-labs/wisp/internal/model"
)

const (
	maxCgroupControlFileBytes = 1 << 20
	maxCgroupIODevices        = 4096
)

var configuredRootCgroupAttrs = model.Labels{
	{Name: "cgroup.scope", Value: "configured_root"},
}

func (s *Source) cgroupPath(name string) string {
	return filepath.Join(s.paths.CgroupFS, name)
}

func (s *Source) cgroup(ts uint64) ([]model.Series, error) {
	if _, err := readBoundedFile(
		s.cgroupPath("cgroup.controllers"),
		64<<10,
	); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf(
				"%w: cgroup.controllers is absent",
				ErrUnsupported,
			)
		}
		return nil, fmt.Errorf("read cgroup.controllers: %w", err)
	}

	series := []model.Series{gaugeInt(
		"node_cgroup_v2_info",
		"",
		ts,
		1,
		cloneLabels(configuredRootCgroupAttrs),
	)}
	var collectionErrors boundedErrors

	collectOptional := func(
		name string,
		parse func([]byte, uint64) ([]model.Series, error),
	) {
		data, err := readBoundedFile(
			s.cgroupPath(name),
			maxCgroupControlFileBytes,
		)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			collectionErrors.Add(fmt.Errorf("read %s: %w", name, err))
			return
		}
		collected, err := parse(data, ts)
		if err != nil {
			collectionErrors.Add(fmt.Errorf("parse %s: %w", name, err))
		}
		series = append(series, collected...)
	}

	collectOptional("cpu.stat", cgroupCPUStatSeries)
	collectOptional("cpu.max", cgroupCPUMaxSeries)
	collectOptional("cpu.weight", func(data []byte, ts uint64) ([]model.Series, error) {
		return cgroupScalarSeries(
			data,
			ts,
			"node_cgroup_cpu_weight",
			"",
		)
	})
	collectOptional("memory.current", func(data []byte, ts uint64) ([]model.Series, error) {
		return cgroupScalarSeries(
			data,
			ts,
			"node_cgroup_memory_current_bytes",
			"bytes",
		)
	})
	collectOptional("memory.max", func(data []byte, ts uint64) ([]model.Series, error) {
		return cgroupLimitSeries(
			data,
			ts,
			"node_cgroup_memory_limit_bytes",
			"node_cgroup_memory_limit_unlimited",
			"bytes",
		)
	})
	collectOptional("memory.swap.current", func(data []byte, ts uint64) ([]model.Series, error) {
		return cgroupScalarSeries(
			data,
			ts,
			"node_cgroup_memory_swap_current_bytes",
			"bytes",
		)
	})
	collectOptional("memory.swap.max", func(data []byte, ts uint64) ([]model.Series, error) {
		return cgroupLimitSeries(
			data,
			ts,
			"node_cgroup_memory_swap_limit_bytes",
			"node_cgroup_memory_swap_limit_unlimited",
			"bytes",
		)
	})
	collectOptional("memory.events", cgroupMemoryEventsSeries)
	collectOptional("pids.current", func(data []byte, ts uint64) ([]model.Series, error) {
		return cgroupScalarSeries(
			data,
			ts,
			"node_cgroup_pids_current",
			"",
		)
	})
	collectOptional("pids.max", func(data []byte, ts uint64) ([]model.Series, error) {
		return cgroupLimitSeries(
			data,
			ts,
			"node_cgroup_pids_limit",
			"node_cgroup_pids_limit_unlimited",
			"",
		)
	})
	collectOptional("io.stat", cgroupIOStatSeries)
	return series, collectionErrors.Err()
}

func cloneLabels(labels model.Labels) model.Labels {
	return append(model.Labels(nil), labels...)
}

func cgroupScalarSeries(
	data []byte,
	ts uint64,
	name string,
	unit string,
) ([]model.Series, error) {
	raw, err := singleCgroupField(data)
	if err != nil {
		return nil, err
	}
	value, err := parseNonNegativeInt63(raw)
	if err != nil {
		return nil, err
	}
	return []model.Series{gaugeInt(
		name,
		unit,
		ts,
		value,
		cloneLabels(configuredRootCgroupAttrs),
	)}, nil
}

func cgroupLimitSeries(
	data []byte,
	ts uint64,
	limitName string,
	unlimitedName string,
	unit string,
) ([]model.Series, error) {
	raw, err := singleCgroupField(data)
	if err != nil {
		return nil, err
	}
	attrs := func() model.Labels {
		return cloneLabels(configuredRootCgroupAttrs)
	}
	if raw == "max" {
		return []model.Series{gaugeInt(
			unlimitedName,
			"",
			ts,
			1,
			attrs(),
		)}, nil
	}
	value, err := parseNonNegativeInt63(raw)
	if err != nil {
		return nil, err
	}
	return []model.Series{
		gaugeInt(limitName, unit, ts, value, attrs()),
		gaugeInt(unlimitedName, "", ts, 0, attrs()),
	}, nil
}

func singleCgroupField(data []byte) (string, error) {
	fields := strings.Fields(string(data))
	if len(fields) != 1 {
		return "", fmt.Errorf(
			"expected exactly one field, got %d",
			len(fields),
		)
	}
	return fields[0], nil
}

func parseCgroupKeyValues(data []byte) (map[string]int64, error) {
	values := make(map[string]int64)
	var parseErrors boundedErrors
	for lineNumber, line := range strings.Split(
		strings.TrimSpace(string(data)),
		"\n",
	) {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			parseErrors.Add(fmt.Errorf(
				"line %d: expected key and value",
				lineNumber+1,
			))
			continue
		}
		if _, duplicate := values[fields[0]]; duplicate {
			parseErrors.Add(fmt.Errorf(
				"line %d: duplicate key %q",
				lineNumber+1,
				fields[0],
			))
			continue
		}
		value, err := parseNonNegativeInt63(fields[1])
		if err != nil {
			parseErrors.Add(fmt.Errorf(
				"line %d key %q: %w",
				lineNumber+1,
				fields[0],
				err,
			))
			continue
		}
		values[fields[0]] = value
	}
	if len(values) == 0 && parseErrors.Empty() {
		parseErrors.Add(errors.New("empty key/value file"))
	}
	return values, parseErrors.Err()
}

func cgroupCPUStatSeries(
	data []byte,
	ts uint64,
) ([]model.Series, error) {
	values, parseErr := parseCgroupKeyValues(data)
	mapping := []struct {
		key  string
		name string
		unit string
	}{
		{"usage_usec", "node_cgroup_cpu_usage_microseconds_total", "us"},
		{"user_usec", "node_cgroup_cpu_user_microseconds_total", "us"},
		{"system_usec", "node_cgroup_cpu_system_microseconds_total", "us"},
		{"nr_periods", "node_cgroup_cpu_periods_total", ""},
		{"nr_throttled", "node_cgroup_cpu_throttled_periods_total", ""},
		{"throttled_usec", "node_cgroup_cpu_throttled_microseconds_total", "us"},
	}
	var series []model.Series
	for _, metric := range mapping {
		if value, exists := values[metric.key]; exists {
			series = append(series, counterInt(
				metric.name,
				metric.unit,
				ts,
				value,
				cloneLabels(configuredRootCgroupAttrs),
			))
		}
	}
	if len(series) == 0 && parseErr == nil {
		parseErr = errors.New("cpu.stat contains no supported keys")
	}
	return series, parseErr
}

func cgroupCPUMaxSeries(
	data []byte,
	ts uint64,
) ([]model.Series, error) {
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return nil, fmt.Errorf(
			"expected quota and period, got %d fields",
			len(fields),
		)
	}
	period, err := parseNonNegativeInt63(fields[1])
	if err != nil || period == 0 {
		return nil, fmt.Errorf("invalid CPU period %q", fields[1])
	}
	attrs := func() model.Labels {
		return cloneLabels(configuredRootCgroupAttrs)
	}
	series := []model.Series{gaugeInt(
		"node_cgroup_cpu_period_microseconds",
		"us",
		ts,
		period,
		attrs(),
	)}
	if fields[0] == "max" {
		return append(series, gaugeInt(
			"node_cgroup_cpu_quota_unlimited",
			"",
			ts,
			1,
			attrs(),
		)), nil
	}
	quota, err := parseNonNegativeInt63(fields[0])
	if err != nil {
		return nil, fmt.Errorf("invalid CPU quota %q", fields[0])
	}
	return append(
		series,
		gaugeInt(
			"node_cgroup_cpu_quota_microseconds",
			"us",
			ts,
			quota,
			attrs(),
		),
		gaugeInt(
			"node_cgroup_cpu_quota_unlimited",
			"",
			ts,
			0,
			attrs(),
		),
	), nil
}

func cgroupMemoryEventsSeries(
	data []byte,
	ts uint64,
) ([]model.Series, error) {
	values, parseErr := parseCgroupKeyValues(data)
	var series []model.Series
	for _, key := range []string{
		"low",
		"high",
		"max",
		"oom",
		"oom_kill",
		"oom_group_kill",
	} {
		value, exists := values[key]
		if !exists {
			continue
		}
		series = append(series, counterInt(
			"node_cgroup_memory_events_total",
			"",
			ts,
			value,
			model.Labels{
				{Name: "cgroup.scope", Value: "configured_root"},
				{Name: "event", Value: key},
			},
		))
	}
	if len(series) == 0 && parseErr == nil {
		parseErr = errors.New("memory.events contains no supported keys")
	}
	return series, parseErr
}

func cgroupIOStatSeries(
	data []byte,
	ts uint64,
) ([]model.Series, error) {
	if strings.TrimSpace(string(data)) == "" {
		return nil, nil
	}
	var series []model.Series
	var parseErrors boundedErrors
	devices := 0
	for lineNumber, line := range strings.Split(
		strings.TrimSpace(string(data)),
		"\n",
	) {
		if line == "" {
			continue
		}
		devices++
		if devices > maxCgroupIODevices {
			parseErrors.Add(fmt.Errorf(
				"io.stat exceeds %d devices",
				maxCgroupIODevices,
			))
			break
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !validMajorMinor(fields[0]) {
			parseErrors.Add(fmt.Errorf(
				"line %d: invalid device record",
				lineNumber+1,
			))
			continue
		}
		mapping := map[string]struct {
			name string
			unit string
		}{
			"rbytes": {"node_cgroup_io_read_bytes_total", "bytes"},
			"wbytes": {"node_cgroup_io_written_bytes_total", "bytes"},
			"rios":   {"node_cgroup_io_read_operations_total", ""},
			"wios":   {"node_cgroup_io_write_operations_total", ""},
			"dbytes": {"node_cgroup_io_discarded_bytes_total", "bytes"},
			"dios":   {"node_cgroup_io_discard_operations_total", ""},
		}
		seen := make(map[string]struct{}, len(fields)-1)
		for _, field := range fields[1:] {
			key, raw, ok := strings.Cut(field, "=")
			if !ok {
				parseErrors.Add(fmt.Errorf(
					"line %d: invalid field %q",
					lineNumber+1,
					field,
				))
				continue
			}
			metric, supported := mapping[key]
			if !supported {
				continue
			}
			if _, duplicate := seen[key]; duplicate {
				parseErrors.Add(fmt.Errorf(
					"line %d: duplicate key %q",
					lineNumber+1,
					key,
				))
				continue
			}
			seen[key] = struct{}{}
			value, err := parseNonNegativeInt63(raw)
			if err != nil {
				parseErrors.Add(fmt.Errorf(
					"line %d key %q: %w",
					lineNumber+1,
					key,
					err,
				))
				continue
			}
			series = append(series, counterInt(
				metric.name,
				metric.unit,
				ts,
				value,
				model.Labels{
					{Name: "cgroup.scope", Value: "configured_root"},
					{Name: "device", Value: fields[0]},
				},
			))
		}
	}
	if len(series) == 0 && parseErrors.Empty() {
		parseErrors.Add(errors.New("io.stat contains no supported counters"))
	}
	return series, parseErrors.Err()
}

func validMajorMinor(raw string) bool {
	major, minor, ok := strings.Cut(raw, ":")
	if !ok {
		return false
	}
	_, majorErr := strconv.ParseUint(major, 10, 32)
	_, minorErr := strconv.ParseUint(minor, 10, 32)
	return majorErr == nil && minorErr == nil
}
