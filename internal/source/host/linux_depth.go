package host

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/yaop-labs/wisp/internal/model"
)

const maxHostVirtualFileBytes = 1 << 20

func readBoundedFile(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf(
			"virtual file exceeds %d bytes",
			maxBytes,
		)
	}
	return data, nil
}

func (s *Source) uptime(ts uint64) ([]model.Series, error) {
	data, err := readBoundedFile(
		s.procPath("uptime"),
		4<<10,
	)
	if err != nil {
		return nil, fmt.Errorf("read uptime: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return nil, fmt.Errorf("parse uptime: missing uptime field")
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || math.IsNaN(seconds) ||
		math.IsInf(seconds, 0) || seconds < 0 {
		return nil, fmt.Errorf(
			"parse uptime %q: invalid non-negative number",
			fields[0],
		)
	}
	capturedSeconds := float64(ts) / float64(timeSecond)
	return []model.Series{
		gauge(
			"node_uptime_seconds",
			"s",
			ts,
			seconds,
			nil,
		),
		gauge(
			"node_boot_time_seconds",
			"s",
			ts,
			capturedSeconds-seconds,
			nil,
		),
	}, nil
}

const timeSecond = uint64(1_000_000_000)

type pressureRecord struct {
	scope  string
	avg10  float64
	avg60  float64
	avg300 float64
	total  uint64
}

func (s *Source) pressure(ts uint64) ([]model.Series, error) {
	var series []model.Series
	var parseErrors []error
	available := 0
	for _, resource := range []string{"cpu", "memory", "io"} {
		data, err := readBoundedFile(
			s.procPath("pressure", resource),
			16<<10,
		)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			parseErrors = append(
				parseErrors,
				fmt.Errorf("read pressure/%s: %w", resource, err),
			)
			continue
		}
		available++
		records, err := parsePressure(data)
		if err != nil {
			parseErrors = append(
				parseErrors,
				fmt.Errorf("parse pressure/%s: %w", resource, err),
			)
			continue
		}
		for _, record := range records {
			series = append(
				series,
				pressureSeries(
					resource,
					record,
					ts,
				)...,
			)
		}
	}
	if available == 0 && len(parseErrors) == 0 {
		return nil, fmt.Errorf(
			"%w: procfs pressure files are absent",
			ErrUnsupported,
		)
	}
	return series, errors.Join(parseErrors...)
}

func parsePressure(data []byte) ([]pressureRecord, error) {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	records := make([]pressureRecord, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 5 ||
			(fields[0] != "some" && fields[0] != "full") {
			return nil, fmt.Errorf("invalid PSI line %q", line)
		}
		if _, duplicate := seen[fields[0]]; duplicate {
			return nil, fmt.Errorf(
				"duplicate PSI scope %q",
				fields[0],
			)
		}
		seen[fields[0]] = struct{}{}
		values := make(map[string]string, 4)
		for _, field := range fields[1:] {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				return nil, fmt.Errorf(
					"invalid PSI field %q",
					field,
				)
			}
			values[key] = value
		}
		record := pressureRecord{scope: fields[0]}
		var err error
		record.avg10, err = parsePressureAverage(
			values,
			"avg10",
		)
		if err != nil {
			return nil, err
		}
		record.avg60, err = parsePressureAverage(
			values,
			"avg60",
		)
		if err != nil {
			return nil, err
		}
		record.avg300, err = parsePressureAverage(
			values,
			"avg300",
		)
		if err != nil {
			return nil, err
		}
		total, exists := values["total"]
		if !exists {
			return nil, fmt.Errorf("missing PSI total")
		}
		record.total, err = strconv.ParseUint(total, 10, 63)
		if err != nil {
			return nil, fmt.Errorf(
				"parse PSI total %q: %w",
				total,
				err,
			)
		}
		records = append(records, record)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("empty PSI data")
	}
	return records, nil
}

func parsePressureAverage(
	values map[string]string,
	name string,
) (float64, error) {
	raw, exists := values[name]
	if !exists {
		return 0, fmt.Errorf("missing PSI %s", name)
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(value) ||
		math.IsInf(value, 0) || value < 0 || value > 100 {
		return 0, fmt.Errorf(
			"parse PSI %s %q: invalid percentage",
			name,
			raw,
		)
	}
	return value / 100, nil
}

func pressureSeries(
	resource string,
	record pressureRecord,
	ts uint64,
) []model.Series {
	scope := "waiting"
	if record.scope == "full" {
		scope = "stalled"
	}
	base := "node_pressure_" + resource + "_" + scope
	return []model.Series{
		counterInt(
			base+"_microseconds_total",
			"us",
			ts,
			int64(record.total),
			nil,
		),
		gauge(
			base+"_ratio",
			"1",
			ts,
			record.avg10,
			model.Labels{{Name: "window", Value: "10s"}},
		),
		gauge(
			base+"_ratio",
			"1",
			ts,
			record.avg60,
			model.Labels{{Name: "window", Value: "60s"}},
		),
		gauge(
			base+"_ratio",
			"1",
			ts,
			record.avg300,
			model.Labels{{Name: "window", Value: "300s"}},
		),
	}
}

func (s *Source) uname(ts uint64) ([]model.Series, error) {
	var value unix.Utsname
	if err := unix.Uname(&value); err != nil {
		return nil, fmt.Errorf("uname: %w", err)
	}
	return []model.Series{gauge(
		"node_uname_info",
		"",
		ts,
		1,
		model.Labels{
			{Name: "sysname", Value: utsString(value.Sysname)},
			{Name: "nodename", Value: utsString(value.Nodename)},
			{Name: "release", Value: utsString(value.Release)},
			{Name: "version", Value: utsString(value.Version)},
			{Name: "machine", Value: utsString(value.Machine)},
			{Name: "domainname", Value: utsString(value.Domainname)},
		},
	)}, nil
}

func utsString(value [65]byte) string {
	length := 0
	for length < len(value) && value[length] != 0 {
		length++
	}
	return string(value[:length])
}
