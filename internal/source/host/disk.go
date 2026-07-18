package host

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/yaop-labs/wisp/internal/model"
)

const (
	maxDiskstatsBytes   = 4 << 20
	maxDiskstatsDevices = 4096
	diskSectorBytes     = int64(512)
)

type diskstatsRecord struct {
	major, minor int64
	device       string
	values       []int64
}

func (s *Source) disk(ts uint64) ([]model.Series, error) {
	data, err := readBoundedFile(
		s.procPath("diskstats"),
		maxDiskstatsBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("read diskstats: %w", err)
	}
	records, parseErr := parseDiskstats(data, maxDiskstatsDevices)
	series := make([]model.Series, 0, len(records)*18)
	for _, record := range records {
		series = append(series, diskSeries(record, ts)...)
	}
	return series, parseErr
}

func parseDiskstats(data []byte, maxDevices int) ([]diskstatsRecord, error) {
	var records []diskstatsRecord
	var parseErrors boundedErrors
	devicesSeen := 0
	for lineNumber, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		devicesSeen++
		if devicesSeen > maxDevices {
			parseErrors.Add(
				fmt.Errorf("diskstats exceeds %d devices", maxDevices),
			)
			break
		}
		if len(fields) < 14 {
			parseErrors.Add(
				fmt.Errorf(
					"diskstats line %d: expected at least 14 fields",
					lineNumber+1,
				),
			)
			continue
		}
		if fields[2] == "" || len(fields[2]) > 255 ||
			strings.IndexByte(fields[2], 0) >= 0 {
			parseErrors.Add(
				fmt.Errorf(
					"diskstats line %d: invalid device name",
					lineNumber+1,
				),
			)
			continue
		}
		major, err := parseNonNegativeInt63(fields[0])
		if err != nil {
			parseErrors.Add(
				fmt.Errorf(
					"diskstats line %d major: %w",
					lineNumber+1,
					err,
				),
			)
			continue
		}
		minor, err := parseNonNegativeInt63(fields[1])
		if err != nil {
			parseErrors.Add(
				fmt.Errorf(
					"diskstats line %d minor: %w",
					lineNumber+1,
					err,
				),
			)
			continue
		}
		valueFields := fields[3:]
		if len(valueFields) > 11 && len(valueFields) < 15 {
			parseErrors.Add(
				fmt.Errorf(
					"diskstats line %d: incomplete discard fields",
					lineNumber+1,
				),
			)
			continue
		}
		if len(valueFields) > 15 && len(valueFields) < 17 {
			parseErrors.Add(
				fmt.Errorf(
					"diskstats line %d: incomplete flush fields",
					lineNumber+1,
				),
			)
			continue
		}
		valueCount := 11
		if len(valueFields) >= 15 {
			valueCount = 15
		}
		if len(valueFields) >= 17 {
			valueCount = 17
		}
		values := make([]int64, valueCount)
		valid := true
		for index := range values {
			values[index], err = parseNonNegativeInt63(
				valueFields[index],
			)
			if err != nil {
				parseErrors.Add(
					fmt.Errorf(
						"diskstats line %d field %d: %w",
						lineNumber+1,
						index+4,
						err,
					),
				)
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		for _, index := range []int{2, 6, 13} {
			if index < len(values) &&
				values[index] > math.MaxInt64/diskSectorBytes {
				parseErrors.Add(
					fmt.Errorf(
						"diskstats line %d sector count overflows bytes",
						lineNumber+1,
					),
				)
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		records = append(records, diskstatsRecord{
			major:  major,
			minor:  minor,
			device: fields[2],
			values: values,
		})
	}
	if len(records) == 0 && parseErrors.Empty() {
		parseErrors.Add(fmt.Errorf("diskstats contains no devices"))
	}
	return records, parseErrors.Err()
}

func parseNonNegativeInt63(raw string) (int64, error) {
	value, err := strconv.ParseUint(raw, 10, 63)
	if err != nil {
		return 0, fmt.Errorf(
			"parse non-negative integer %q: %w",
			raw,
			err,
		)
	}
	return int64(value), nil
}

func diskSeries(record diskstatsRecord, ts uint64) []model.Series {
	attrs := func() model.Labels {
		return model.Labels{
			{Name: "device", Value: record.device},
			{Name: "major", Value: strconv.FormatInt(record.major, 10)},
			{Name: "minor", Value: strconv.FormatInt(record.minor, 10)},
		}
	}
	counter := func(name, unit string, value int64) model.Series {
		return counterInt(name, unit, ts, value, attrs())
	}
	gaugeValue := func(name, unit string, value int64) model.Series {
		return gaugeInt(name, unit, ts, value, attrs())
	}
	values := record.values
	series := []model.Series{
		counter("node_disk_reads_completed_total", "", values[0]),
		counter("node_disk_reads_merged_total", "", values[1]),
		counter(
			"node_disk_read_bytes_total",
			"bytes",
			values[2]*diskSectorBytes,
		),
		counter("node_disk_read_milliseconds_total", "ms", values[3]),
		counter("node_disk_writes_completed_total", "", values[4]),
		counter("node_disk_writes_merged_total", "", values[5]),
		counter(
			"node_disk_written_bytes_total",
			"bytes",
			values[6]*diskSectorBytes,
		),
		counter("node_disk_write_milliseconds_total", "ms", values[7]),
		gaugeValue("node_disk_io_now", "", values[8]),
		counter("node_disk_io_milliseconds_total", "ms", values[9]),
		counter(
			"node_disk_io_weighted_milliseconds_total",
			"ms",
			values[10],
		),
	}
	if len(values) >= 15 {
		series = append(
			series,
			counter("node_disk_discards_completed_total", "", values[11]),
			counter("node_disk_discards_merged_total", "", values[12]),
			counter(
				"node_disk_discarded_bytes_total",
				"bytes",
				values[13]*diskSectorBytes,
			),
			counter(
				"node_disk_discard_milliseconds_total",
				"ms",
				values[14],
			),
		)
	}
	if len(values) >= 17 {
		series = append(
			series,
			counter(
				"node_disk_flush_requests_completed_total",
				"",
				values[15],
			),
			counter(
				"node_disk_flush_milliseconds_total",
				"ms",
				values[16],
			),
		)
	}
	return series
}
