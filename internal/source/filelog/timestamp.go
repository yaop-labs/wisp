package filelog

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"

	"github.com/yaop-labs/wisp/internal/selfobs"
)

const maxTimestampCaptureBytes = 128

type timestampParser struct {
	pattern *regexp.Regexp
	format  string
}

func newTimestampParser(config *TimestampConfig) (*timestampParser, error) {
	if config == nil {
		return nil, nil
	}
	if config.Pattern == "" || len(config.Pattern) > 1024 {
		return nil, fmt.Errorf("filelog: timestamp pattern must contain between 1 and 1024 bytes")
	}
	pattern, err := regexp.Compile(config.Pattern)
	if err != nil || pattern.NumSubexp() != 1 {
		return nil, fmt.Errorf(
			"filelog: timestamp pattern must be valid with exactly one capture group",
		)
	}
	if pattern.MatchString("") {
		return nil, fmt.Errorf("filelog: timestamp pattern must not match empty input")
	}
	switch config.Format {
	case "rfc3339", "rfc3339nano", "unix", "unix_ms", "unix_us", "unix_ns":
	default:
		return nil, fmt.Errorf("filelog: unsupported timestamp format")
	}
	return &timestampParser{pattern: pattern, format: config.Format}, nil
}

func (s *Source) parseTextTimestamp(body []byte) uint64 {
	if s.timestamp == nil {
		return 0
	}
	value, ok := s.timestamp.parse(body)
	if ok {
		selfobs.FileLogTimestampParsed.Inc()
		return value
	}
	selfobs.FileLogTimestampErrors.Inc()
	return 0
}

func (p *timestampParser) parse(body []byte) (uint64, bool) {
	indices := p.pattern.FindSubmatchIndex(body)
	if len(indices) != 4 || indices[2] < 0 ||
		indices[3]-indices[2] > maxTimestampCaptureBytes {
		return 0, false
	}
	capture := string(body[indices[2]:indices[3]])
	switch p.format {
	case "rfc3339":
		return parseRFC3339Timestamp(capture, time.RFC3339)
	case "rfc3339nano":
		return parseRFC3339Timestamp(capture, time.RFC3339Nano)
	case "unix":
		return parseUnixTimestamp(capture, uint64(time.Second))
	case "unix_ms":
		return parseUnixTimestamp(capture, uint64(time.Millisecond))
	case "unix_us":
		return parseUnixTimestamp(capture, uint64(time.Microsecond))
	case "unix_ns":
		return parseUnixTimestamp(capture, 1)
	default:
		return 0, false
	}
}

func parseRFC3339Timestamp(value, layout string) (uint64, bool) {
	parsed, err := time.Parse(layout, value)
	if err != nil {
		return 0, false
	}
	seconds := parsed.Unix()
	if seconds < 0 || uint64(seconds) > math.MaxUint64/uint64(time.Second) {
		return 0, false
	}
	return uint64(seconds)*uint64(time.Second) +
		uint64(parsed.Nanosecond()), true
}

func parseUnixTimestamp(value string, multiplier uint64) (uint64, bool) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed > math.MaxUint64/multiplier {
		return 0, false
	}
	return parsed * multiplier, true
}
