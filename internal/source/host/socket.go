package host

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/yaop-labs/wisp/internal/model"
)

const maxNetworkStatsBytes = 1 << 20

type sockstatRecord struct {
	family   string
	protocol string
	values   map[string]int64
}

var visibleNetworkNamespaceAttrs = model.Labels{
	{Name: "network.scope", Value: "visible_namespace"},
}

func (s *Source) socket(ts uint64) ([]model.Series, error) {
	var series []model.Series
	var collectionErrors boundedErrors
	available := 0
	for _, file := range []struct {
		name   string
		family string
	}{
		{"sockstat", "ipv4"},
		{"sockstat6", "ipv6"},
	} {
		data, err := readBoundedFile(
			s.procPath("net", file.name),
			maxNetworkStatsBytes,
		)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			collectionErrors.Add(fmt.Errorf("read net/%s: %w", file.name, err))
			continue
		}
		available++
		records, err := parseSockstat(data, file.family)
		if err != nil {
			collectionErrors.Add(fmt.Errorf("parse net/%s: %w", file.name, err))
		}
		series = append(series, sockstatSeries(records, ts)...)
	}

	data, err := readBoundedFile(
		s.procPath("net", "snmp"),
		maxNetworkStatsBytes,
	)
	if errors.Is(err, os.ErrNotExist) {
		// Optional on unusually constrained network namespaces.
	} else if err != nil {
		collectionErrors.Add(fmt.Errorf("read net/snmp: %w", err))
	} else {
		available++
		collected, err := parseSNMPSeries(data, ts)
		if err != nil {
			collectionErrors.Add(fmt.Errorf("parse net/snmp: %w", err))
		}
		series = append(series, collected...)
	}
	if available == 0 && collectionErrors.Empty() {
		collectionErrors.Add(fmt.Errorf(
			"%w: socket statistics files are absent",
			ErrUnsupported,
		))
	}
	return series, collectionErrors.Err()
}

func parseSockstat(
	data []byte,
	family string,
) ([]sockstatRecord, error) {
	if family != "ipv4" && family != "ipv6" {
		return nil, fmt.Errorf("invalid address family %q", family)
	}
	allowedProtocols := map[string]string{
		"sockets":  "sockets",
		"TCP":      "tcp",
		"TCP6":     "tcp",
		"UDP":      "udp",
		"UDP6":     "udp",
		"UDPLITE":  "udplite",
		"UDPLITE6": "udplite",
		"RAW":      "raw",
		"RAW6":     "raw",
		"FRAG":     "fragment",
		"FRAG6":    "fragment",
	}
	var records []sockstatRecord
	var parseErrors boundedErrors
	seen := make(map[string]struct{})
	for lineNumber, line := range strings.Split(
		strings.TrimSpace(string(data)),
		"\n",
	) {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || len(fields)%2 == 0 ||
			!strings.HasSuffix(fields[0], ":") {
			parseErrors.Add(fmt.Errorf(
				"line %d: invalid protocol record",
				lineNumber+1,
			))
			continue
		}
		rawProtocol := strings.TrimSuffix(fields[0], ":")
		protocol, supported := allowedProtocols[rawProtocol]
		if !supported {
			continue
		}
		if _, duplicate := seen[protocol]; duplicate {
			parseErrors.Add(fmt.Errorf(
				"line %d: duplicate protocol %q",
				lineNumber+1,
				protocol,
			))
			continue
		}
		seen[protocol] = struct{}{}
		values := make(map[string]int64, (len(fields)-1)/2)
		supportedKeys := map[string]struct{}{
			"used": {}, "inuse": {}, "orphan": {},
			"tw": {}, "alloc": {}, "mem": {},
			"memory": {},
		}
		for index := 1; index < len(fields); index += 2 {
			key := fields[index]
			if _, supported := supportedKeys[key]; !supported {
				continue
			}
			if _, duplicate := values[key]; duplicate {
				parseErrors.Add(fmt.Errorf(
					"line %d: duplicate key %q",
					lineNumber+1,
					key,
				))
				continue
			}
			value, err := parseNonNegativeInt63(fields[index+1])
			if err != nil {
				parseErrors.Add(fmt.Errorf(
					"line %d key %q: %w",
					lineNumber+1,
					key,
					err,
				))
				continue
			}
			values[key] = value
		}
		if len(values) == 0 {
			parseErrors.Add(fmt.Errorf(
				"line %d protocol %q contains no supported keys",
				lineNumber+1,
				rawProtocol,
			))
			continue
		}
		records = append(records, sockstatRecord{
			family:   family,
			protocol: protocol,
			values:   values,
		})
	}
	if len(records) == 0 && parseErrors.Empty() {
		parseErrors.Add(errors.New("sockstat contains no supported protocols"))
	}
	return records, parseErrors.Err()
}

func sockstatSeries(
	records []sockstatRecord,
	ts uint64,
) []model.Series {
	pageSize := int64(os.Getpagesize())
	type metricSpec struct {
		key  string
		name string
		unit string
	}
	specs := []metricSpec{
		{"used", "node_socket_used", ""},
		{"inuse", "node_socket_inuse", ""},
		{"orphan", "node_socket_orphan", ""},
		{"tw", "node_socket_time_wait", ""},
		{"alloc", "node_socket_allocated", ""},
		{"mem", "node_socket_memory_pages", ""},
		{"memory", "node_socket_reassembly_memory_bytes", "bytes"},
	}
	var series []model.Series
	for _, record := range records {
		for _, spec := range specs {
			value, exists := record.values[spec.key]
			if !exists {
				continue
			}
			attrs := model.Labels{
				{Name: "family", Value: record.family},
				{Name: "network.scope", Value: "visible_namespace"},
				{Name: "protocol", Value: record.protocol},
			}
			series = append(series, gaugeInt(
				spec.name,
				spec.unit,
				ts,
				value,
				attrs,
			))
			if spec.key == "mem" &&
				value <= int64(^uint64(0)>>1)/pageSize {
				series = append(series, gaugeInt(
					"node_socket_memory_bytes",
					"bytes",
					ts,
					value*pageSize,
					model.Labels{
						{Name: "family", Value: record.family},
						{Name: "network.scope", Value: "visible_namespace"},
						{Name: "protocol", Value: record.protocol},
					},
				))
			}
		}
	}
	return series
}

type snmpMetricSpec struct {
	protocol string
	field    string
	name     string
	gauge    bool
}

var snmpMetricSpecs = []snmpMetricSpec{
	{"Tcp", "ActiveOpens", "node_netstat_tcp_active_opens_total", false},
	{"Tcp", "PassiveOpens", "node_netstat_tcp_passive_opens_total", false},
	{"Tcp", "AttemptFails", "node_netstat_tcp_attempt_failures_total", false},
	{"Tcp", "EstabResets", "node_netstat_tcp_established_resets_total", false},
	{"Tcp", "CurrEstab", "node_netstat_tcp_current_established", true},
	{"Tcp", "InSegs", "node_netstat_tcp_segments_received_total", false},
	{"Tcp", "OutSegs", "node_netstat_tcp_segments_sent_total", false},
	{"Tcp", "RetransSegs", "node_netstat_tcp_segments_retransmitted_total", false},
	{"Tcp", "InErrs", "node_netstat_tcp_receive_errors_total", false},
	{"Tcp", "OutRsts", "node_netstat_tcp_resets_sent_total", false},
	{"Tcp", "InCsumErrors", "node_netstat_tcp_checksum_errors_total", false},
	{"Udp", "InDatagrams", "node_netstat_udp_datagrams_received_total", false},
	{"Udp", "NoPorts", "node_netstat_udp_no_port_errors_total", false},
	{"Udp", "InErrors", "node_netstat_udp_receive_errors_total", false},
	{"Udp", "OutDatagrams", "node_netstat_udp_datagrams_sent_total", false},
	{"Udp", "RcvbufErrors", "node_netstat_udp_receive_buffer_errors_total", false},
	{"Udp", "SndbufErrors", "node_netstat_udp_send_buffer_errors_total", false},
	{"Udp", "InCsumErrors", "node_netstat_udp_checksum_errors_total", false},
	{"Udp", "IgnoredMulti", "node_netstat_udp_ignored_multicast_total", false},
	{"Udp", "MemErrors", "node_netstat_udp_memory_errors_total", false},
}

func parseSNMPSeries(data []byte, ts uint64) ([]model.Series, error) {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	valuesByProtocol := make(map[string]map[string]int64)
	var parseErrors boundedErrors
	for index := 0; index < len(lines); {
		if strings.TrimSpace(lines[index]) == "" {
			index++
			continue
		}
		if index+1 >= len(lines) {
			parseErrors.Add(errors.New("unpaired SNMP header line"))
			break
		}
		header := strings.Fields(lines[index])
		values := strings.Fields(lines[index+1])
		index += 2
		if len(header) < 2 || len(values) != len(header) ||
			header[0] != values[0] ||
			!strings.HasSuffix(header[0], ":") {
			parseErrors.Add(fmt.Errorf(
				"invalid SNMP header/value pair ending at line %d",
				index,
			))
			continue
		}
		protocol := strings.TrimSuffix(header[0], ":")
		if protocol != "Tcp" && protocol != "Udp" {
			continue
		}
		if _, duplicate := valuesByProtocol[protocol]; duplicate {
			parseErrors.Add(fmt.Errorf(
				"duplicate SNMP protocol %q",
				protocol,
			))
			continue
		}
		parsed := make(map[string]int64, len(header)-1)
		wanted := make(map[string]struct{})
		for _, spec := range snmpMetricSpecs {
			if spec.protocol == protocol {
				wanted[spec.field] = struct{}{}
			}
		}
		for fieldIndex := 1; fieldIndex < len(header); fieldIndex++ {
			field := header[fieldIndex]
			if _, supported := wanted[field]; !supported {
				continue
			}
			if _, duplicate := parsed[field]; duplicate {
				parseErrors.Add(fmt.Errorf(
					"%s duplicate field %q",
					protocol,
					field,
				))
				continue
			}
			value, err := parseNonNegativeInt63(values[fieldIndex])
			if err != nil {
				parseErrors.Add(fmt.Errorf(
					"%s %s: %w",
					protocol,
					field,
					err,
				))
				continue
			}
			parsed[field] = value
		}
		valuesByProtocol[protocol] = parsed
	}
	var series []model.Series
	for _, spec := range snmpMetricSpecs {
		value, exists := valuesByProtocol[spec.protocol][spec.field]
		if !exists {
			continue
		}
		if spec.gauge {
			series = append(series, gaugeInt(
				spec.name,
				"",
				ts,
				value,
				cloneLabels(visibleNetworkNamespaceAttrs),
			))
		} else {
			series = append(series, counterInt(
				spec.name,
				"",
				ts,
				value,
				cloneLabels(visibleNetworkNamespaceAttrs),
			))
		}
	}
	if len(series) == 0 && parseErrors.Empty() {
		parseErrors.Add(errors.New("SNMP contains no supported TCP/UDP fields"))
	}
	return series, parseErrors.Err()
}
