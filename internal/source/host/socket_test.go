package host

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
)

func TestSocketCollectorMetricContract(t *testing.T) {
	proc := t.TempDir()
	writeFixture(t, proc, "net/sockstat", strings.Join([]string{
		"sockets: used 5",
		"TCP: inuse 2 orphan 1 tw 3 alloc 4 mem 6",
		"UDP: inuse 7 mem 8",
		"RAW: inuse 1",
		"FRAG: inuse 2 memory 4096",
	}, "\n"))
	writeFixture(t, proc, "net/sockstat6", strings.Join([]string{
		"TCP6: inuse 9",
		"UDP6: inuse 10",
	}, "\n"))
	writeFixture(t, proc, "net/snmp", strings.Join([]string{
		"Tcp: ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors",
		"Tcp: 1 2 3 4 5 6 7 8 9 10 11",
		"Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors",
		"Udp: 12 13 14 15 16 17 18 19 20",
	}, "\n"))
	source := NewWithPaths(
		time.Second,
		[]string{"socket"},
		nil,
		Paths{ProcFS: proc},
		discardLogger(),
	)
	series, err := source.socket(123)
	if err != nil {
		t.Fatal(err)
	}
	byName := seriesByName(series)
	assertIntMetric(t, byName, "node_netstat_tcp_current_established", 5)
	assertIntMetric(
		t,
		byName,
		"node_netstat_tcp_segments_retransmitted_total",
		8,
	)
	assertIntMetric(
		t,
		byName,
		"node_netstat_udp_receive_buffer_errors_total",
		16,
	)
	assertIntMetric(
		t,
		byName,
		"node_socket_reassembly_memory_bytes",
		4096,
	)
	memoryBytes := findSocketSeries(
		t,
		byName["node_socket_memory_bytes"],
		"ipv4",
		"tcp",
	)
	if got := memoryBytes.Points[0].IntValue; got != 6*int64(os.Getpagesize()) {
		t.Errorf("TCP socket memory bytes = %d", got)
	}
	tcp6 := findSocketSeries(
		t,
		byName["node_socket_inuse"],
		"ipv6",
		"tcp",
	)
	if tcp6.Points[0].IntValue != 9 {
		t.Errorf("TCP6 inuse = %d, want 9", tcp6.Points[0].IntValue)
	}
	if byName["node_netstat_tcp_current_established"][0].Type != model.MetricGauge {
		t.Fatal("current established must be a gauge")
	}
	if byName["node_netstat_tcp_active_opens_total"][0].Type != model.MetricSum {
		t.Fatal("active opens must be a counter")
	}
}

func findSocketSeries(
	t *testing.T,
	series []model.Series,
	family string,
	protocol string,
) model.Series {
	t.Helper()
	for _, item := range series {
		gotFamily, _ := item.Attrs.Get("family")
		gotProtocol, _ := item.Attrs.Get("protocol")
		if gotFamily == family && gotProtocol == protocol {
			return item
		}
	}
	t.Fatalf(
		"missing socket series family=%s protocol=%s",
		family,
		protocol,
	)
	return model.Series{}
}

func TestSocketCollectorUnsupportedAndPartialFailure(t *testing.T) {
	proc := t.TempDir()
	source := NewWithPaths(
		time.Second,
		[]string{"socket"},
		nil,
		Paths{ProcFS: proc},
		discardLogger(),
	)
	if _, err := source.socket(1); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("missing socket files error = %v", err)
	}

	writeFixture(t, proc, "net/sockstat", "TCP: inuse malformed\n")
	writeFixture(t, proc, "net/snmp", strings.Join([]string{
		"Tcp: CurrEstab",
		"Tcp: 2",
	}, "\n"))
	series, err := source.socket(1)
	if err == nil {
		t.Fatal("malformed sockstat should be reported")
	}
	assertIntMetric(
		t,
		seriesByName(series),
		"node_netstat_tcp_current_established",
		2,
	)
}

func TestSocketParsersRejectMalformedInput(t *testing.T) {
	for _, data := range []string{
		"",
		"TCP inuse 1",
		"TCP: inuse",
		"TCP: inuse -1",
		"TCP: inuse 1\nTCP: inuse 2",
	} {
		if _, err := parseSockstat([]byte(data), "ipv4"); err == nil {
			t.Errorf("parseSockstat(%q) should fail", data)
		}
	}
	for _, data := range []string{
		"",
		"Tcp: CurrEstab",
		"Tcp: CurrEstab\nUdp: 1",
		"Tcp: CurrEstab\nTcp: -1",
	} {
		if _, err := parseSNMPSeries([]byte(data), 1); err == nil {
			t.Errorf("parseSNMPSeries(%q) should fail", data)
		}
	}
}

func FuzzParseSockstat(f *testing.F) {
	f.Add([]byte("TCP: inuse 2 orphan 1 tw 3 alloc 4 mem 6\n"))
	f.Add([]byte("malformed"))
	f.Fuzz(func(t *testing.T, data []byte) {
		records, _ := parseSockstat(data, "ipv4")
		if len(records) > 6 {
			t.Fatalf("records = %d, want at most 6 protocols", len(records))
		}
		for _, record := range records {
			if record.family != "ipv4" || record.protocol == "" {
				t.Fatalf("invalid record: %+v", record)
			}
			for key, value := range record.values {
				if key == "" || value < 0 {
					t.Fatalf("invalid value %q=%d", key, value)
				}
			}
		}
	})
}

func FuzzParseSNMPSeries(f *testing.F) {
	f.Add([]byte("Tcp: CurrEstab InSegs\nTcp: 1 2\n"))
	f.Add([]byte("malformed"))
	f.Fuzz(func(t *testing.T, data []byte) {
		series, _ := parseSNMPSeries(data, 1)
		if len(series) > len(snmpMetricSpecs) {
			t.Fatalf("series = %d, exceeds allowlist", len(series))
		}
		for _, item := range series {
			if item.Points[0].IntValue < 0 ||
				len(item.Attrs) != 1 {
				t.Fatalf("invalid SNMP series: %+v", item)
			}
			if scope, _ := item.Attrs.Get("network.scope"); scope != "visible_namespace" {
				t.Fatalf("invalid network scope: %+v", item)
			}
		}
	})
}
