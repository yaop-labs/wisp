package host

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
)

func TestCgroupV2ConfiguredRootMetricContract(t *testing.T) {
	root := t.TempDir()
	fixtures := map[string]string{
		"cgroup.controllers": "",
		"cpu.stat": strings.Join([]string{
			"usage_usec 100",
			"user_usec 60",
			"system_usec 40",
			"nr_periods 10",
			"nr_throttled 2",
			"throttled_usec 7",
		}, "\n"),
		"cpu.max":             "20000 100000\n",
		"cpu.weight":          "100\n",
		"memory.current":      "4096\n",
		"memory.max":          "8192\n",
		"memory.swap.current": "1024\n",
		"memory.swap.max":     "max\n",
		"memory.events": strings.Join([]string{
			"low 1",
			"high 2",
			"max 3",
			"oom 4",
			"oom_kill 5",
			"oom_group_kill 6",
		}, "\n"),
		"pids.current": "12\n",
		"pids.max":     "max\n",
		"io.stat":      "8:0 rbytes=100 wbytes=200 rios=3 wios=4 dbytes=5 dios=6\n",
	}
	for name, contents := range fixtures {
		writeFixture(t, root, name, contents)
	}
	source := NewWithPaths(
		time.Second,
		[]string{"cgroup"},
		nil,
		Paths{CgroupFS: root},
		discardLogger(),
	)
	series, err := source.cgroup(123)
	if err != nil {
		t.Fatal(err)
	}
	byName := seriesByName(series)
	assertIntMetric(t, byName, "node_cgroup_v2_info", 1)
	assertIntMetric(
		t,
		byName,
		"node_cgroup_cpu_usage_microseconds_total",
		100,
	)
	assertIntMetric(
		t,
		byName,
		"node_cgroup_cpu_quota_microseconds",
		20000,
	)
	assertIntMetric(
		t,
		byName,
		"node_cgroup_cpu_period_microseconds",
		100000,
	)
	assertIntMetric(
		t,
		byName,
		"node_cgroup_memory_current_bytes",
		4096,
	)
	assertIntMetric(
		t,
		byName,
		"node_cgroup_memory_limit_bytes",
		8192,
	)
	assertIntMetric(
		t,
		byName,
		"node_cgroup_memory_swap_limit_unlimited",
		1,
	)
	assertIntMetric(t, byName, "node_cgroup_pids_current", 12)
	assertIntMetric(t, byName, "node_cgroup_pids_limit_unlimited", 1)
	assertIntMetric(
		t,
		byName,
		"node_cgroup_io_written_bytes_total",
		200,
	)
	events := byName["node_cgroup_memory_events_total"]
	if len(events) != 6 {
		t.Fatalf("memory event series = %d, want 6", len(events))
	}
	for _, item := range series {
		if got, _ := item.Attrs.Get("cgroup.scope"); got != "configured_root" {
			t.Errorf("%s cgroup.scope = %q", item.Name, got)
		}
	}
	ioMetric := byName["node_cgroup_io_read_bytes_total"][0]
	if got, _ := ioMetric.Attrs.Get("device"); got != "8:0" {
		t.Errorf("I/O device = %q, want 8:0", got)
	}
}

func assertIntMetric(
	t *testing.T,
	byName map[string][]model.Series,
	name string,
	want int64,
) {
	t.Helper()
	items := byName[name]
	if len(items) == 0 {
		t.Fatalf("missing metric %s", name)
	}
	point := items[0].Points[0]
	if point.IsFloat || point.IntValue != want {
		t.Errorf("%s point = %+v, want integer %d", name, point, want)
	}
}

func TestCgroupV2UnsupportedAndPartialFailure(t *testing.T) {
	root := t.TempDir()
	source := NewWithPaths(
		time.Second,
		[]string{"cgroup"},
		nil,
		Paths{CgroupFS: root},
		discardLogger(),
	)
	if _, err := source.cgroup(1); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("missing cgroup v2 error = %v", err)
	}

	writeFixture(t, root, "cgroup.controllers", "cpu memory\n")
	writeFixture(t, root, "cpu.stat", "usage_usec malformed\n")
	writeFixture(t, root, "memory.current", "42\n")
	series, err := source.cgroup(1)
	if err == nil {
		t.Fatal("malformed cpu.stat should be reported")
	}
	byName := seriesByName(series)
	assertIntMetric(t, byName, "node_cgroup_v2_info", 1)
	assertIntMetric(t, byName, "node_cgroup_memory_current_bytes", 42)
}

func TestCgroupParsersRejectMalformedAndDuplicateData(t *testing.T) {
	for _, data := range []string{"", "key", "key 1\nkey 2", "key -1"} {
		if _, err := parseCgroupKeyValues([]byte(data)); err == nil {
			t.Errorf("parseCgroupKeyValues(%q) should fail", data)
		}
	}
	for _, data := range []string{"", "max", "max 0", "-1 100000"} {
		if _, err := cgroupCPUMaxSeries([]byte(data), 1); err == nil {
			t.Errorf("cgroupCPUMaxSeries(%q) should fail", data)
		}
	}
	if _, err := cgroupIOStatSeries(
		[]byte("bad rbytes=1\n"),
		1,
	); err == nil {
		t.Fatal("invalid io.stat device should fail")
	}
}

func TestCgroupPermissionFailureIsOperational(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "cgroup.controllers", "cpu\n")
	if err := os.Chmod(
		root+"/cgroup.controllers",
		0,
	); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(root+"/cgroup.controllers", 0o600)
	})
	if os.Geteuid() == 0 {
		t.Skip("root bypasses fixture permissions")
	}
	source := NewWithPaths(
		time.Second,
		[]string{"cgroup"},
		nil,
		Paths{CgroupFS: root},
		discardLogger(),
	)
	if _, err := source.cgroup(1); err == nil ||
		errors.Is(err, ErrUnsupported) {
		t.Fatalf("permission error = %v, want operational error", err)
	}
}

func FuzzParseCgroupIOStat(f *testing.F) {
	f.Add([]byte("8:0 rbytes=100 wbytes=200 rios=3 wios=4\n"))
	f.Add([]byte("bad"))
	f.Fuzz(func(t *testing.T, data []byte) {
		series, _ := cgroupIOStatSeries(data, 1)
		if len(series) > maxCgroupIODevices*6 {
			t.Fatalf("series = %d, exceeds bound", len(series))
		}
		for _, item := range series {
			if item.Type != model.MetricSum ||
				!item.Monotonic ||
				item.Points[0].IntValue < 0 {
				t.Fatalf("invalid cgroup I/O series: %+v", item)
			}
			if _, ok := item.Attrs.Get("device"); !ok {
				t.Fatalf("missing device attribute: %+v", item)
			}
		}
	})
}
