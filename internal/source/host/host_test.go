package host

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/selfobs"
)

func TestCollectorWorkerNeverDuplicatesHungAttempt(t *testing.T) {
	var worker collectorWorker
	var calls atomic.Int64
	release := make(chan struct{})
	collect := func(uint64) ([]model.Series, error) {
		calls.Add(1)
		<-release
		return []model.Series{gaugeInt("test", "", 1, 1, nil)}, nil
	}
	done, started := worker.start(collect, 1)
	if !started {
		t.Fatal("first attempt did not start")
	}
	if _, started := worker.start(collect, 2); started {
		t.Fatal("second attempt started while first was in flight")
	}
	deadline := time.Now().Add(time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if calls.Load() != 1 {
		t.Fatalf("collector calls = %d, want 1", calls.Load())
	}
	close(release)
	select {
	case result := <-done:
		if result.err != nil || len(result.series) != 1 {
			t.Fatalf("collector result = %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("collector did not finish")
	}
	deadline = time.Now().Add(time.Second)
	for {
		done, started = worker.start(
			func(uint64) ([]model.Series, error) {
				calls.Add(1)
				return nil, nil
			},
			3,
		)
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker never became available")
		}
		runtime.Gosched()
	}
	<-done
	if calls.Load() != 2 {
		t.Fatalf("collector calls after recovery = %d, want 2", calls.Load())
	}
}

func TestCollectionCycleBoundsHungCollectorAndKeepsHealthyData(t *testing.T) {
	release := make(chan struct{})
	source := &Source{
		timeout: 20 * time.Millisecond,
		logger:  discardLogger(),
		workers: map[string]*collectorWorker{
			"fast": {},
			"hung": {},
		},
		durations: make(map[string]float64),
		success:   make(map[string]float64),
		states:    make(map[string]string),
	}
	source.collectorEntries = []collectorEntry{
		{
			name: "fast",
			collect: func(ts uint64) ([]model.Series, error) {
				return []model.Series{
					gaugeInt("healthy", "", ts, 1, nil),
				}, nil
			},
		},
		{
			name: "hung",
			collect: func(uint64) ([]model.Series, error) {
				<-release
				return nil, nil
			},
		},
	}
	timeoutsBefore := selfobs.HostCollectorTimeouts.Get()
	var batch model.Batch
	collectWithinTestDeadline(t, source, &batch)
	if len(batch.Series) != 1 || batch.Series[0].Name != "healthy" {
		t.Fatalf("healthy collector data was lost: %+v", batch)
	}
	if got := selfobs.HostCollectorTimeouts.Get(); got != timeoutsBefore+1 {
		t.Fatalf("timeouts = %d, want %d", got, timeoutsBefore+1)
	}

	// The next cycle must not spawn or wait on another hung attempt.
	collectWithinTestDeadline(t, source, &batch)
	if len(batch.Series) != 1 || batch.Series[0].Name != "healthy" {
		t.Fatalf("second-cycle healthy data was lost: %+v", batch)
	}
	close(release)
}

func collectWithinTestDeadline(t *testing.T, source *Source, batch *model.Batch) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		defer close(done)
		source.collectAndEmit(
			context.Background(),
			func(_ context.Context, emitted model.Batch) error {
				*batch = emitted
				return nil
			},
		)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("collection cycle did not return within the test deadline")
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func collectOnce(t *testing.T) model.Batch {
	t.Helper()
	s := New(
		time.Hour,
		nil,
		model.Labels{{Name: "service.name", Value: "wisp"}},
		discardLogger(),
	)

	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan model.Batch, 1)
	emit := func(_ context.Context, b model.Batch) error {
		select {
		case got <- b:
		default:
		}
		cancel() // stop after the immediate first collection
		return nil
	}
	_ = s.Start(ctx, emit)

	select {
	case b := <-got:
		return b
	default:
		t.Fatal("no batch emitted")
		return model.Batch{}
	}
}

func writeFixture(t *testing.T, root, name, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", path, err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func seriesByName(series []model.Series) map[string][]model.Series {
	result := make(map[string][]model.Series)
	for _, item := range series {
		result[item.Name] = append(result[item.Name], item)
	}
	return result
}

func TestCollectorsReadConfiguredProcFS(t *testing.T) {
	proc := t.TempDir()
	writeFixture(t, proc, "loadavg", "1.25 2.50 3.75 1/1 1\n")
	writeFixture(t, proc, "meminfo", strings.Join([]string{
		"MemTotal: 1024 kB",
		"MemFree: 512 kB",
		"MemAvailable: 768 kB",
		"Cached: 64 kB",
		"Buffers: 32 kB",
	}, "\n"))
	writeFixture(t, proc, "stat", strings.Join([]string{
		"cpu  10 20 30 40",
		"cpu0 100 2 30 400 5 6 7 8",
	}, "\n"))
	writeFixture(t, proc, "net/dev", strings.Join([]string{
		"Inter-| Receive | Transmit",
		" face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed",
		"eth0: 123 1 0 0 0 0 0 0 456 1 0 0 0 0 0 0",
	}, "\n"))

	source := NewWithPaths(
		time.Second,
		[]string{"load", "memory", "cpu", "network"},
		nil,
		Paths{ProcFS: proc},
		discardLogger(),
	)
	const ts = uint64(10)
	var all []model.Series
	for _, collect := range []func(uint64) ([]model.Series, error){
		source.load,
		source.memory,
		source.cpu,
		source.network,
	} {
		series, err := collect(ts)
		if err != nil {
			t.Fatalf("collect fixture: %v", err)
		}
		all = append(all, series...)
	}
	byName := seriesByName(all)
	if got := byName["node_load1"][0].Points[0].Value(); got != 1.25 {
		t.Errorf("node_load1 = %v, want 1.25", got)
	}
	if got := byName["node_memory_MemTotal_bytes"][0].Points[0].Value(); got != 1024*1024 {
		t.Errorf("node_memory_MemTotal_bytes = %v, want %v", got, 1024*1024)
	}
	cpu := byName["node_cpu_milliseconds_total"][0]
	if got := cpu.Points[0].IntValue; got != 1000 {
		t.Errorf("first CPU value = %d, want 1000ms", got)
	}
	if got, _ := cpu.Attrs.Get("cpu"); got != "0" {
		t.Errorf("CPU attribute = %q, want 0", got)
	}
	if got := byName["node_network_receive_bytes_total"][0].Points[0].IntValue; got != 123 {
		t.Errorf("receive bytes = %d, want 123", got)
	}
	if got := byName["node_network_transmit_bytes_total"][0].Points[0].IntValue; got != 456 {
		t.Errorf("transmit bytes = %d, want 456", got)
	}
}

func TestUptimeCollector(t *testing.T) {
	proc := t.TempDir()
	writeFixture(t, proc, "uptime", "123.5 42.0\n")
	source := NewWithPaths(
		time.Second,
		[]string{"uptime"},
		nil,
		Paths{ProcFS: proc},
		discardLogger(),
	)
	series, err := source.uptime(200 * timeSecond)
	if err != nil {
		t.Fatal(err)
	}
	byName := seriesByName(series)
	if got := byName["node_uptime_seconds"][0].Points[0].Value(); got != 123.5 {
		t.Errorf("uptime = %v, want 123.5", got)
	}
	if got := byName["node_boot_time_seconds"][0].Points[0].Value(); got != 76.5 {
		t.Errorf("boot time = %v, want 76.5", got)
	}

	writeFixture(t, proc, "uptime", "NaN 1\n")
	if _, err := source.uptime(0); err == nil {
		t.Fatal("NaN uptime should fail")
	}
}

func TestParsePressure(t *testing.T) {
	records, err := parsePressure([]byte(strings.Join([]string{
		"some avg10=0.50 avg60=1.25 avg300=2.50 total=12345",
		"full avg10=0.00 avg60=0.10 avg300=0.20 total=42",
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	if math.Abs(records[0].avg60-0.0125) > 1e-12 {
		t.Errorf("avg60 = %v, want 0.0125", records[0].avg60)
	}
	if records[0].total != 12345 || records[1].scope != "full" {
		t.Errorf("unexpected records: %+v", records)
	}

	for _, input := range []string{
		"",
		"some avg10=101 avg60=1 avg300=1 total=1",
		"some avg10=1 avg60=1 avg300=1",
		"some avg10=1 avg60=1 avg300=1 total=1\nsome avg10=1 avg60=1 avg300=1 total=2",
		"other avg10=1 avg60=1 avg300=1 total=1",
	} {
		if _, err := parsePressure([]byte(input)); err == nil {
			t.Errorf("parsePressure(%q) should fail", input)
		}
	}
}

func TestPressureCollectorAndUnsupportedKernel(t *testing.T) {
	proc := t.TempDir()
	source := NewWithPaths(
		time.Second,
		[]string{"pressure"},
		nil,
		Paths{ProcFS: proc},
		discardLogger(),
	)
	if _, err := source.pressure(1); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("missing PSI error = %v, want ErrUnsupported", err)
	}

	writeFixture(
		t,
		proc,
		"pressure/cpu",
		"some avg10=0.50 avg60=1.25 avg300=2.50 total=12345\n",
	)
	series, err := source.pressure(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 4 {
		t.Fatalf("CPU PSI series = %d, want 4", len(series))
	}
	total := seriesByName(series)["node_pressure_cpu_waiting_microseconds_total"][0]
	if total.Points[0].IntValue != 12345 || total.Unit != "us" {
		t.Errorf("unexpected PSI total: %+v", total)
	}
}

func TestCollectionIsolatesCollectorFailuresAndPublishesStats(t *testing.T) {
	proc := t.TempDir()
	writeFixture(t, proc, "loadavg", "1 2 3 1/1 1\n")
	source := NewWithPaths(
		time.Second,
		[]string{"load", "pressure"},
		model.Labels{{Name: "host.name", Value: "fixture"}},
		Paths{ProcFS: proc},
		discardLogger(),
	)
	unsupportedBefore := selfobs.HostCollectorUnsupported.Get()
	var batch model.Batch
	source.collectAndEmit(
		context.Background(),
		func(_ context.Context, emitted model.Batch) error {
			batch = emitted
			return nil
		},
	)
	if len(batch.Series) != 3 {
		t.Fatalf("emitted series = %d, want the 3 healthy load series", len(batch.Series))
	}
	for _, item := range batch.Series {
		if got, _ := item.Resource.Get("host.name"); got != "fixture" {
			t.Errorf("resource host.name = %q, want fixture", got)
		}
	}
	if got := source.successSnapshot(); got["load"] != 1 || got["pressure"] != 0 {
		t.Errorf("success snapshot = %v", got)
	}
	if got := selfobs.HostCollectorUnsupported.Get(); got != unsupportedBefore+1 {
		t.Errorf("unsupported counter = %d, want %d", got, unsupportedBefore+1)
	}
	recorder := httptest.NewRecorder()
	selfobs.Handler().ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodGet, "/metrics", nil),
	)
	for _, want := range []string{
		`wisp_host_collector_success{collector="load"} 1`,
		`wisp_host_collector_success{collector="pressure"} 0`,
		`wisp_host_collector_duration_seconds{collector="load"}`,
	} {
		if !strings.Contains(recorder.Body.String(), want) {
			t.Errorf("self metrics missing %q", want)
		}
	}

	snapshot := source.successSnapshot()
	snapshot["load"] = 0
	if source.successSnapshot()["load"] != 1 {
		t.Fatal("snapshot mutation changed source state")
	}
}

func TestNewWithPathsFillsOnlyMissingDefaults(t *testing.T) {
	source := NewWithPaths(
		time.Second,
		[]string{"load"},
		nil,
		Paths{ProcFS: "/host/proc"},
		discardLogger(),
	)
	if source.paths.ProcFS != "/host/proc" {
		t.Errorf("ProcFS = %q", source.paths.ProcFS)
	}
	defaults := DefaultPaths()
	if source.paths.SysFS != defaults.SysFS ||
		source.paths.RootFS != defaults.RootFS ||
		source.paths.CgroupFS != defaults.CgroupFS {
		t.Errorf("defaults not filled: %+v", source.paths)
	}
}

func TestReadBoundedFileRejectsOversizedVirtualFile(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "large", "12345")
	if _, err := readBoundedFile(filepath.Join(root, "large"), 4); err == nil {
		t.Fatal("oversized virtual file should fail")
	}
}

func TestUnameCollector(t *testing.T) {
	source := New(time.Second, []string{"uname"}, nil, discardLogger())
	series, err := source.uname(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 1 || series[0].Name != "node_uname_info" {
		t.Fatalf("unexpected uname series: %+v", series)
	}
	for _, name := range []string{
		"sysname",
		"nodename",
		"release",
		"version",
		"machine",
		"domainname",
	} {
		if _, ok := series[0].Attrs.Get(name); !ok {
			t.Errorf("node_uname_info missing %q", name)
		}
	}
}

func FuzzParsePressure(f *testing.F) {
	f.Add([]byte("some avg10=0.50 avg60=1.25 avg300=2.50 total=12345\n"))
	f.Add([]byte("full avg10=0 avg60=0 avg300=100 total=0\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		records, err := parsePressure(data)
		if err != nil {
			return
		}
		if len(records) == 0 || len(records) > 2 {
			t.Fatalf("successful parse returned %d records", len(records))
		}
		seen := make(map[string]bool, len(records))
		for _, record := range records {
			if record.scope != "some" && record.scope != "full" {
				t.Fatalf("invalid scope %q", record.scope)
			}
			if seen[record.scope] {
				t.Fatalf("duplicate scope %q", record.scope)
			}
			seen[record.scope] = true
			for _, average := range []float64{
				record.avg10,
				record.avg60,
				record.avg300,
			} {
				if math.IsNaN(average) ||
					math.IsInf(average, 0) ||
					average < 0 ||
					average > 1 {
					t.Fatalf("invalid average %v", average)
				}
			}
			if record.total > math.MaxInt64 {
				t.Fatalf("total does not fit int64: %d", record.total)
			}
		}
	})
}

func TestHostCollectEmitsSeries(t *testing.T) {
	b := collectOnce(t)
	if b.Len() == 0 {
		t.Fatal("expected at least one data point from host collectors")
	}

	byName := map[string]model.Series{}
	for _, s := range b.Series {
		byName[s.Name] = s
		if len(s.Resource) == 0 || s.Resource[0].Name != "service.name" {
			t.Errorf("series %q missing stamped resource", s.Name)
		}
	}

	// /proc/loadavg exists on any Linux test host.
	load, ok := byName["node_load1"]
	if !ok {
		t.Fatal("expected node_load1 series")
	}
	if load.Type != model.MetricGauge {
		t.Errorf("node_load1 type = %v, want gauge", load.Type)
	}

	// cpu is a monotonic integer counter (ms) with cpu/mode attributes.
	if cpu, ok := byName["node_cpu_milliseconds_total"]; ok {
		if cpu.Type != model.MetricSum || !cpu.Monotonic {
			t.Errorf("node_cpu_milliseconds_total should be a monotonic sum")
		}
		if len(cpu.Points) > 0 && cpu.Points[0].IsFloat {
			t.Errorf("node_cpu_milliseconds_total should be an integer counter, not float")
		}
		if len(cpu.Attrs) != 2 {
			t.Errorf("node_cpu_milliseconds_total should carry cpu+mode attrs, got %d", len(cpu.Attrs))
		}
	}
}
