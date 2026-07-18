package host

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

func TestBoundedErrorsCapsReportedDetails(t *testing.T) {
	var collected boundedErrors
	if !collected.Empty() || collected.Err() != nil {
		t.Fatal("zero boundedErrors should be empty")
	}
	for index := 0; index < maxReportedCollectorErrors+5; index++ {
		collected.Add(errors.New("failure"))
	}
	err := collected.Err()
	if err == nil || !strings.Contains(
		err.Error(),
		"5 additional errors omitted",
	) {
		t.Fatalf("bounded error = %v", err)
	}
	if got := strings.Count(err.Error(), "failure"); got != maxReportedCollectorErrors {
		t.Fatalf("reported failures = %d, want %d", got, maxReportedCollectorErrors)
	}
}

func TestParseDiskstatsAndMetricContract(t *testing.T) {
	const line = "8 0 sda 10 2 3 4 20 5 6 7 1 8 9 30 4 5 6 40 7\n"
	records, err := parseDiskstats([]byte(line), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	series := seriesByName(diskSeries(records[0], 123))
	if got := series["node_disk_read_bytes_total"][0].Points[0].IntValue; got != 3*512 {
		t.Errorf("read bytes = %d, want %d", got, 3*512)
	}
	if got := series["node_disk_written_bytes_total"][0].Points[0].IntValue; got != 6*512 {
		t.Errorf("written bytes = %d, want %d", got, 6*512)
	}
	if got := series["node_disk_discarded_bytes_total"][0].Points[0].IntValue; got != 5*512 {
		t.Errorf("discarded bytes = %d, want %d", got, 5*512)
	}
	if got := series["node_disk_flush_requests_completed_total"][0].Points[0].IntValue; got != 40 {
		t.Errorf("flush requests = %d, want 40", got)
	}
	ioNow := series["node_disk_io_now"][0]
	if ioNow.Monotonic || ioNow.Points[0].IntValue != 1 {
		t.Errorf("unexpected io_now gauge: %+v", ioNow)
	}
	for _, item := range diskSeries(records[0], 123) {
		if got, _ := item.Attrs.Get("device"); got != "sda" {
			t.Errorf("%s device = %q", item.Name, got)
		}
		if got, _ := item.Attrs.Get("major"); got != "8" {
			t.Errorf("%s major = %q", item.Name, got)
		}
	}
}

func TestParseDiskstatsSupportsBaseKernelFields(t *testing.T) {
	records, err := parseDiskstats(
		[]byte("7 0 loop0 1 2 3 4 5 6 7 8 0 9 10\n"),
		10,
	)
	if err != nil {
		t.Fatal(err)
	}
	series := diskSeries(records[0], 1)
	if len(series) != 11 {
		t.Fatalf("base diskstats series = %d, want 11", len(series))
	}
}

func TestParseDiskstatsReturnsValidRecordsWithErrors(t *testing.T) {
	data := strings.Join([]string{
		"8 0 sda 1 2 3 4 5 6 7 8 0 9 10",
		"malformed",
		"8 1 sda1 1 2 -3 4 5 6 7 8 0 9 10",
	}, "\n")
	records, err := parseDiskstats([]byte(data), 10)
	if err == nil {
		t.Fatal("malformed records should be reported")
	}
	if len(records) != 1 || records[0].device != "sda" {
		t.Fatalf("valid records = %+v, want sda", records)
	}
}

func TestParseDiskstatsBoundsDevices(t *testing.T) {
	data := []byte(strings.Join([]string{
		"8 0 sda 1 2 3 4 5 6 7 8 0 9 10",
		"8 1 sdb 1 2 3 4 5 6 7 8 0 9 10",
	}, "\n"))
	records, err := parseDiskstats(data, 1)
	if err == nil || len(records) != 1 {
		t.Fatalf("limit result records=%d err=%v", len(records), err)
	}
}

func TestParseDiskstatsRejectsSectorByteOverflow(t *testing.T) {
	overflow := int64(math.MaxInt64/512 + 1)
	input := "8 0 sda 1 2 " +
		strconv.FormatInt(overflow, 10) +
		" 4 5 6 7 8 0 9 10\n"
	if records, err := parseDiskstats([]byte(input), 10); err == nil || len(records) != 0 {
		t.Fatalf("overflow records=%d err=%v", len(records), err)
	}
}

func FuzzParseDiskstats(f *testing.F) {
	f.Add([]byte("8 0 sda 1 2 3 4 5 6 7 8 0 9 10\n"))
	f.Add([]byte("malformed"))
	f.Fuzz(func(t *testing.T, data []byte) {
		records, err := parseDiskstats(data, 32)
		if len(records) > 32 {
			t.Fatalf("records = %d, want at most 32", len(records))
		}
		for _, record := range records {
			if record.device == "" || len(record.device) > 255 {
				t.Fatalf("invalid device %q", record.device)
			}
			if record.major < 0 || record.minor < 0 {
				t.Fatalf("negative device numbers: %+v", record)
			}
			if len(record.values) != 11 &&
				len(record.values) != 15 &&
				len(record.values) != 17 {
				t.Fatalf("unexpected value count %d", len(record.values))
			}
			for _, value := range record.values {
				if value < 0 {
					t.Fatalf("negative diskstats value %d", value)
				}
			}
		}
		if err == nil && len(records) == 0 {
			t.Fatal("successful parse returned no records")
		}
	})
}
