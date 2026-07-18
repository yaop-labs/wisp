package host

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestParseMountinfoDecodesAndDeduplicates(t *testing.T) {
	data := strings.Join([]string{
		"10 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw",
		"11 1 8:2 / /data\\040disk ro,relatime shared:1 - xfs /dev/sdb1 ro",
		"12 1 0:1 / /proc rw - proc proc rw",
		"13 1 8:3 / / rw - ext4 /dev/newer rw",
	}, "\n")
	records, err := parseMountinfo([]byte(data), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("records = %d, want 3", len(records))
	}
	if records[0].mountpoint != "/" || records[0].device != "/dev/newer" {
		t.Errorf("overmount selection = %+v", records[0])
	}
	if records[1].mountpoint != "/data disk" || !records[1].readOnly {
		t.Errorf("escaped mount = %+v", records[1])
	}
}

func TestParseMountinfoReturnsValidRecordsWithErrors(t *testing.T) {
	data := strings.Join([]string{
		"10 1 8:1 / / rw - ext4 /dev/sda1 rw",
		"missing separator",
		"bad 1 8:2 / /data rw - xfs /dev/sdb1 rw",
	}, "\n")
	records, err := parseMountinfo([]byte(data), 10)
	if err == nil {
		t.Fatal("invalid mountinfo should be reported")
	}
	if len(records) != 1 || records[0].mountpoint != "/" {
		t.Fatalf("valid records = %+v", records)
	}
}

func TestDecodeMountField(t *testing.T) {
	decoded, err := decodeMountField(`/a\040b\011c\134d`)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != "/a b\tc\\d" {
		t.Errorf("decoded = %q", decoded)
	}
	for _, invalid := range []string{`\`, `\04`, `\999`, `a\000b`} {
		if _, err := decodeMountField(invalid); err == nil {
			t.Errorf("decodeMountField(%q) should fail", invalid)
		}
	}
}

func TestFilesystemTypeSafetyFilter(t *testing.T) {
	for _, fsType := range []string{
		"proc",
		"nfs4",
		"cifs",
		"fuse.sshfs",
		"cgroup2",
	} {
		if !isSkippedFilesystemType(fsType) {
			t.Errorf("%q should be skipped", fsType)
		}
	}
	for _, fsType := range []string{"ext4", "xfs", "btrfs", "overlay", "tmpfs"} {
		if isSkippedFilesystemType(fsType) {
			t.Errorf("%q should be eligible", fsType)
		}
	}
}

func TestFilesystemSeriesUsesExactIntegerGauges(t *testing.T) {
	mount := mountinfoRecord{
		mountpoint: "/data",
		fsType:     "ext4",
		device:     "/dev/sda1",
		readOnly:   true,
	}
	series, err := filesystemSeries(mount, unix.Statfs_t{
		Bsize:  4096,
		Blocks: 100,
		Bfree:  20,
		Bavail: 10,
		Files:  50,
		Ffree:  25,
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	byName := seriesByName(series)
	if got := byName["node_filesystem_size_bytes"][0].Points[0].IntValue; got != 409600 {
		t.Errorf("size = %d, want 409600", got)
	}
	if got := byName["node_filesystem_readonly"][0].Points[0].IntValue; got != 1 {
		t.Errorf("readonly = %d, want 1", got)
	}
	if got := byName["node_filesystem_device_error"][0].Points[0].IntValue; got != 0 {
		t.Errorf("device_error = %d, want 0", got)
	}
	for _, item := range series {
		if item.Points[0].IsFloat {
			t.Errorf("%s should use an integer point", item.Name)
		}
	}
}

func TestFilesystemCollectorUsesConfiguredRootsAndIsolatesMountErrors(t *testing.T) {
	proc := t.TempDir()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, proc, "1/mountinfo", strings.Join([]string{
		"10 1 8:1 / / rw - ext4 /dev/root rw",
		"11 1 8:2 / /data rw - xfs /dev/data rw",
		"12 1 8:3 / /missing rw - ext4 /dev/missing rw",
		"13 1 0:1 / /proc rw - proc proc rw",
	}, "\n"))
	source := NewWithPaths(
		time.Second,
		[]string{"filesystem"},
		nil,
		Paths{ProcFS: proc, RootFS: root},
		discardLogger(),
	)
	series, err := source.filesystem(1)
	if err == nil {
		t.Fatal("missing eligible mount should be reported")
	}
	byName := seriesByName(series)
	if got := len(byName["node_filesystem_size_bytes"]); got != 2 {
		t.Fatalf("successful filesystem size series = %d, want 2", got)
	}
	errors := byName["node_filesystem_device_error"]
	if len(errors) != 3 {
		t.Fatalf("device error series = %d, want 3", len(errors))
	}
	foundFailure := false
	for _, item := range errors {
		mountpoint, _ := item.Attrs.Get("mountpoint")
		if mountpoint == "/missing" && item.Points[0].IntValue == 1 {
			foundFailure = true
		}
	}
	if !foundFailure {
		t.Fatal("missing mount did not emit device_error=1")
	}
}

func TestFilesystemCollectorFallsBackToSelfMountinfo(t *testing.T) {
	proc := t.TempDir()
	root := t.TempDir()
	writeFixture(
		t,
		proc,
		"self/mountinfo",
		"10 1 8:1 / / rw - ext4 /dev/root rw\n",
	)
	source := NewWithPaths(
		time.Second,
		[]string{"filesystem"},
		nil,
		Paths{ProcFS: proc, RootFS: root},
		discardLogger(),
	)
	series, err := source.filesystem(1)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(seriesByName(series)["node_filesystem_size_bytes"]); got != 1 {
		t.Fatalf("filesystem size series = %d, want 1", got)
	}
}

func TestFilesystemBoundsOverflow(t *testing.T) {
	if _, err := filesystemBytes(math.MaxUint64, 4096); err == nil {
		t.Fatal("overflow should fail")
	}
}

func FuzzParseMountinfo(f *testing.F) {
	f.Add([]byte("10 1 8:1 / / rw - ext4 /dev/sda1 rw\n"))
	f.Add([]byte("missing separator"))
	f.Fuzz(func(t *testing.T, data []byte) {
		records, err := parseMountinfo(data, 32)
		if len(records) > 32 {
			t.Fatalf("records = %d, want at most 32", len(records))
		}
		previous := ""
		for _, record := range records {
			if !filepath.IsAbs(record.mountpoint) {
				t.Fatalf("non-absolute mountpoint %q", record.mountpoint)
			}
			if previous != "" && previous >= record.mountpoint {
				t.Fatalf(
					"mountpoints not strictly sorted: %q then %q",
					previous,
					record.mountpoint,
				)
			}
			previous = record.mountpoint
			if record.fsType == "" ||
				len(record.fsType) > maxMountFieldBytes ||
				len(record.device) > maxMountFieldBytes {
				t.Fatalf("invalid mount metadata: %+v", record)
			}
		}
		if err == nil && len(records) == 0 {
			t.Fatal("successful parse returned no records")
		}
	})
}
