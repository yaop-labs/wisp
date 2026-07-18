package host

import (
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/yaop-labs/wisp/internal/model"
)

const (
	maxMountinfoBytes   = 8 << 20
	maxMountinfoRecords = 8192
	maxFilesystemMounts = 4096
	maxMountFieldBytes  = 4096
)

type mountinfoRecord struct {
	id         int64
	mountpoint string
	fsType     string
	device     string
	readOnly   bool
}

var skippedFilesystemTypes = map[string]struct{}{
	"autofs":      {},
	"binfmt_misc": {},
	"bpf":         {},
	"cgroup":      {},
	"cgroup2":     {},
	"configfs":    {},
	"debugfs":     {},
	"devpts":      {},
	"devtmpfs":    {},
	"efivarfs":    {},
	"fuse":        {},
	"fuseblk":     {},
	"fusectl":     {},
	"hugetlbfs":   {},
	"mqueue":      {},
	"nsfs":        {},
	"proc":        {},
	"pstore":      {},
	"ramfs":       {},
	"securityfs":  {},
	"sysfs":       {},
	"tracefs":     {},
	"9p":          {},
	"afs":         {},
	"ceph":        {},
	"cifs":        {},
	"glusterfs":   {},
	"lustre":      {},
	"nfs":         {},
	"nfs4":        {},
	"smb3":        {},
}

func (s *Source) filesystem(ts uint64) ([]model.Series, error) {
	data, err := readBoundedFile(
		s.procPath("1", "mountinfo"),
		maxMountinfoBytes,
	)
	if err != nil {
		pidOneErr := err
		data, err = readBoundedFile(
			s.procPath("self", "mountinfo"),
			maxMountinfoBytes,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"read PID 1 and self mountinfo: %w",
				errors.Join(pidOneErr, err),
			)
		}
	}
	mounts, parseErr := parseMountinfo(data, maxMountinfoRecords)
	var series []model.Series
	var collectionErrors boundedErrors
	collectionErrors.Add(parseErr)
	eligible := make([]mountinfoRecord, 0, len(mounts))
	for _, mount := range mounts {
		if isSkippedFilesystemType(mount.fsType) {
			continue
		}
		eligible = append(eligible, mount)
	}
	if len(eligible) > maxFilesystemMounts {
		collectionErrors.Add(
			fmt.Errorf(
				"filesystem collector exceeds %d eligible mounts",
				maxFilesystemMounts,
			),
		)
		eligible = eligible[:maxFilesystemMounts]
	}
	for _, mount := range eligible {
		path, err := s.rootPath(mount.mountpoint)
		if err != nil {
			collectionErrors.Add(
				fmt.Errorf(
					"filesystem %q path: %w",
					mount.mountpoint,
					err,
				),
			)
			series = append(
				series,
				filesystemErrorSeries(mount, ts),
			)
			continue
		}
		var stat unix.Statfs_t
		if err := unix.Statfs(path, &stat); err != nil {
			collectionErrors.Add(
				fmt.Errorf(
					"statfs %q: %w",
					mount.mountpoint,
					err,
				),
			)
			series = append(
				series,
				filesystemErrorSeries(mount, ts),
			)
			continue
		}
		collected, err := filesystemSeries(mount, stat, ts)
		if err != nil {
			collectionErrors.Add(
				fmt.Errorf(
					"filesystem %q: %w",
					mount.mountpoint,
					err,
				),
			)
			series = append(
				series,
				filesystemErrorSeries(mount, ts),
			)
			continue
		}
		series = append(series, collected...)
	}
	if len(eligible) == 0 && collectionErrors.Empty() {
		collectionErrors.Add(
			fmt.Errorf(
				"%w: mountinfo contains no eligible local filesystems",
				ErrUnsupported,
			),
		)
	}
	return series, collectionErrors.Err()
}

func parseMountinfo(
	data []byte,
	maxRecords int,
) ([]mountinfoRecord, error) {
	byMountpoint := make(map[string]mountinfoRecord)
	var parseErrors boundedErrors
	recordsSeen := 0
	for lineNumber, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		recordsSeen++
		if recordsSeen > maxRecords {
			parseErrors.Add(
				fmt.Errorf("mountinfo exceeds %d records", maxRecords),
			)
			break
		}
		before, after, ok := strings.Cut(line, " - ")
		if !ok {
			parseErrors.Add(
				fmt.Errorf(
					"mountinfo line %d: missing separator",
					lineNumber+1,
				),
			)
			continue
		}
		left := strings.Fields(before)
		right := strings.Fields(after)
		if len(left) < 6 || len(right) < 3 {
			parseErrors.Add(
				fmt.Errorf(
					"mountinfo line %d: missing required fields",
					lineNumber+1,
				),
			)
			continue
		}
		id, err := parseNonNegativeInt63(left[0])
		if err != nil {
			parseErrors.Add(
				fmt.Errorf(
					"mountinfo line %d ID: %w",
					lineNumber+1,
					err,
				),
			)
			continue
		}
		mountpoint, err := decodeMountField(left[4])
		if err != nil || !filepath.IsAbs(mountpoint) {
			parseErrors.Add(
				fmt.Errorf(
					"mountinfo line %d mountpoint %q: invalid absolute path",
					lineNumber+1,
					left[4],
				),
			)
			continue
		}
		fsType, err := decodeMountField(right[0])
		if err != nil || fsType == "" {
			parseErrors.Add(
				fmt.Errorf(
					"mountinfo line %d filesystem type: invalid value",
					lineNumber+1,
				),
			)
			continue
		}
		device, err := decodeMountField(right[1])
		if err != nil {
			parseErrors.Add(
				fmt.Errorf(
					"mountinfo line %d device: invalid value",
					lineNumber+1,
				),
			)
			continue
		}
		record := mountinfoRecord{
			id:         id,
			mountpoint: filepath.Clean(mountpoint),
			fsType:     fsType,
			device:     device,
			readOnly:   mountOption(left[5], "ro"),
		}
		previous, exists := byMountpoint[record.mountpoint]
		if !exists || previous.id < record.id {
			byMountpoint[record.mountpoint] = record
		}
	}
	mountpoints := make([]string, 0, len(byMountpoint))
	for mountpoint := range byMountpoint {
		mountpoints = append(mountpoints, mountpoint)
	}
	slices.Sort(mountpoints)
	records := make([]mountinfoRecord, 0, len(mountpoints))
	for _, mountpoint := range mountpoints {
		records = append(records, byMountpoint[mountpoint])
	}
	if len(records) == 0 && parseErrors.Empty() {
		parseErrors.Add(errors.New("mountinfo contains no mounts"))
	}
	return records, parseErrors.Err()
}

func decodeMountField(raw string) (string, error) {
	if len(raw) > maxMountFieldBytes {
		return "", fmt.Errorf(
			"mount field exceeds %d bytes",
			maxMountFieldBytes,
		)
	}
	var decoded strings.Builder
	decoded.Grow(len(raw))
	for index := 0; index < len(raw); index++ {
		if raw[index] != '\\' {
			if raw[index] == 0 {
				return "", errors.New("mount field contains NUL")
			}
			decoded.WriteByte(raw[index])
			continue
		}
		if index+3 >= len(raw) {
			return "", errors.New("truncated mount field escape")
		}
		value := byte(0)
		for offset := 1; offset <= 3; offset++ {
			digit := raw[index+offset]
			if digit < '0' || digit > '7' {
				return "", errors.New("invalid mount field escape")
			}
			value = value*8 + digit - '0'
		}
		if value == 0 {
			return "", errors.New("mount field decodes to NUL")
		}
		decoded.WriteByte(value)
		index += 3
	}
	return decoded.String(), nil
}

func mountOption(options, want string) bool {
	for _, option := range strings.Split(options, ",") {
		if option == want {
			return true
		}
	}
	return false
}

func isSkippedFilesystemType(fsType string) bool {
	if _, skipped := skippedFilesystemTypes[fsType]; skipped {
		return true
	}
	return strings.HasPrefix(fsType, "fuse.")
}

func (s *Source) rootPath(mountpoint string) (string, error) {
	if !filepath.IsAbs(mountpoint) {
		return "", errors.New("mountpoint is not absolute")
	}
	root := filepath.Clean(s.paths.RootFS)
	relative := strings.TrimPrefix(filepath.Clean(mountpoint), "/")
	target := filepath.Join(root, relative)
	relation, err := filepath.Rel(root, target)
	if err != nil || relation == ".." ||
		strings.HasPrefix(relation, ".."+string(filepath.Separator)) {
		return "", errors.New("mountpoint escapes rootfs")
	}
	return target, nil
}

func filesystemAttrs(mount mountinfoRecord) model.Labels {
	return model.Labels{
		{Name: "device", Value: mount.device},
		{Name: "fstype", Value: mount.fsType},
		{Name: "mountpoint", Value: mount.mountpoint},
	}
}

func filesystemErrorSeries(
	mount mountinfoRecord,
	ts uint64,
) model.Series {
	return gaugeInt(
		"node_filesystem_device_error",
		"",
		ts,
		1,
		filesystemAttrs(mount),
	)
}

func filesystemSeries(
	mount mountinfoRecord,
	stat unix.Statfs_t,
	ts uint64,
) ([]model.Series, error) {
	if stat.Bsize <= 0 {
		return nil, fmt.Errorf("invalid block size %d", stat.Bsize)
	}
	size, err := filesystemBytes(stat.Blocks, stat.Bsize)
	if err != nil {
		return nil, fmt.Errorf("size: %w", err)
	}
	free, err := filesystemBytes(stat.Bfree, stat.Bsize)
	if err != nil {
		return nil, fmt.Errorf("free: %w", err)
	}
	available, err := filesystemBytes(stat.Bavail, stat.Bsize)
	if err != nil {
		return nil, fmt.Errorf("available: %w", err)
	}
	if stat.Files > math.MaxInt64 || stat.Ffree > math.MaxInt64 {
		return nil, errors.New("inode count exceeds int64")
	}
	attrs := func() model.Labels {
		return filesystemAttrs(mount)
	}
	readOnly := int64(0)
	if mount.readOnly || stat.Flags&unix.ST_RDONLY != 0 {
		readOnly = 1
	}
	return []model.Series{
		gaugeInt(
			"node_filesystem_size_bytes",
			"bytes",
			ts,
			size,
			attrs(),
		),
		gaugeInt(
			"node_filesystem_free_bytes",
			"bytes",
			ts,
			free,
			attrs(),
		),
		gaugeInt(
			"node_filesystem_avail_bytes",
			"bytes",
			ts,
			available,
			attrs(),
		),
		gaugeInt(
			"node_filesystem_files",
			"",
			ts,
			int64(stat.Files),
			attrs(),
		),
		gaugeInt(
			"node_filesystem_files_free",
			"",
			ts,
			int64(stat.Ffree),
			attrs(),
		),
		gaugeInt(
			"node_filesystem_readonly",
			"",
			ts,
			readOnly,
			attrs(),
		),
		gaugeInt(
			"node_filesystem_device_error",
			"",
			ts,
			0,
			attrs(),
		),
	}, nil
}

func filesystemBytes(blocks uint64, blockSize int64) (int64, error) {
	if blockSize <= 0 ||
		blocks > uint64(math.MaxInt64)/uint64(blockSize) {
		return 0, errors.New("block count overflows bytes")
	}
	return int64(blocks) * blockSize, nil
}
