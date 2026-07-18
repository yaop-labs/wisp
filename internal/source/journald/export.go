package journald

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
)

const (
	maxFieldNameBytes = 64
	maxCursorBytes    = 4096
)

var exportedFields = map[string]struct{}{
	"__CURSOR":             {},
	"__REALTIME_TIMESTAMP": {},
	"MESSAGE":              {},
	"PRIORITY":             {},
	"SYSLOG_FACILITY":      {},
	"SYSLOG_IDENTIFIER":    {},
	"SYSLOG_PID":           {},
	"_SYSTEMD_UNIT":        {},
	"_SYSTEMD_USER_UNIT":   {},
	"_PID":                 {},
	"_UID":                 {},
	"_GID":                 {},
	"_HOSTNAME":            {},
	"_COMM":                {},
	"_EXE":                 {},
	"_TRANSPORT":           {},
	"_BOOT_ID":             {},
}

type journalEntry struct {
	fields           map[string][]byte
	messageOversized bool
}

// exportReader parses systemd's Journal Export Format. Text fields are
// newline-delimited; binary fields carry a little-endian uint64 length. Values
// larger than maxFieldBytes are streamed to io.Discard rather than allocated.
type exportReader struct {
	reader        *bufio.Reader
	maxFieldBytes int
}

func newExportReader(reader io.Reader, maxFieldBytes int) *exportReader {
	return &exportReader{
		reader:        bufio.NewReaderSize(reader, 64<<10),
		maxFieldBytes: maxFieldBytes,
	}
}

func (r *exportReader) next() (journalEntry, error) {
	entry := journalEntry{fields: make(map[string][]byte)}
	for {
		lineLimit := r.maxFieldBytes
		if lineLimit < maxCursorBytes {
			lineLimit = maxCursorBytes
		}
		line, oversized, err := readBoundedLine(
			r.reader,
			lineLimit+maxFieldNameBytes+1,
		)
		if err != nil {
			if errors.Is(err, io.EOF) && len(entry.fields) > 0 {
				return journalEntry{}, fmt.Errorf(
					"journald export: truncated entry",
				)
			}
			return journalEntry{}, err
		}
		if len(line) == 0 && !oversized {
			if len(entry.fields) == 0 {
				continue
			}
			return entry, nil
		}
		if separator := strings.IndexByte(string(line), '='); separator >= 0 {
			name := string(line[:separator])
			if !validFieldName(name) {
				return journalEntry{}, fmt.Errorf(
					"journald export: invalid field name",
				)
			}
			value := line[separator+1:]
			if oversized || len(value) > r.fieldLimit(name) {
				if name == "MESSAGE" {
					entry.messageOversized = true
				}
				continue
			}
			r.store(&entry, name, value)
			continue
		}
		if oversized || !validFieldName(string(line)) {
			return journalEntry{}, fmt.Errorf(
				"journald export: invalid binary field name",
			)
		}
		name := string(line)
		var sizeBytes [8]byte
		if _, err := io.ReadFull(r.reader, sizeBytes[:]); err != nil {
			return journalEntry{}, fmt.Errorf(
				"journald export: read binary length: %w",
				err,
			)
		}
		size := binary.LittleEndian.Uint64(sizeBytes[:])
		keep := size <= uint64(r.fieldLimit(name)) &&
			size <= uint64(math.MaxInt)
		var value []byte
		if keep {
			value = make([]byte, int(size))
			if _, err := io.ReadFull(r.reader, value); err != nil {
				return journalEntry{}, fmt.Errorf(
					"journald export: read binary value: %w",
					err,
				)
			}
		} else {
			if size > math.MaxInt64 {
				return journalEntry{}, fmt.Errorf(
					"journald export: binary field is too large",
				)
			}
			if _, err := io.CopyN(io.Discard, r.reader, int64(size)); err != nil {
				return journalEntry{}, fmt.Errorf(
					"journald export: discard binary value: %w",
					err,
				)
			}
			if name == "MESSAGE" {
				entry.messageOversized = true
			}
		}
		terminator, err := r.reader.ReadByte()
		if err != nil {
			return journalEntry{}, fmt.Errorf(
				"journald export: read binary terminator: %w",
				err,
			)
		}
		if terminator != '\n' {
			return journalEntry{}, fmt.Errorf(
				"journald export: invalid binary terminator",
			)
		}
		if keep {
			r.store(&entry, name, value)
		}
	}
}

func (r *exportReader) fieldLimit(name string) int {
	if name == "MESSAGE" {
		return r.maxFieldBytes
	}
	return maxCursorBytes
}

func (r *exportReader) store(entry *journalEntry, name string, value []byte) {
	if _, wanted := exportedFields[name]; !wanted {
		return
	}
	if _, exists := entry.fields[name]; exists {
		return
	}
	entry.fields[name] = append([]byte(nil), value...)
}

func validFieldName(name string) bool {
	if len(name) == 0 || len(name) > maxFieldNameBytes {
		return false
	}
	for _, value := range []byte(name) {
		if value >= 'A' && value <= 'Z' ||
			value >= '0' && value <= '9' ||
			value == '_' {
			continue
		}
		return false
	}
	return true
}

func readBoundedLine(
	reader *bufio.Reader,
	maxBytes int,
) ([]byte, bool, error) {
	var (
		line      []byte
		oversized bool
	)
	for {
		part, err := reader.ReadSlice('\n')
		if len(part) > 0 {
			content := part
			if part[len(part)-1] == '\n' {
				content = part[:len(part)-1]
			}
			if !oversized && len(line)+len(content) <= maxBytes {
				line = append(line, content...)
			} else {
				oversized = true
			}
		}
		switch {
		case err == nil:
			return line, oversized, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(line) == 0 && !oversized:
			return nil, false, io.EOF
		case errors.Is(err, io.EOF):
			return nil, false, fmt.Errorf(
				"journald export: unterminated field",
			)
		default:
			return nil, false, err
		}
	}
}
