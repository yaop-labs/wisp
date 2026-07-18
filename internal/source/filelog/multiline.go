package filelog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"time"

	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"

	"github.com/yaop-labs/wisp/internal/selfobs"
)

const (
	defaultMultilineMaxLines   = 256
	defaultMultilineFlushAfter = 5 * time.Second
	maxMultilineLines          = 4096
	maxMultilinePatternBytes   = 1024
)

type multilineFramer struct {
	startPattern *regexp.Regexp
	maxLines     int
	flushAfter   time.Duration
}

type multilinePending struct {
	body        []byte
	startOffset int64
	endOffset   int64
	lines       int
}

func newMultilineFramer(config *MultilineConfig) (*multilineFramer, error) {
	if config == nil {
		return nil, nil
	}
	if config.StartPattern == "" ||
		len(config.StartPattern) > maxMultilinePatternBytes {
		return nil, fmt.Errorf(
			"filelog: multiline start pattern must contain between 1 and %d bytes",
			maxMultilinePatternBytes,
		)
	}
	pattern, err := regexp.Compile(config.StartPattern)
	if err != nil {
		return nil, fmt.Errorf("filelog: multiline start pattern is not a valid regular expression")
	}
	if pattern.MatchString("") {
		return nil, fmt.Errorf("filelog: multiline start pattern must not match empty input")
	}
	maxLines := config.MaxLines
	if maxLines == 0 {
		maxLines = defaultMultilineMaxLines
	}
	if maxLines < 1 || maxLines > maxMultilineLines {
		return nil, fmt.Errorf(
			"filelog: multiline max lines must be between 1 and %d",
			maxMultilineLines,
		)
	}
	flushAfter := config.FlushAfter
	if flushAfter == 0 {
		flushAfter = defaultMultilineFlushAfter
	}
	if flushAfter < 100*time.Millisecond || flushAfter > 24*time.Hour {
		return nil, fmt.Errorf(
			"filelog: multiline flush after must be between 100ms and 24h",
		)
	}
	return &multilineFramer{
		startPattern: pattern,
		maxLines:     maxLines,
		flushAfter:   flushAfter,
	}, nil
}

func (s *Source) readMultilineFile(
	ctx context.Context,
	keyPath string,
	readPath string,
	state checkpoint,
	flushPartial bool,
) (bool, error) {
	file, err := os.Open(readPath)
	if err != nil {
		return false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, err
	}
	identity, err := fileIdentity(info)
	if err != nil {
		return false, err
	}
	if identity != state.Identity {
		return false, fmt.Errorf("filelog: identity changed before read")
	}
	if _, err := file.Seek(state.Offset, io.SeekStart); err != nil {
		return false, err
	}

	reader := bufio.NewReaderSize(file, readBufferBytes)
	offset := state.Offset
	readBytes := int64(0)
	var (
		records            []*logspb.LogRecord
		batchBytes         int
		batchEnd           = state.Offset
		line               []byte
		physicalOversized  = state.Dropping
		logicalDropping    = state.MultilineDropping
		lineStart          = offset
		pending            *multilinePending
		lastCompleteOffset = offset
	)
	flush := func() error {
		if len(records) == 0 {
			return nil
		}
		if err := s.emitRecords(ctx, keyPath, records); err != nil {
			return fmt.Errorf("%w: %w", errAdmission, err)
		}
		state.Offset = batchEnd
		s.store.files[keyPath] = state
		if err := s.persistCheckpoint(); err != nil {
			return err
		}
		records = nil
		batchBytes = 0
		return nil
	}
	add := func(record *logspb.LogRecord, commitEnd int64) error {
		recordBytes := proto.Size(record)
		if batchBytes+recordBytes > s.cfg.MaxBatchBytes && len(records) > 0 {
			if err := flush(); err != nil {
				return err
			}
		}
		records = append(records, record)
		batchBytes += recordBytes
		batchEnd = commitEnd
		return nil
	}
	persistBoundary := func(commitEnd int64, keepDropping bool) error {
		if err := flush(); err != nil {
			return err
		}
		state.Offset = commitEnd
		state.Dropping = false
		state.MultilineDropping = keepDropping
		s.store.files[keyPath] = state
		return s.persistCheckpoint()
	}
	commitPending := func(reason string) error {
		if pending == nil {
			return nil
		}
		body := pending.body
		start := pending.startOffset
		end := pending.endOffset
		pending = nil
		redacted, keep := s.redactLogBody(body)
		if !keep {
			return persistBoundary(end, false)
		}
		record := newLogRecord(redacted, keyPath, start)
		if reason != "" {
			record.Attributes = append(
				record.Attributes,
				stringAttribute("wisp.multiline.flush_reason", reason),
			)
			selfobs.FileLogMultilineForcedFlushes.Inc()
		}
		return add(record, end)
	}
	beginPending := func(value []byte, start, end int64) {
		pending = &multilinePending{
			body:        slices.Clone(value),
			startOffset: start,
			endOffset:   end,
			lines:       1,
		}
	}
	processLine := func(value []byte, start, end int64) error {
		startsRecord := s.multiline.startPattern.Match(value)
		if logicalDropping {
			if !startsRecord {
				return persistBoundary(end, true)
			}
			logicalDropping = false
			state.MultilineDropping = false
			beginPending(value, start, end)
			return nil
		}
		if pending == nil {
			beginPending(value, start, end)
			return nil
		}
		if startsRecord {
			if err := commitPending(""); err != nil {
				return err
			}
			beginPending(value, start, end)
			return nil
		}
		if pending.lines >= s.multiline.maxLines ||
			len(value)+1 > s.cfg.MaxLineBytes-len(pending.body) {
			selfobs.FileLogOversized.Inc()
			selfobs.FileLogMultilineOversized.Inc()
			pending = nil
			logicalDropping = true
			return persistBoundary(end, true)
		}
		pending.body = append(pending.body, '\n')
		pending.body = append(pending.body, value...)
		pending.endOffset = end
		pending.lines++
		return nil
	}

	for readBytes < s.cfg.MaxReadBytes {
		part, readErr := reader.ReadSlice('\n')
		offset += int64(len(part))
		readBytes += int64(len(part))
		selfobs.FileLogBytesRead.Add(uint64(len(part)))
		if !physicalOversized {
			if len(line)+len(part) > s.cfg.MaxLineBytes+1 {
				physicalOversized = true
				line = nil
				pending = nil
				logicalDropping = true
			} else {
				line = append(line, part...)
			}
		}
		complete := readErr == nil
		if errors.Is(readErr, io.EOF) && flushPartial &&
			(len(part) > 0 || physicalOversized) {
			complete = true
		}
		if complete {
			lastCompleteOffset = offset
			if physicalOversized {
				selfobs.FileLogOversized.Inc()
				selfobs.FileLogMultilineOversized.Inc()
				if err := persistBoundary(offset, true); err != nil {
					return false, err
				}
			} else if err := processLine(
				bytesTrimLineEnding(line),
				lineStart,
				offset,
			); err != nil {
				return false, err
			}
			line = nil
			physicalOversized = false
			lineStart = offset
		}
		switch {
		case readErr == nil:
			continue
		case errors.Is(readErr, bufio.ErrBufferFull):
			continue
		case errors.Is(readErr, io.EOF):
			if flushPartial {
				if logicalDropping {
					logicalDropping = false
					if err := persistBoundary(offset, false); err != nil {
						return false, err
					}
				}
				if pending != nil {
					if err := commitPending("rotation"); err != nil {
						return false, err
					}
				}
			} else if pending != nil && len(line) == 0 &&
				time.Since(info.ModTime()) >= s.multiline.flushAfter {
				if err := commitPending("timeout"); err != nil {
					return false, err
				}
			}
			if err := flush(); err != nil {
				return false, err
			}
			if physicalOversized {
				state.Offset = offset
				state.Dropping = true
				state.MultilineDropping = true
				s.store.files[keyPath] = state
				if err := s.persistCheckpoint(); err != nil {
					return false, err
				}
				return false, nil
			}
			return len(line) == 0 && pending == nil && !logicalDropping, nil
		default:
			return false, readErr
		}
	}
	if err := flush(); err != nil {
		return false, err
	}
	switch {
	case physicalOversized:
		state.Offset = offset
		state.Dropping = true
		state.MultilineDropping = true
		s.store.files[keyPath] = state
		if err := s.persistCheckpoint(); err != nil {
			return false, err
		}
	case pending != nil &&
		pending.endOffset-pending.startOffset >= s.cfg.MaxReadBytes:
		selfobs.FileLogOversized.Inc()
		selfobs.FileLogMultilineOversized.Inc()
		pending = nil
		logicalDropping = true
		if err := persistBoundary(lastCompleteOffset, true); err != nil {
			return false, err
		}
	}
	return false, nil
}
