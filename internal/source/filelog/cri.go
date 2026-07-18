package filelog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strings"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"

	"github.com/yaop-labs/wisp/internal/selfobs"
)

const maxCRIHeaderBytes = 128

type criLine struct {
	timeUnixNano uint64
	stream       string
	tag          byte
	content      []byte
}

func parseCRILine(line []byte) (criLine, error) {
	timestamp, rest, ok := splitCRIField(line)
	if !ok {
		return criLine{}, fmt.Errorf("missing timestamp")
	}
	stream, rest, ok := splitCRIField(rest)
	if !ok {
		return criLine{}, fmt.Errorf("missing stream")
	}
	tag, content, ok := splitCRIField(rest)
	if !ok {
		return criLine{}, fmt.Errorf("missing tag or content separator")
	}
	parsedTime, err := time.Parse(time.RFC3339Nano, string(timestamp))
	if err != nil {
		return criLine{}, fmt.Errorf("invalid timestamp")
	}
	streamValue := string(stream)
	if streamValue != "stdout" && streamValue != "stderr" {
		return criLine{}, fmt.Errorf("invalid stream")
	}
	if len(tag) != 1 || (tag[0] != 'P' && tag[0] != 'F') {
		return criLine{}, fmt.Errorf("invalid tag")
	}
	seconds := parsedTime.Unix()
	if seconds < 0 || uint64(seconds) > math.MaxUint64/uint64(time.Second) {
		return criLine{}, fmt.Errorf("timestamp outside OTLP range")
	}
	nanos := uint64(seconds)*uint64(time.Second) + uint64(parsedTime.Nanosecond())
	return criLine{
		timeUnixNano: nanos,
		stream:       streamValue,
		tag:          tag[0],
		content:      content,
	}, nil
}

type criPending struct {
	body         []byte
	startOffset  int64
	endOffset    int64
	timeUnixNano uint64
	stream       string
}

func (s *Source) readCRIFile(
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
		logicalDropping    = state.CRIDropping
		lineStart          = offset
		pending            *criPending
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
		state.CRIDropping = keepDropping
		s.store.files[keyPath] = state
		return s.persistCheckpoint()
	}
	redactAndAdd := func(
		body []byte,
		commitEnd int64,
		build func([]byte) *logspb.LogRecord,
	) error {
		redacted, keep := s.redactLogBody(body)
		if !keep {
			return persistBoundary(commitEnd, false)
		}
		return add(build(redacted), commitEnd)
	}
	addPending := func(partial bool, sequenceError bool) error {
		if pending == nil {
			return nil
		}
		extra := make([]*commonpb.KeyValue, 0, 2)
		if partial {
			extra = append(extra, boolAttribute("wisp.cri.partial", true))
		}
		if sequenceError {
			extra = append(extra, boolAttribute("wisp.cri.sequence_error", true))
		}
		body := pending.body
		startOffset := pending.startOffset
		end := pending.endOffset
		timeUnixNano := pending.timeUnixNano
		stream := pending.stream
		pending = nil
		return redactAndAdd(body, end, func(redacted []byte) *logspb.LogRecord {
			return newCRILogRecord(
				redacted,
				keyPath,
				startOffset,
				timeUnixNano,
				stream,
				extra...,
			)
		})
	}

	var processParsed func(criLine, int64, int64) error
	processParsed = func(parsed criLine, start, end int64) error {
		if logicalDropping {
			logicalDropping = parsed.tag == 'P'
			return persistBoundary(end, logicalDropping)
		}
		if pending != nil && pending.stream != parsed.stream {
			selfobs.FileLogCRISequenceErrors.Inc()
			if err := addPending(true, true); err != nil {
				return err
			}
			return processParsed(parsed, start, end)
		}
		if pending == nil {
			if len(parsed.content) > s.cfg.MaxLineBytes {
				selfobs.FileLogOversized.Inc()
				logicalDropping = parsed.tag == 'P'
				return persistBoundary(end, logicalDropping)
			}
			if parsed.tag == 'F' {
				return redactAndAdd(
					parsed.content,
					end,
					func(redacted []byte) *logspb.LogRecord {
						return newCRILogRecord(
							redacted,
							keyPath,
							start,
							parsed.timeUnixNano,
							parsed.stream,
						)
					},
				)
			}
			pending = &criPending{
				body:         slices.Clone(parsed.content),
				startOffset:  start,
				endOffset:    end,
				timeUnixNano: parsed.timeUnixNano,
				stream:       parsed.stream,
			}
			return nil
		}

		if len(parsed.content) > s.cfg.MaxLineBytes-len(pending.body) {
			selfobs.FileLogOversized.Inc()
			pending = nil
			logicalDropping = parsed.tag == 'P'
			return persistBoundary(end, logicalDropping)
		}
		pending.body = append(pending.body, parsed.content...)
		pending.endOffset = end
		if parsed.tag == 'P' {
			return nil
		}
		return addPending(false, false)
	}
	processLine := func(value []byte, start, end int64) error {
		parsed, err := parseCRILine(value)
		if err != nil {
			selfobs.FileLogCRIParseErrors.Inc()
			if logicalDropping {
				logicalDropping = false
				state.CRIDropping = false
			}
			if pending != nil {
				selfobs.FileLogCRISequenceErrors.Inc()
				if err := addPending(true, true); err != nil {
					return err
				}
			}
			return redactAndAdd(
				value,
				end,
				func(redacted []byte) *logspb.LogRecord {
					record := newLogRecord(redacted, keyPath, start)
					record.Attributes = append(
						record.Attributes,
						boolAttribute("wisp.cri.parse_error", true),
					)
					return record
				},
			)
		}
		selfobs.FileLogCRIFragments.Inc()
		return processParsed(parsed, start, end)
	}

	physicalLimit := s.cfg.MaxLineBytes + maxCRIHeaderBytes + 1
	for readBytes < s.cfg.MaxReadBytes {
		part, readErr := reader.ReadSlice('\n')
		offset += int64(len(part))
		readBytes += int64(len(part))
		selfobs.FileLogBytesRead.Add(uint64(len(part)))
		if !physicalOversized {
			if len(line)+len(part) > physicalLimit {
				physicalOversized = true
				line = nil
				pending = nil
				logicalDropping = false
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
				if err := flush(); err != nil {
					return false, err
				}
				selfobs.FileLogOversized.Inc()
				if err := persistBoundary(offset, false); err != nil {
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
					selfobs.FileLogCRIPartialRecords.Inc()
					if err := addPending(true, false); err != nil {
						return false, err
					}
				}
			}
			if err := flush(); err != nil {
				return false, err
			}
			if physicalOversized {
				state.Offset = offset
				state.Dropping = true
				state.CRIDropping = false
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
		state.CRIDropping = false
		s.store.files[keyPath] = state
		if err := s.persistCheckpoint(); err != nil {
			return false, err
		}
	case pending != nil &&
		pending.endOffset-pending.startOffset >= s.cfg.MaxReadBytes:
		selfobs.FileLogOversized.Inc()
		pending = nil
		logicalDropping = true
		if err := persistBoundary(lastCompleteOffset, true); err != nil {
			return false, err
		}
	}
	return false, nil
}

func splitCRIField(value []byte) ([]byte, []byte, bool) {
	index := -1
	for i, char := range value {
		if char == ' ' {
			index = i
			break
		}
	}
	if index <= 0 {
		return nil, nil, false
	}
	return value[:index], value[index+1:], true
}

func newCRILogRecord(
	body []byte,
	path string,
	offset int64,
	timeUnixNano uint64,
	stream string,
	extra ...*commonpb.KeyValue,
) *logspb.LogRecord {
	record := newLogRecord(body, path, offset)
	record.TimeUnixNano = timeUnixNano
	record.Attributes = append(record.Attributes, stringAttribute("log.iostream", stream))
	record.Attributes = append(record.Attributes, extra...)
	return record
}

func boolAttribute(key string, value bool) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key: key,
		Value: &commonpb.AnyValue{
			Value: &commonpb.AnyValue_BoolValue{BoolValue: value},
		},
	}
}

func stringAttribute(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key: key,
		Value: &commonpb.AnyValue{
			Value: &commonpb.AnyValue_StringValue{StringValue: strings.ToValidUTF8(value, "?")},
		},
	}
}
