// Package journald collects bounded systemd journal entries into OTLP Logs.
// Cursor checkpoints advance only after downstream delivery or spool fsync.
package journald

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/otlpwire"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
	"github.com/yaop-labs/wisp/internal/signal"
)

const (
	defaultPollInterval = time.Second
	defaultTimeout      = 10 * time.Second
	defaultMaxEntries   = 512
	defaultMaxField     = 256 << 10
	defaultMaxBatch     = 512 << 10
	minMaxBatch         = 8 << 10
	maxStderrBytes      = 32 << 10
)

var outputFields = []string{
	"MESSAGE",
	"PRIORITY",
	"SYSLOG_FACILITY",
	"SYSLOG_IDENTIFIER",
	"SYSLOG_PID",
	"_SYSTEMD_UNIT",
	"_SYSTEMD_USER_UNIT",
	"_PID",
	"_UID",
	"_GID",
	"_HOSTNAME",
	"_COMM",
	"_EXE",
	"_TRANSPORT",
	"_BOOT_ID",
}

var journalAttributeFields = []struct {
	field     string
	attribute string
}{
	{"SYSLOG_FACILITY", "syslog.facility"},
	{"SYSLOG_IDENTIFIER", "syslog.identifier"},
	{"SYSLOG_PID", "syslog.pid"},
	{"_BOOT_ID", "systemd.boot_id"},
	{"_COMM", "process.executable.name"},
	{"_EXE", "process.executable.path"},
	{"_GID", "group.id"},
	{"_HOSTNAME", "host.name"},
	{"_PID", "process.pid"},
	{"_SYSTEMD_UNIT", "systemd.unit"},
	{"_SYSTEMD_USER_UNIT", "systemd.user_unit"},
	{"_TRANSPORT", "systemd.transport"},
	{"_UID", "user.id"},
}

type Config struct {
	CheckpointFile string
	PollInterval   time.Duration
	Timeout        time.Duration
	StartAt        string
	Directory      string
	Units          []string
	Identifiers    []string
	MaxEntries     int
	MaxFieldBytes  int
	MaxBatchBytes  int
	Redaction      *RedactionConfig
	Resource       map[string]string
	Command        string
}

type Source struct {
	cfg      Config
	logger   *slog.Logger
	store    *checkpointStore
	redactor *contentRedactor
	emit     func(context.Context, signal.Envelope) error

	healthMu  sync.RWMutex
	healthErr error
}

func New(cfg Config, logger *slog.Logger) (*Source, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("journald: source requires Linux")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.StartAt == "" {
		cfg.StartAt = "end"
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = defaultMaxEntries
	}
	if cfg.MaxFieldBytes <= 0 {
		cfg.MaxFieldBytes = defaultMaxField
	}
	if cfg.MaxBatchBytes <= 0 {
		cfg.MaxBatchBytes = defaultMaxBatch
	}
	if cfg.CheckpointFile == "" {
		return nil, fmt.Errorf("journald: checkpoint file is required")
	}
	if cfg.StartAt != "beginning" && cfg.StartAt != "end" {
		return nil, fmt.Errorf("journald: start_at must be beginning or end")
	}
	if cfg.PollInterval < 100*time.Millisecond ||
		cfg.Timeout < time.Second || cfg.Timeout > time.Minute ||
		cfg.MaxEntries < 1 || cfg.MaxEntries > 10_000 ||
		cfg.MaxFieldBytes < 1 || cfg.MaxFieldBytes > 1<<20 ||
		cfg.MaxBatchBytes < minMaxBatch ||
		cfg.MaxBatchBytes < cfg.MaxFieldBytes ||
		cfg.MaxBatchBytes > otlpwire.DefaultMaxRequestBytes {
		return nil, fmt.Errorf("journald: invalid collection bounds")
	}
	if cfg.Directory != "" {
		if !filepath.IsAbs(cfg.Directory) ||
			filepath.Clean(cfg.Directory) == string(filepath.Separator) {
			return nil, fmt.Errorf(
				"journald: directory must be an absolute non-root path",
			)
		}
		cfg.Directory = filepath.Clean(cfg.Directory)
	}
	for _, value := range append(
		append([]string(nil), cfg.Units...),
		cfg.Identifiers...,
	) {
		if !validFilter(value) {
			return nil, fmt.Errorf("journald: invalid unit or identifier filter")
		}
	}
	if len(cfg.Units) > 128 || len(cfg.Identifiers) > 128 {
		return nil, fmt.Errorf("journald: too many filters")
	}
	checkpointPath, err := filepath.Abs(cfg.CheckpointFile)
	if err != nil {
		return nil, fmt.Errorf("journald checkpoint: absolute path: %w", err)
	}
	cfg.CheckpointFile = checkpointPath
	if cfg.Command == "" {
		cfg.Command = "journalctl"
	}
	command, err := exec.LookPath(cfg.Command)
	if err != nil {
		return nil, fmt.Errorf("journald: find journalctl: %w", err)
	}
	if !filepath.IsAbs(command) {
		return nil, fmt.Errorf("journald: journalctl path must be absolute")
	}
	cfg.Command = command
	store, err := loadCheckpoint(checkpointPath)
	if err != nil {
		return nil, err
	}
	redactor, err := newContentRedactor(cfg.Redaction, cfg.MaxFieldBytes)
	if err != nil {
		return nil, err
	}
	return &Source{
		cfg: cfg, logger: logger, store: store, redactor: redactor,
	}, nil
}

func (s *Source) SetLogsEmitter(
	emit func(context.Context, signal.Envelope) error,
) {
	s.emit = emit
}

func (s *Source) Start(
	ctx context.Context,
	_ func(context.Context, model.Batch) error,
) error {
	if s.emit == nil {
		return fmt.Errorf("journald: logs emitter is not configured")
	}
	ticker := time.NewTicker(s.cfg.PollInterval)
	defer ticker.Stop()
	s.poll(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.poll(ctx)
		}
	}
}

func (*Source) Stop(context.Context) error { return nil }

func (s *Source) Healthy() error {
	s.healthMu.RLock()
	defer s.healthMu.RUnlock()
	return s.healthErr
}

func (s *Source) setHealth(err error) {
	s.healthMu.Lock()
	s.healthErr = err
	s.healthMu.Unlock()
}

func (s *Source) poll(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if !s.store.state.Initialized {
		s.store.state = checkpoint{
			Version:     checkpointVersion,
			Initialized: true,
		}
		if s.cfg.StartAt == "end" {
			s.store.state.SinceUnixUsec = uint64(time.Now().UnixMicro())
		}
		s.store.dirty = true
	}
	if s.store.dirty {
		if err := s.persistCheckpoint(); err != nil {
			s.logger.Warn(
				"journald checkpoint unavailable; pausing collection",
				"err", err,
			)
			return
		}
	}
	if err := s.collect(ctx); err != nil {
		s.setHealth(err)
		switch {
		case errors.Is(err, pipeline.ErrBackpressure):
			selfobs.JournaldBackpressure.Inc()
		case errors.Is(err, errAdmission):
			selfobs.JournaldAdmissionErrors.Inc()
		default:
			selfobs.JournaldReadErrors.Inc()
		}
		if pipeline.IsLoggableEmitError(ctx, err) {
			s.logger.Warn("journald collection failed", "err", err)
		}
		return
	}
	s.setHealth(nil)
}

var errAdmission = errors.New("journald: durable admission failed")

func (s *Source) collect(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, s.cfg.Timeout)
	defer cancel()
	args := s.commandArgs()
	// #nosec G204 -- New resolves an absolute executable and all arguments are
	// passed directly (never through a shell) after bounded config validation.
	command := exec.CommandContext(ctx, s.cfg.Command, args...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("journald: stdout pipe: %w", err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return fmt.Errorf("journald: stderr pipe: %w", err)
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("journald: start journalctl: %w", err)
	}
	var stderrOutput boundedBuffer
	stderrDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&stderrOutput, stderr)
		close(stderrDone)
	}()

	parseErr := s.consume(ctx, stdout)
	if parseErr != nil && command.Process != nil {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	<-stderrDone
	if parseErr != nil {
		return parseErr
	}
	if ctx.Err() != nil {
		return fmt.Errorf("journald: journalctl timeout: %w", ctx.Err())
	}
	if waitErr != nil {
		detail := strings.TrimSpace(stderrOutput.String())
		if detail != "" {
			return fmt.Errorf(
				"journald: journalctl failed: %w: %s",
				waitErr,
				detail,
			)
		}
		return fmt.Errorf("journald: journalctl failed: %w", waitErr)
	}
	return nil
}

func (s *Source) commandArgs() []string {
	args := []string{
		"--no-pager",
		"--quiet",
		"--output=export",
		"--output-fields=" + strings.Join(outputFields, ","),
		"--lines=+" + strconv.Itoa(s.cfg.MaxEntries),
	}
	if cursor := s.store.state.Cursor; cursor != "" {
		args = append(args, "--after-cursor="+cursor)
	} else if since := s.store.state.SinceUnixUsec; since > 0 {
		args = append(args, "--since="+formatSince(since))
	}
	if s.cfg.Directory != "" {
		args = append(args, "--directory="+s.cfg.Directory)
	}
	for _, unit := range s.cfg.Units {
		args = append(args, "--unit="+unit)
	}
	for _, identifier := range s.cfg.Identifiers {
		args = append(args, "--identifier="+identifier)
	}
	return args
}

func formatSince(microseconds uint64) string {
	return fmt.Sprintf(
		"@%d.%06d",
		microseconds/1_000_000,
		microseconds%1_000_000,
	)
}

func (s *Source) consume(ctx context.Context, output io.Reader) error {
	reader := newExportReader(output, s.cfg.MaxFieldBytes)
	var (
		records    []*logspb.LogRecord
		batchBytes int
		lastCursor string
		entries    int
	)
	flush := func() error {
		if len(records) == 0 {
			return nil
		}
		if err := s.emitRecords(ctx, records); err != nil {
			return fmt.Errorf("%w: %w", errAdmission, err)
		}
		s.store.state.Cursor = lastCursor
		s.store.state.SinceUnixUsec = 0
		s.store.dirty = true
		if err := s.persistCheckpoint(); err != nil {
			return err
		}
		records = nil
		batchBytes = 0
		return nil
	}
	for {
		entry, err := reader.next()
		if errors.Is(err, io.EOF) {
			return flush()
		}
		if err != nil {
			return err
		}
		entries++
		if entries > s.cfg.MaxEntries {
			return fmt.Errorf(
				"journald export: journalctl exceeded max_entries_per_poll",
			)
		}
		record, cursor, keep, err := s.convertEntry(entry)
		if err != nil {
			return err
		}
		if !keep {
			if err := flush(); err != nil {
				return err
			}
			s.store.state.Cursor = cursor
			s.store.state.SinceUnixUsec = 0
			s.store.dirty = true
			if err := s.persistCheckpoint(); err != nil {
				return err
			}
			continue
		}
		recordBytes := proto.Size(record)
		if recordBytes > s.cfg.MaxBatchBytes {
			record = oversizedRecord(record, cursor)
			recordBytes = proto.Size(record)
			selfobs.JournaldOversizedRecords.Inc()
			if recordBytes > s.cfg.MaxBatchBytes {
				return fmt.Errorf(
					"%w: journald oversized marker exceeds max_batch_bytes",
					pipeline.ErrPermanent,
				)
			}
		}
		if batchBytes+recordBytes > s.cfg.MaxBatchBytes && len(records) > 0 {
			if err := flush(); err != nil {
				return err
			}
		}
		records = append(records, record)
		batchBytes += recordBytes
		lastCursor = cursor
	}
}

func oversizedRecord(
	original *logspb.LogRecord,
	cursor string,
) *logspb.LogRecord {
	record := &logspb.LogRecord{
		TimeUnixNano:         original.TimeUnixNano,
		ObservedTimeUnixNano: original.ObservedTimeUnixNano,
		SeverityNumber:       original.SeverityNumber,
		SeverityText:         original.SeverityText,
		Body: &commonpb.AnyValue{
			Value: &commonpb.AnyValue_StringValue{},
		},
	}
	addStringAttribute(record, "wisp.journald.cursor", []byte(cursor))
	addBoolAttribute(record, "wisp.journald.record_oversized", true)
	return record
}

func (s *Source) convertEntry(
	entry journalEntry,
) (*logspb.LogRecord, string, bool, error) {
	cursor := strings.ToValidUTF8(string(entry.fields["__CURSOR"]), "?")
	if cursor == "" {
		return nil, "", false, fmt.Errorf(
			"journald export: entry has no cursor",
		)
	}
	if err := validateCursor(cursor); err != nil {
		return nil, "", false, fmt.Errorf("journald export: %w", err)
	}
	timestamp, err := parseRealtime(entry.fields["__REALTIME_TIMESTAMP"])
	if err != nil {
		return nil, "", false, err
	}
	message := entry.fields["MESSAGE"]
	if !entry.messageOversized {
		var keep bool
		message, keep = s.redactor.apply(message)
		if !keep {
			return nil, cursor, false, nil
		}
	}
	record := &logspb.LogRecord{
		TimeUnixNano:         timestamp,
		ObservedTimeUnixNano: uint64(time.Now().UnixNano()),
		Body: &commonpb.AnyValue{
			Value: &commonpb.AnyValue_StringValue{
				StringValue: strings.ToValidUTF8(string(message), "?"),
			},
		},
	}
	addStringAttribute(record, "wisp.journald.cursor", []byte(cursor))
	if entry.messageOversized {
		addBoolAttribute(record, "wisp.journald.message_oversized", true)
		selfobs.JournaldOversizedMessages.Inc()
	} else if _, ok := entry.fields["MESSAGE"]; !ok {
		addBoolAttribute(record, "wisp.journald.message_missing", true)
	}
	for _, mapping := range journalAttributeFields {
		addStringAttribute(
			record,
			mapping.attribute,
			entry.fields[mapping.field],
		)
	}
	setSeverity(record, entry.fields["PRIORITY"])
	return record, cursor, true, nil
}

func parseRealtime(value []byte) (uint64, error) {
	microseconds, err := strconv.ParseUint(string(value), 10, 64)
	if err != nil || microseconds == 0 ||
		microseconds > ^uint64(0)/1000 {
		return 0, fmt.Errorf(
			"journald export: invalid realtime timestamp",
		)
	}
	return microseconds * 1000, nil
}

func addStringAttribute(
	record *logspb.LogRecord,
	key string,
	value []byte,
) {
	if len(value) == 0 {
		return
	}
	record.Attributes = append(record.Attributes, &commonpb.KeyValue{
		Key: key,
		Value: &commonpb.AnyValue{
			Value: &commonpb.AnyValue_StringValue{
				StringValue: strings.ToValidUTF8(string(value), "?"),
			},
		},
	})
}

func addBoolAttribute(record *logspb.LogRecord, key string, value bool) {
	record.Attributes = append(record.Attributes, &commonpb.KeyValue{
		Key: key,
		Value: &commonpb.AnyValue{
			Value: &commonpb.AnyValue_BoolValue{BoolValue: value},
		},
	})
}

func setSeverity(record *logspb.LogRecord, priority []byte) {
	switch string(priority) {
	case "0":
		record.SeverityNumber = logspb.SeverityNumber_SEVERITY_NUMBER_FATAL4
		record.SeverityText = "EMERG"
	case "1":
		record.SeverityNumber = logspb.SeverityNumber_SEVERITY_NUMBER_FATAL3
		record.SeverityText = "ALERT"
	case "2":
		record.SeverityNumber = logspb.SeverityNumber_SEVERITY_NUMBER_FATAL2
		record.SeverityText = "CRIT"
	case "3":
		record.SeverityNumber = logspb.SeverityNumber_SEVERITY_NUMBER_ERROR
		record.SeverityText = "ERR"
	case "4":
		record.SeverityNumber = logspb.SeverityNumber_SEVERITY_NUMBER_WARN
		record.SeverityText = "WARNING"
	case "5":
		record.SeverityNumber = logspb.SeverityNumber_SEVERITY_NUMBER_INFO2
		record.SeverityText = "NOTICE"
	case "6":
		record.SeverityNumber = logspb.SeverityNumber_SEVERITY_NUMBER_INFO
		record.SeverityText = "INFO"
	case "7":
		record.SeverityNumber = logspb.SeverityNumber_SEVERITY_NUMBER_DEBUG
		record.SeverityText = "DEBUG"
	}
}

func (s *Source) emitRecords(
	ctx context.Context,
	records []*logspb.LogRecord,
) error {
	resourceValues := maps.Clone(s.cfg.Resource)
	resource := &resourcepb.Resource{}
	keys := make([]string, 0, len(resourceValues))
	for key := range resourceValues {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		resource.Attributes = append(resource.Attributes, &commonpb.KeyValue{
			Key: key,
			Value: &commonpb.AnyValue{
				Value: &commonpb.AnyValue_StringValue{
					StringValue: resourceValues[key],
				},
			},
		})
	}
	request := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: resource,
			ScopeLogs: []*logspb.ScopeLogs{{
				Scope: &commonpb.InstrumentationScope{
					Name: "github.com/yaop-labs/wisp/journald",
				},
				LogRecords: records,
			}},
		}},
	}
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(request)
	if err != nil {
		return fmt.Errorf(
			"%w: journald encode OTLP Logs: %v",
			pipeline.ErrPermanent,
			err,
		)
	}
	identity, ok := signal.ResourceIdentity(resourceValues)
	if !ok {
		identity = nil
	}
	envelope, err := signal.New(
		signal.Logs,
		signal.OTLPLogsSchema,
		signal.OTLPProtobufEncoding,
		payload,
		identity,
	)
	if err != nil {
		return err
	}
	if err := s.emit(ctx, envelope); err != nil {
		return err
	}
	selfobs.JournaldRecords.Add(uint64(len(records)))
	selfobs.JournaldBatches.Inc()
	return nil
}

func (s *Source) persistCheckpoint() error {
	if err := s.store.save(); err != nil {
		selfobs.JournaldCheckpointErrors.Inc()
		s.setHealth(err)
		return err
	}
	return nil
}

type boundedBuffer struct {
	buffer bytes.Buffer
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := maxStderrBytes - b.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = b.buffer.Write(value)
	}
	return original, nil
}

func (b *boundedBuffer) String() string { return b.buffer.String() }
