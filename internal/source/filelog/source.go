// Package filelog tails bounded newline-delimited files into OTLP Logs
// envelopes. Checkpoints advance only after downstream delivery or spool fsync.
package filelog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
	"github.com/yaop-labs/wisp/internal/signal"
)

const (
	defaultPollInterval  = time.Second
	defaultMaxLineBytes  = 256 << 10
	defaultMaxBatchBytes = 512 << 10
	defaultMaxReadBytes  = 4 << 20
	defaultFormat        = "text"
	readBufferBytes      = 64 << 10
	maxDirectoryEntries  = 4096
)

var errAdmission = errors.New("filelog: durable admission failed")

type Config struct {
	Include        []string
	Exclude        []string
	CheckpointFile string
	PollInterval   time.Duration
	StartAt        string
	Format         string
	Kubernetes     *KubernetesConfig
	Redaction      *RedactionConfig
	Multiline      *MultilineConfig
	MaxLineBytes   int
	MaxBatchBytes  int
	MaxReadBytes   int64
	Resource       map[string]string
}

type KubernetesConfig struct {
	PodLogsRoot string
}

type RedactionConfig struct {
	Patterns    []string
	Replacement string
}

type MultilineConfig struct {
	StartPattern string
	MaxLines     int
	FlushAfter   time.Duration
}

type Source struct {
	cfg       Config
	logger    *slog.Logger
	store     *checkpointStore
	redactor  *contentRedactor
	multiline *multilineFramer
	emit      func(context.Context, signal.Envelope) error

	healthMu  sync.RWMutex
	healthErr error
	active    atomic.Int64
}

func New(cfg Config, logger *slog.Logger) (*Source, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.StartAt == "" {
		cfg.StartAt = "end"
	}
	if cfg.Format == "" {
		cfg.Format = defaultFormat
	}
	if cfg.MaxLineBytes <= 0 {
		cfg.MaxLineBytes = defaultMaxLineBytes
	}
	if cfg.MaxBatchBytes <= 0 {
		cfg.MaxBatchBytes = defaultMaxBatchBytes
	}
	if cfg.MaxReadBytes <= 0 {
		cfg.MaxReadBytes = defaultMaxReadBytes
	}
	redactor, err := newContentRedactor(cfg.Redaction, cfg.MaxLineBytes)
	if err != nil {
		return nil, err
	}
	multiline, err := newMultilineFramer(cfg.Multiline)
	if err != nil {
		return nil, err
	}
	if multiline != nil && cfg.Format != "text" {
		return nil, fmt.Errorf("filelog: multiline requires text format")
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("filelog: durable file identity requires Linux")
	}
	if len(cfg.Include) == 0 || cfg.CheckpointFile == "" {
		return nil, fmt.Errorf("filelog: include and checkpoint file are required")
	}
	if cfg.StartAt != "beginning" && cfg.StartAt != "end" {
		return nil, fmt.Errorf("filelog: start_at must be beginning or end")
	}
	if cfg.Format != "text" && cfg.Format != "cri" {
		return nil, fmt.Errorf("filelog: format must be text or cri")
	}
	if cfg.Kubernetes != nil {
		if cfg.Format != "cri" {
			return nil, fmt.Errorf("filelog: kubernetes enrichment requires CRI format")
		}
		if cfg.Kubernetes.PodLogsRoot == "" {
			cfg.Kubernetes.PodLogsRoot = "/var/log/pods"
		}
		if !filepath.IsAbs(cfg.Kubernetes.PodLogsRoot) {
			return nil, fmt.Errorf("filelog: kubernetes pod logs root must be an absolute non-root path")
		}
		root := filepath.Clean(cfg.Kubernetes.PodLogsRoot)
		if root == string(filepath.Separator) {
			return nil, fmt.Errorf("filelog: kubernetes pod logs root must be an absolute non-root path")
		}
		cfg.Kubernetes.PodLogsRoot = root
	}
	if cfg.MaxLineBytes < 1 || cfg.MaxBatchBytes < cfg.MaxLineBytes ||
		cfg.MaxReadBytes < int64(cfg.MaxBatchBytes) {
		return nil, fmt.Errorf("filelog: invalid line, batch, or read bounds")
	}
	include, err := absolutePatterns(cfg.Include)
	if err != nil {
		return nil, err
	}
	exclude, err := absolutePatterns(cfg.Exclude)
	if err != nil {
		return nil, err
	}
	cfg.Include, cfg.Exclude = include, exclude
	checkpointPath, err := filepath.Abs(cfg.CheckpointFile)
	if err != nil {
		return nil, fmt.Errorf("filelog checkpoint: absolute path: %w", err)
	}
	cfg.CheckpointFile = checkpointPath
	store, err := loadCheckpointStore(checkpointPath)
	if err != nil {
		return nil, err
	}
	return &Source{
		cfg: cfg, logger: logger, store: store, redactor: redactor,
		multiline: multiline,
	}, nil
}

func (s *Source) Format() string { return s.cfg.Format }

func absolutePatterns(patterns []string) ([]string, error) {
	out := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		absolute, err := filepath.Abs(pattern)
		if err != nil {
			return nil, fmt.Errorf("filelog pattern %q: %w", pattern, err)
		}
		out = append(out, filepath.Clean(absolute))
	}
	return out, nil
}

func (s *Source) SetLogsEmitter(emit func(context.Context, signal.Envelope) error) {
	s.emit = emit
}

func (s *Source) Start(ctx context.Context, _ func(context.Context, model.Batch) error) error {
	if s.emit == nil {
		return fmt.Errorf("filelog: logs emitter is not configured")
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

func (s *Source) ActiveFiles() int64 { return s.active.Load() }

func (s *Source) setHealth(err error) {
	s.healthMu.Lock()
	s.healthErr = err
	s.healthMu.Unlock()
}

func (s *Source) poll(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if err := s.Healthy(); err != nil {
		if err := s.persistCheckpoint(); err != nil {
			return
		}
	}
	paths, err := s.discover()
	if err != nil {
		selfobs.FileLogReadErrors.Inc()
		s.logger.Warn("filelog discovery failed", "err", err)
		return
	}
	s.active.Store(int64(len(paths)))
	for _, path := range paths {
		if ctx.Err() != nil {
			return
		}
		if err := s.tailPath(ctx, path); err != nil {
			if checkpointErr := s.Healthy(); checkpointErr != nil {
				s.logger.Warn("filelog checkpoint unavailable; pausing collection",
					"err", checkpointErr)
				return
			}
			if errors.Is(err, pipeline.ErrBackpressure) {
				selfobs.FileLogBackpressure.Inc()
			}
			if pipeline.IsLoggableEmitError(ctx, err) {
				if errors.Is(err, errAdmission) {
					selfobs.FileLogAdmissionErrors.Inc()
				} else {
					selfobs.FileLogReadErrors.Inc()
				}
				s.logger.Warn("filelog tail failed", "path", path, "err", err)
			}
		}
	}
}

func (s *Source) discover() ([]string, error) {
	seen := make(map[string]struct{})
	for _, pattern := range s.cfg.Include {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("include glob %q: %w", pattern, err)
		}
		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil || !info.Mode().IsRegular() || s.excluded(path) {
				continue
			}
			seen[filepath.Clean(path)] = struct{}{}
		}
	}
	paths := mapsKeys(seen)
	slices.Sort(paths)
	return paths, nil
}

func mapsKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	return out
}

func (s *Source) excluded(path string) bool {
	checkpointTempPrefix := filepath.Join(
		filepath.Dir(s.cfg.CheckpointFile),
		"."+filepath.Base(s.cfg.CheckpointFile)+".tmp-",
	)
	if path == s.cfg.CheckpointFile || strings.HasPrefix(path, checkpointTempPrefix) {
		return true
	}
	for _, pattern := range s.cfg.Exclude {
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
	}
	return false
}

func (s *Source) tailPath(ctx context.Context, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	currentIdentity, err := fileIdentity(info)
	if err != nil {
		return err
	}
	state, known := s.store.files[path]
	if !known {
		offset := int64(0)
		if s.cfg.StartAt == "end" {
			offset = info.Size()
		}
		s.store.files[path] = checkpoint{Identity: currentIdentity, Offset: offset}
		if err := s.persistCheckpoint(); err != nil {
			return err
		}
		state = s.store.files[path]
	}
	if state.Identity != currentIdentity {
		if rotatedPath := findIdentity(filepath.Dir(path), state.Identity, path); rotatedPath != "" {
			drained, err := s.readFile(ctx, path, rotatedPath, state, true)
			if err != nil || !drained {
				return err
			}
		} else {
			selfobs.FileLogRotationMisses.Inc()
		}
		selfobs.FileLogRotations.Inc()
		s.store.files[path] = checkpoint{Identity: currentIdentity, Offset: 0}
		if err := s.persistCheckpoint(); err != nil {
			return err
		}
		state = s.store.files[path]
	}
	if info.Size() < state.Offset {
		selfobs.FileLogTruncations.Inc()
		state = checkpoint{Identity: currentIdentity}
		s.store.files[path] = state
		if err := s.persistCheckpoint(); err != nil {
			return err
		}
	}
	_, err = s.readFile(ctx, path, path, s.store.files[path], false)
	return err
}

func findIdentity(dir, identity, currentPath string) string {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > maxDirectoryEntries {
		return ""
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if path == currentPath || entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		id, err := fileIdentity(info)
		if err == nil && id == identity {
			return path
		}
	}
	return ""
}

func (s *Source) readFile(ctx context.Context, keyPath, readPath string, state checkpoint, flushPartial bool) (bool, error) {
	if s.cfg.Format == "cri" {
		if state.MultilineDropping {
			state.MultilineDropping = false
			s.store.files[keyPath] = state
			if err := s.persistCheckpoint(); err != nil {
				return false, err
			}
		}
		return s.readCRIFile(ctx, keyPath, readPath, state, flushPartial)
	}
	if state.CRIDropping {
		state.CRIDropping = false
		s.store.files[keyPath] = state
		if err := s.persistCheckpoint(); err != nil {
			return false, err
		}
	}
	if s.multiline != nil {
		return s.readMultilineFile(
			ctx,
			keyPath,
			readPath,
			state,
			flushPartial,
		)
	}
	if state.MultilineDropping {
		state.MultilineDropping = false
		s.store.files[keyPath] = state
		if err := s.persistCheckpoint(); err != nil {
			return false, err
		}
	}
	return s.readTextFile(ctx, keyPath, readPath, state, flushPartial)
}

func (s *Source) readTextFile(ctx context.Context, keyPath, readPath string, state checkpoint, flushPartial bool) (bool, error) {
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
		records    []*logspb.LogRecord
		batchBytes int
		batchEnd   = state.Offset
		line       []byte
		oversized  = state.Dropping
		lineStart  = offset
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
	for readBytes < s.cfg.MaxReadBytes {
		part, readErr := reader.ReadSlice('\n')
		offset += int64(len(part))
		readBytes += int64(len(part))
		selfobs.FileLogBytesRead.Add(uint64(len(part)))
		if !oversized {
			if len(line)+len(part) > s.cfg.MaxLineBytes+1 {
				oversized = true
				line = nil
			} else {
				line = append(line, part...)
			}
		}
		complete := readErr == nil
		if errors.Is(readErr, io.EOF) && flushPartial && (len(part) > 0 || oversized) {
			complete = true
		}
		if complete {
			if oversized {
				if err := flush(); err != nil {
					return false, err
				}
				selfobs.FileLogOversized.Inc()
				state.Offset = offset
				state.Dropping = false
				s.store.files[keyPath] = state
				if err := s.persistCheckpoint(); err != nil {
					return false, err
				}
			} else {
				line = bytesTrimLineEnding(line)
				redacted, keep := s.redactLogBody(line)
				if !keep {
					if err := flush(); err != nil {
						return false, err
					}
					state.Offset = offset
					state.Dropping = false
					s.store.files[keyPath] = state
					if err := s.persistCheckpoint(); err != nil {
						return false, err
					}
				} else {
					record := newLogRecord(redacted, keyPath, lineStart)
					recordBytes := proto.Size(record)
					if batchBytes+recordBytes > s.cfg.MaxBatchBytes && len(records) > 0 {
						if err := flush(); err != nil {
							return false, err
						}
					}
					records = append(records, record)
					batchBytes += recordBytes
					batchEnd = offset
				}
			}
			line = nil
			oversized = false
			lineStart = offset
		}
		switch {
		case readErr == nil:
			continue
		case errors.Is(readErr, bufio.ErrBufferFull):
			continue
		case errors.Is(readErr, io.EOF):
			if err := flush(); err != nil {
				return false, err
			}
			if oversized {
				state.Offset = offset
				state.Dropping = true
				s.store.files[keyPath] = state
				if err := s.persistCheckpoint(); err != nil {
					return false, err
				}
				return false, nil
			}
			return len(line) == 0, nil
		default:
			return false, readErr
		}
	}
	if err := flush(); err != nil {
		return false, err
	}
	if oversized {
		state.Offset = offset
		state.Dropping = true
		s.store.files[keyPath] = state
		if err := s.persistCheckpoint(); err != nil {
			return false, err
		}
	}
	return false, nil
}

func bytesTrimLineEnding(line []byte) []byte {
	line = slices.Clone(line)
	line = bytesTrimSuffix(line, '\n')
	return bytesTrimSuffix(line, '\r')
}

func bytesTrimSuffix(value []byte, suffix byte) []byte {
	if len(value) > 0 && value[len(value)-1] == suffix {
		return value[:len(value)-1]
	}
	return value
}

func newLogRecord(line []byte, path string, offset int64) *logspb.LogRecord {
	body := strings.ToValidUTF8(string(line), "?")
	return &logspb.LogRecord{
		ObservedTimeUnixNano: uint64(time.Now().UnixNano()),
		Body: &commonpb.AnyValue{
			Value: &commonpb.AnyValue_StringValue{StringValue: body},
		},
		Attributes: []*commonpb.KeyValue{
			{
				Key: "log.file.path",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_StringValue{StringValue: path},
				},
			},
			{
				Key: "wisp.file.offset",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_IntValue{IntValue: offset},
				},
			},
		},
	}
}

func (s *Source) emitRecords(
	ctx context.Context,
	path string,
	records []*logspb.LogRecord,
) error {
	resource, identityAttributes, enriched := s.resourceForPath(path)
	request := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: resource,
			ScopeLogs: []*logspb.ScopeLogs{{
				Scope: &commonpb.InstrumentationScope{
					Name: "github.com/yaop-labs/wisp/filelog",
				},
				LogRecords: records,
			}},
		}},
	}
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(request)
	if err != nil {
		return fmt.Errorf("%w: filelog encode OTLP Logs: %v", pipeline.ErrPermanent, err)
	}
	identity, ok := signal.ResourceIdentity(identityAttributes)
	if !ok {
		identity = nil
	}
	envelope, err := signal.New(
		signal.Logs, signal.OTLPLogsSchema, signal.OTLPProtobufEncoding,
		payload, identity,
	)
	if err != nil {
		return err
	}
	if err := s.emit(ctx, envelope); err != nil {
		return err
	}
	selfobs.FileLogRecords.Add(uint64(len(records)))
	selfobs.FileLogBatches.Inc()
	if s.cfg.Kubernetes != nil {
		if enriched {
			selfobs.FileLogKubernetesEnriched.Add(uint64(len(records)))
		} else {
			selfobs.FileLogKubernetesMisses.Add(uint64(len(records)))
		}
	}
	return nil
}

func (s *Source) resourceForPath(
	path string,
) (*resourcepb.Resource, map[string]string, bool) {
	stringValues := maps.Clone(s.cfg.Resource)
	if stringValues == nil {
		stringValues = make(map[string]string)
	}
	values := make(map[string]*commonpb.AnyValue, len(stringValues)+5)
	for key, value := range stringValues {
		values[key] = &commonpb.AnyValue{
			Value: &commonpb.AnyValue_StringValue{StringValue: value},
		}
	}
	enriched := false
	if s.cfg.Kubernetes != nil {
		metadata, ok := parseKubernetesPodLogPath(
			s.cfg.Kubernetes.PodLogsRoot,
			path,
		)
		if ok {
			enriched = true
			kubernetesStrings := map[string]string{
				"k8s.namespace.name": metadata.namespace,
				"k8s.pod.name":       metadata.podName,
				"k8s.pod.uid":        metadata.podUID,
				"k8s.container.name": metadata.container,
			}
			for key, value := range kubernetesStrings {
				stringValues[key] = value
				values[key] = &commonpb.AnyValue{
					Value: &commonpb.AnyValue_StringValue{StringValue: value},
				}
			}
			delete(stringValues, "k8s.container.restart_count")
			values["k8s.container.restart_count"] = &commonpb.AnyValue{
				Value: &commonpb.AnyValue_IntValue{
					IntValue: metadata.restartCount,
				},
			}
		}
	}
	resource := &resourcepb.Resource{}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		resource.Attributes = append(resource.Attributes, &commonpb.KeyValue{
			Key:   key,
			Value: values[key],
		})
	}
	return resource, stringValues, enriched
}

func (s *Source) persistCheckpoint() error {
	if err := s.store.save(); err != nil {
		selfobs.FileLogCheckpointErrors.Inc()
		s.setHealth(err)
		return err
	}
	s.setHealth(nil)
	return nil
}
