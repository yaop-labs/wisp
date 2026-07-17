// Package spool provides a signal-neutral, crash-safe on-disk durability
// queue. Signal-specific adapters own payload encoding and downstream delivery.
package spool

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
	"github.com/yaop-labs/wisp/internal/signal"
)

const (
	fileSuffix       = ".envelope"
	legacyFileSuffix = ".batch"
)

const (
	defaultMaxBytes = 512 << 20
	defaultMaxAge   = 6 * time.Hour
)

// ErrRecordTooLarge means one encoded envelope cannot fit a configured hard
// limit even when its queue is otherwise empty.
var ErrRecordTooLarge = errors.New("spool: record exceeds queue limit")

// Sender is kept as an alias for source compatibility. New signal-neutral
// components should depend on signal.Sender directly.
type Sender = signal.Sender

// SignalLimit optionally applies an independent cap and pressure band to one
// signal. A zero MaxBytes means the signal only shares the global budget.
type SignalLimit struct {
	MaxBytes      int64
	HighWatermark int64
	LowWatermark  int64
}

// Config configures the spool.
type Config struct {
	Dir           string
	MaxBytes      int64         // global hard cap. 0 -> 512MiB default; <0 unbounded.
	MaxAge        time.Duration // 0 -> 6h default; <0 disables expiry.
	HighWatermark int64         // global pressure engages at/above; default 80%.
	LowWatermark  int64         // global pressure releases at/below; default 50%.
	DrainInterval time.Duration
	SignalLimits  map[signal.Kind]SignalLimit
}

type depth struct {
	bytes    atomic.Int64
	count    atomic.Int64
	pressure atomic.Bool
}

// Queue is the signal-neutral durability core.
type Queue struct {
	sender   Sender
	dir      string
	maxBytes int64
	maxAge   time.Duration
	highWM   int64
	lowWM    int64
	limits   map[signal.Kind]SignalLimit
	logger   *slog.Logger
	syncDir  func(string) error

	mu      sync.Mutex
	drainMu sync.Mutex
	seq     atomic.Uint64

	curBytes  atomic.Int64
	curCount  atomic.Int64
	pressure  atomic.Bool
	unhealthy atomic.Bool

	depthMu sync.Mutex
	depths  map[signal.Kind]*depth

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewQueue(sender Sender, cfg Config, logger *slog.Logger) (*Queue, error) {
	if sender == nil {
		return nil, fmt.Errorf("spool: sender required")
	}
	if cfg.Dir == "" {
		return nil, fmt.Errorf("spool: dir required")
	}
	if err := os.MkdirAll(cfg.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("spool: mkdir %s: %w", cfg.Dir, err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.DrainInterval <= 0 {
		cfg.DrainInterval = 5 * time.Second
	}
	switch {
	case cfg.MaxBytes == 0:
		cfg.MaxBytes = defaultMaxBytes
	case cfg.MaxBytes < 0:
		cfg.MaxBytes = 0
	}
	switch {
	case cfg.MaxAge == 0:
		cfg.MaxAge = defaultMaxAge
	case cfg.MaxAge < 0:
		cfg.MaxAge = 0
	}
	cfg.HighWatermark, cfg.LowWatermark = watermarks(
		cfg.MaxBytes, cfg.HighWatermark, cfg.LowWatermark,
	)

	limits := make(map[signal.Kind]SignalLimit, len(cfg.SignalLimits))
	for kind, limit := range cfg.SignalLimits {
		if !signal.IsValidKind(kind) {
			return nil, fmt.Errorf("spool: invalid signal limit kind %q", kind)
		}
		if limit.MaxBytes < 0 {
			return nil, fmt.Errorf("spool: negative max bytes for signal %q", kind)
		}
		if limit.MaxBytes == 0 {
			continue
		}
		if limit.HighWatermark < 0 || limit.HighWatermark > limit.MaxBytes {
			return nil, fmt.Errorf("spool: invalid high watermark for signal %q", kind)
		}
		if limit.LowWatermark < 0 ||
			(limit.HighWatermark > 0 && limit.LowWatermark >= limit.HighWatermark) {
			return nil, fmt.Errorf("spool: invalid low watermark for signal %q", kind)
		}
		if limit.LowWatermark > 0 && limit.HighWatermark == 0 {
			return nil, fmt.Errorf("spool: signal %q high watermark required with low watermark", kind)
		}
		limit.HighWatermark, limit.LowWatermark = watermarks(
			limit.MaxBytes, limit.HighWatermark, limit.LowWatermark,
		)
		limits[kind] = limit
	}

	ctx, cancel := context.WithCancel(context.Background())
	q := &Queue{
		sender: sender, dir: cfg.Dir, maxBytes: cfg.MaxBytes, maxAge: cfg.MaxAge,
		highWM: cfg.HighWatermark, lowWM: cfg.LowWatermark, limits: limits,
		logger: logger, syncDir: syncDir, depths: make(map[signal.Kind]*depth),
		cancel: cancel,
	}
	q.cleanupTemp()
	q.seedDepth()
	q.wg.Add(1)
	go q.drainLoop(ctx, cfg.DrainInterval)
	return q, nil
}

func watermarks(maxBytes, high, low int64) (int64, int64) {
	if maxBytes <= 0 {
		return 0, 0
	}
	if high <= 0 || high > maxBytes {
		high = maxBytes * 4 / 5
		if high == 0 {
			high = 1
		}
	}
	if low <= 0 || low >= high {
		low = maxBytes / 2
		if low >= high {
			low = high - 1
		}
	}
	return high, low
}

func (q *Queue) cleanupTemp() {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return
	}
	for _, ent := range entries {
		if !ent.IsDir() && filepath.Ext(ent.Name()) == ".tmp" {
			_ = os.Remove(filepath.Join(q.dir, ent.Name()))
		}
	}
}

// Accept sends an envelope immediately or persists it after a transient
// downstream failure. Nil means the envelope was delivered or durably accepted.
func (q *Queue) Accept(ctx context.Context, envelope signal.Envelope) error {
	if err := envelope.Validate(); err != nil {
		return fmt.Errorf("spool: invalid envelope: %w", err)
	}
	if err := q.sender.Send(ctx, envelope); err == nil {
		return nil
	} else if errors.Is(err, pipeline.ErrPermanent) {
		return err
	}
	if err := q.enqueue(envelope); err != nil {
		selfobs.SpoolWriteErrors.Inc()
		q.unhealthy.Store(true)
		q.logger.Error("spool: persistence failed, data not durable",
			"signal", envelope.Kind, "err", err)
		return fmt.Errorf("spool: enqueue: %w", err)
	}
	q.unhealthy.Store(false)
	selfobs.SpoolEnqueued.Inc()
	return nil
}

func (q *Queue) enqueue(envelope signal.Envelope) error {
	data, err := envelope.MarshalBinary()
	if err != nil {
		return err
	}
	need := int64(len(data))

	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.ensureRoomLocked(envelope.Kind, need); err != nil {
		return err
	}

	name := fmt.Sprintf("%020d-%06d-%s%s",
		time.Now().UnixNano(), q.seq.Add(1), envelope.Kind, fileSuffix)
	final := filepath.Join(q.dir, name)
	tmp := final + ".tmp"
	defer func() { _ = os.Remove(tmp) }()
	if err := writeFileSync(tmp, data); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	q.addDepth(envelope.Kind, need, 1)
	q.updatePressure(envelope.Kind)
	if err := q.syncDir(q.dir); err != nil {
		return fmt.Errorf("sync spool directory: %w", err)
	}
	return nil
}

func writeFileSync(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}

func (q *Queue) depth(kind signal.Kind) *depth {
	q.depthMu.Lock()
	defer q.depthMu.Unlock()
	d := q.depths[kind]
	if d == nil {
		d = &depth{}
		q.depths[kind] = d
	}
	return d
}

func (q *Queue) addDepth(kind signal.Kind, bytes, count int64) {
	q.curBytes.Add(bytes)
	q.curCount.Add(count)
	d := q.depth(kind)
	d.bytes.Add(bytes)
	d.count.Add(count)
}

func (q *Queue) removeFile(path string, size int64, kind signal.Kind, counter *selfobs.Counter) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.removeFileLocked(path, size, kind, counter)
}

func (q *Queue) removeFileLocked(path string, size int64, kind signal.Kind, counter *selfobs.Counter) bool {
	if err := os.Remove(path); err != nil {
		return false
	}
	q.addDepth(kind, -size, -1)
	counter.Inc()
	q.updatePressure(kind)
	return true
}

func (q *Queue) ensureRoomLocked(kind signal.Kind, need int64) error {
	if q.maxBytes > 0 && need > q.maxBytes {
		return fmt.Errorf("%w: %d > global %d", ErrRecordTooLarge, need, q.maxBytes)
	}
	if limit, ok := q.limits[kind]; ok && need > limit.MaxBytes {
		return fmt.Errorf("%w: %d > %s %d", ErrRecordTooLarge, need, kind, limit.MaxBytes)
	}

	limit, hasLimit := q.limits[kind]
	signalFits := !hasLimit || q.SignalBytes(kind)+need <= limit.MaxBytes
	globalFits := q.maxBytes <= 0 || q.Bytes()+need <= q.maxBytes
	if signalFits && globalFits {
		return nil
	}

	files := q.sortedFiles()
	if hasLimit {
		for _, file := range files {
			if q.SignalBytes(kind)+need <= limit.MaxBytes {
				break
			}
			if file.kind == kind {
				q.removeFileLocked(file.path, file.size, file.kind, selfobs.SpoolDropped)
			}
		}
	}
	if q.maxBytes > 0 {
		for _, file := range files {
			if q.Bytes()+need <= q.maxBytes {
				break
			}
			q.removeFileLocked(file.path, file.size, file.kind, selfobs.SpoolDropped)
		}
	}
	q.updatePressure(kind)
	return nil
}

func (q *Queue) drainLoop(ctx context.Context, interval time.Duration) {
	defer q.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			q.expireOld()
			q.drain(ctx)
		}
	}
}

func (q *Queue) expireOld() {
	if q.maxAge <= 0 {
		return
	}
	cutoff := time.Now().Add(-q.maxAge).UnixNano()
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, file := range q.sortedFiles() {
		ts, ok := timestampOf(file.path)
		if !ok || ts >= cutoff {
			continue
		}
		q.removeFileLocked(file.path, file.size, file.kind, selfobs.SpoolExpired)
		q.updatePressure(file.kind)
	}
}

// drain uses round-robin service between signal kinds. A transient failure
// blocks only that signal for this pass; healthy signals continue draining.
func (q *Queue) drain(ctx context.Context) {
	q.drainMu.Lock()
	defer q.drainMu.Unlock()

	files := q.sortedFiles()
	byKind := make(map[signal.Kind][]spoolFile)
	for _, file := range files {
		byKind[file.kind] = append(byKind[file.kind], file)
	}
	kinds := make([]signal.Kind, 0, len(byKind))
	for kind := range byKind {
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	blocked := make(map[signal.Kind]bool, len(kinds))

	for {
		progress := false
		for _, kind := range kinds {
			if ctx.Err() != nil {
				return
			}
			queue := byKind[kind]
			if blocked[kind] || len(queue) == 0 {
				continue
			}
			file := queue[0]
			byKind[kind] = queue[1:]

			data, err := os.ReadFile(file.path)
			if err != nil {
				continue
			}
			envelope, err := decodeEnvelope(data)
			if err != nil {
				q.logger.Warn("spool: dropping undecodable envelope",
					"file", file.path, "signal", kind, "err", err)
				if q.removeFile(file.path, file.size, file.kind, selfobs.SpoolCorrupt) {
					progress = true
				}
				continue
			}
			if err := q.sender.Send(ctx, envelope); err != nil {
				if errors.Is(err, pipeline.ErrPermanent) {
					q.logger.Warn("spool: quarantining permanently-rejected envelope",
						"file", file.path, "signal", envelope.Kind, "err", err)
					if q.removeFile(file.path, file.size, file.kind, selfobs.SpoolQuarantined) {
						progress = true
					}
					continue
				}
				blocked[kind] = true
				continue
			}
			if q.removeFile(file.path, file.size, file.kind, selfobs.SpoolDrained) {
				progress = true
			}
		}
		if !progress {
			break
		}
	}
	for _, kind := range kinds {
		q.updatePressure(kind)
	}
}

func timestampOf(path string) (int64, bool) {
	name := filepath.Base(path)
	dash := strings.IndexByte(name, '-')
	if dash <= 0 {
		return 0, false
	}
	ts, err := strconv.ParseInt(name[:dash], 10, 64)
	return ts, err == nil
}

type spoolFile struct {
	path string
	size int64
	kind signal.Kind
}

func (q *Queue) sortedFiles() []spoolFile {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return nil
	}
	files := make([]spoolFile, 0, len(entries))
	for _, ent := range entries {
		ext := filepath.Ext(ent.Name())
		if ent.IsDir() || (ext != fileSuffix && ext != legacyFileSuffix) {
			continue
		}
		info, err := ent.Info()
		if err != nil {
			continue
		}
		path := filepath.Join(q.dir, ent.Name())
		files = append(files, spoolFile{
			path: path,
			size: info.Size(),
			kind: kindOfFile(path, ext),
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	return files
}

func kindOfFile(path, ext string) signal.Kind {
	if ext == legacyFileSuffix {
		return signal.Metrics
	}
	stem := strings.TrimSuffix(filepath.Base(path), fileSuffix)
	parts := strings.SplitN(stem, "-", 3)
	if len(parts) == 3 && parts[2] != "" {
		return signal.Kind(parts[2])
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	envelope, err := signal.UnmarshalBinary(data, signal.DefaultMaxPayload)
	if err != nil {
		return ""
	}
	return envelope.Kind
}

func decodeEnvelope(data []byte) (signal.Envelope, error) {
	if signal.IsRecord(data) {
		return signal.UnmarshalBinary(data, signal.DefaultMaxPayload)
	}
	batch, err := decodeLegacy(data)
	if err != nil {
		return signal.Envelope{}, err
	}
	return metricEnvelope(batch)
}

func (q *Queue) seedDepth() {
	for _, file := range q.sortedFiles() {
		q.addDepth(file.kind, file.size, 1)
	}
	q.updatePressure("")
	q.depthMu.Lock()
	kinds := make([]signal.Kind, 0, len(q.depths))
	for kind := range q.depths {
		kinds = append(kinds, kind)
	}
	q.depthMu.Unlock()
	for _, kind := range kinds {
		q.updatePressure(kind)
	}
}

func (q *Queue) updatePressure(kind signal.Kind) {
	if q.maxBytes > 0 && q.highWM > 0 {
		bytes := q.Bytes()
		switch {
		case bytes >= q.highWM:
			if q.pressure.CompareAndSwap(false, true) {
				q.logger.Warn("spool backpressure engaged",
					"bytes", bytes, "high_watermark", q.highWM)
			}
		case bytes <= q.lowWM:
			if q.pressure.CompareAndSwap(true, false) {
				q.logger.Info("spool backpressure released",
					"bytes", bytes, "low_watermark", q.lowWM)
			}
		}
	}
	limit, ok := q.limits[kind]
	if !ok {
		return
	}
	d := q.depth(kind)
	bytes := d.bytes.Load()
	switch {
	case bytes >= limit.HighWatermark:
		d.pressure.Store(true)
	case bytes <= limit.LowWatermark:
		d.pressure.Store(false)
	}
}

func (q *Queue) Healthy() bool       { return !q.unhealthy.Load() }
func (q *Queue) Bytes() int64        { return q.curBytes.Load() }
func (q *Queue) Count() int64        { return q.curCount.Load() }
func (q *Queue) UnderPressure() bool { return q.pressure.Load() }

// SignalDepth is an atomic snapshot intended for status and self-observability.
// The on-disk records remain the authoritative delivery state.
type SignalDepth struct {
	Bytes         int64
	Count         int64
	UnderPressure bool
}

func (q *Queue) SignalBytes(kind signal.Kind) int64 {
	return q.depth(kind).bytes.Load()
}
func (q *Queue) SignalCount(kind signal.Kind) int64 {
	return q.depth(kind).count.Load()
}
func (q *Queue) UnderSignalPressure(kind signal.Kind) bool {
	if _, ok := q.limits[kind]; !ok {
		return q.UnderPressure()
	}
	return q.UnderPressure() || q.depth(kind).pressure.Load()
}

func (q *Queue) DepthBySignal() map[signal.Kind]SignalDepth {
	q.depthMu.Lock()
	defer q.depthMu.Unlock()
	out := make(map[signal.Kind]SignalDepth, len(q.depths))
	globalPressure := q.UnderPressure()
	for kind, d := range q.depths {
		pressure := globalPressure
		if _, limited := q.limits[kind]; limited {
			pressure = pressure || d.pressure.Load()
		}
		out[kind] = SignalDepth{
			Bytes: d.bytes.Load(), Count: d.count.Load(), UnderPressure: pressure,
		}
	}
	return out
}

func (q *Queue) Flush(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		before := q.Count()
		q.drain(ctx)
		after := q.Count()
		if after == 0 || after >= before {
			return nil
		}
	}
}

func (q *Queue) Close() error {
	q.cancel()
	q.wg.Wait()
	return q.sender.Close()
}
