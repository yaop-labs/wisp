// Package spool is the on-disk durability queue. When the wrapped exporter
// fails, the batch is written to disk instead of dropped and a background
// drainer re-sends it once downstream recovers. Spooled batches survive
// restarts (the drainer picks up existing files on startup). The queue is
// bounded by max_bytes (oldest dropped) and crash-safe via temp-file + rename.
package spool

import (
	"bytes"
	"context"
	"encoding/gob"
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

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
)

const fileSuffix = ".batch"

// Durability bounds applied when the config leaves them unset (0), so an enabled
// spool is always bounded and self-expiring rather than able to fill the disk.
const (
	defaultMaxBytes = 512 << 20     // 512 MiB
	defaultMaxAge   = 6 * time.Hour // spooled data older than this is dropped
)

// Config configures the spool.
type Config struct {
	Dir           string
	MaxBytes      int64         // hard cap; oldest dropped to stay under it. 0 -> 512MiB default; <0 unbounded.
	MaxAge        time.Duration // drop spooled batches older than this. 0 -> 6h default; <0 disables.
	HighWatermark int64         // bytes; backpressure engages at/above. Default 80% of MaxBytes.
	LowWatermark  int64         // bytes; backpressure releases at/below. Default 50% of MaxBytes.
	DrainInterval time.Duration
}

// Exporter wraps inner with an on-disk fallback queue.
type Exporter struct {
	inner    pipeline.Exporter
	dir      string
	maxBytes int64
	maxAge   time.Duration
	highWM   int64
	lowWM    int64
	logger   *slog.Logger

	mu      sync.Mutex // serializes enqueue/eviction disk mutations
	drainMu sync.Mutex // ensures only one drain pass runs at a time
	seq     atomic.Uint64

	// curBytes/curCount are an O(1) view of the on-disk depth, seeded from the
	// directory at startup (so files left by a previous run count) and kept in
	// step at every add/remove site. They back UnderPressure and the gauges.
	curBytes atomic.Int64
	curCount atomic.Int64
	pressure atomic.Bool

	// unhealthy latches a durability failure: the last attempt to persist a
	// batch hit an I/O error. Cleared on the next successful write. Surfaced via
	// Healthy() to the agent's /healthz so a broken spool fails readiness.
	unhealthy atomic.Bool

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(inner pipeline.Exporter, cfg Config, logger *slog.Logger) (*Exporter, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("spool: dir required")
	}
	if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("spool: mkdir %s: %w", cfg.Dir, err)
	}
	if cfg.DrainInterval <= 0 {
		cfg.DrainInterval = 5 * time.Second
	}
	// Default the durability bounds so an enabled-but-unconfigured spool is still
	// bounded and self-expiring. A negative value is an explicit opt-out
	// (unbounded size / never expire).
	switch {
	case cfg.MaxBytes == 0:
		cfg.MaxBytes = defaultMaxBytes
	case cfg.MaxBytes < 0:
		cfg.MaxBytes = 0 // unbounded
	}
	switch {
	case cfg.MaxAge == 0:
		cfg.MaxAge = defaultMaxAge
	case cfg.MaxAge < 0:
		cfg.MaxAge = 0 // expiry disabled
	}
	// Default watermarks at 80%/50% of the hard cap when not set explicitly.
	if cfg.MaxBytes > 0 {
		if cfg.HighWatermark <= 0 || cfg.HighWatermark > cfg.MaxBytes {
			cfg.HighWatermark = cfg.MaxBytes * 4 / 5
		}
		if cfg.LowWatermark <= 0 || cfg.LowWatermark >= cfg.HighWatermark {
			cfg.LowWatermark = cfg.MaxBytes / 2
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Exporter{
		inner: inner, dir: cfg.Dir, maxBytes: cfg.MaxBytes, maxAge: cfg.MaxAge,
		highWM: cfg.HighWatermark, lowWM: cfg.LowWatermark, logger: logger, cancel: cancel,
	}
	e.cleanupTemp() // discard torn .tmp files from a previous crash
	e.seedDepth()   // count pre-existing files (durable across restarts)
	e.wg.Add(1)
	go e.drainLoop(ctx, cfg.DrainInterval)
	return e, nil
}

// cleanupTemp removes leftover *.tmp files: a crash mid-write leaves a temp file
// that was never renamed to a final ".batch", so it holds a partial (torn)
// record. Dropping them keeps the queue free of undecodable junk.
func (e *Exporter) cleanupTemp() {
	entries, err := os.ReadDir(e.dir)
	if err != nil {
		return
	}
	for _, ent := range entries {
		if !ent.IsDir() && filepath.Ext(ent.Name()) == ".tmp" {
			_ = os.Remove(filepath.Join(e.dir, ent.Name()))
		}
	}
}

// Healthy reports whether the spool's last persistence attempt succeeded. A
// false result means the durability layer is failing (e.g. disk full / I/O
// error) and the agent should be considered not-ready.
func (e *Exporter) Healthy() bool { return !e.unhealthy.Load() }

// seedDepth initializes the cached depth from files already on disk.
func (e *Exporter) seedDepth() {
	files := e.sortedFiles()
	var total int64
	for _, f := range files {
		total += f.size
	}
	e.curBytes.Store(total)
	e.curCount.Store(int64(len(files)))
	e.updatePressure()
}

// Bytes returns the current on-disk spool size (cached, O(1)).
func (e *Exporter) Bytes() int64 { return e.curBytes.Load() }

// Count returns the current number of spooled batches (cached, O(1)).
func (e *Exporter) Count() int64 { return e.curCount.Load() }

// UnderPressure reports whether the spool has crossed its high-water mark and
// has not yet drained back below the low mark (hysteresis). Always false when
// the spool is unbounded (MaxBytes <= 0).
func (e *Exporter) UnderPressure() bool { return e.pressure.Load() }

// updatePressure recomputes the backpressure flag from cached bytes with
// hysteresis: engage at/above highWM, release at/below lowWM, hold in between.
func (e *Exporter) updatePressure() {
	if e.maxBytes <= 0 || e.highWM <= 0 {
		return // unbounded: no backpressure
	}
	b := e.curBytes.Load()
	switch {
	case b >= e.highWM:
		if e.pressure.CompareAndSwap(false, true) {
			e.logger.Warn("spool backpressure engaged", "bytes", b, "high_watermark", e.highWM)
		}
	case b <= e.lowWM:
		if e.pressure.CompareAndSwap(true, false) {
			e.logger.Info("spool backpressure released", "bytes", b, "low_watermark", e.lowWM)
		}
	}
}

// Export ships through inner; on failure the batch is durably spooled and the
// call still returns nil (accepted = either sent or persisted).
func (e *Exporter) Export(ctx context.Context, b model.Batch) error {
	if err := e.inner.Export(ctx, b); err == nil {
		return nil
	}
	if err := e.enqueue(b); err != nil {
		// Durability failure: downstream is down AND we can't persist. Surface
		// it loudly (counter + ERROR + unhealthy) instead of silently losing
		// data - orchestration can then restart the agent.
		selfobs.SpoolWriteErrors.Inc()
		e.unhealthy.Store(true)
		e.logger.Error("spool: persistence failed, data not durable", "err", err)
		return fmt.Errorf("spool: enqueue: %w", err)
	}
	e.unhealthy.Store(false)
	selfobs.SpoolEnqueued.Inc()
	return nil
}

func (e *Exporter) enqueue(b model.Batch) error {
	data, err := encode(b)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ensureRoom(int64(len(data)))

	name := fmt.Sprintf("%020d-%06d%s", time.Now().UnixNano(), e.seq.Add(1), fileSuffix)
	final := filepath.Join(e.dir, name)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	e.curBytes.Add(int64(len(data)))
	e.curCount.Add(1)
	e.updatePressure()
	return nil
}

// ensureRoom drops oldest batches until data of size need fits within maxBytes.
// Caller holds e.mu. maxBytes <= 0 means unbounded.
func (e *Exporter) ensureRoom(need int64) {
	if e.maxBytes <= 0 {
		return
	}
	files := e.sortedFiles()
	total := e.curBytes.Load()
	for total+need > e.maxBytes && len(files) > 0 {
		oldest := files[0]
		files = files[1:]
		if err := os.Remove(oldest.path); err == nil {
			total -= oldest.size
			e.curBytes.Add(-oldest.size)
			e.curCount.Add(-1)
			selfobs.SpoolDropped.Inc()
		} else {
			break
		}
	}
	e.updatePressure()
}

func (e *Exporter) drainLoop(ctx context.Context, interval time.Duration) {
	defer e.wg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.expireOld()
			e.drain(ctx)
		}
	}
}

// expireOld drops spooled batches older than maxAge (by the unix-nanos prefix in
// their filename), so a long downstream outage can't keep stale data forever.
func (e *Exporter) expireOld() {
	if e.maxAge <= 0 {
		return
	}
	cutoff := time.Now().Add(-e.maxAge).UnixNano()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, f := range e.sortedFiles() {
		ts, ok := timestampOf(f.path)
		if !ok || ts >= cutoff {
			continue // unparseable names are left for drain to handle
		}
		if err := os.Remove(f.path); err == nil {
			e.curBytes.Add(-f.size)
			e.curCount.Add(-1)
			selfobs.SpoolExpired.Inc()
		}
	}
	e.updatePressure()
}

// drain re-sends spooled batches oldest-first, stopping at the first failure
// (downstream still down) so it doesn't hammer a dead endpoint. drainMu makes
// passes mutually exclusive so the background loop and Flush never double-send.
func (e *Exporter) drain(ctx context.Context) {
	e.drainMu.Lock()
	defer e.drainMu.Unlock()

	e.mu.Lock()
	files := e.sortedFiles()
	e.mu.Unlock()

	for _, f := range files {
		if ctx.Err() != nil {
			return
		}
		data, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		b, err := decode(data)
		if err != nil {
			// Corrupt entry: drop it rather than block the queue forever.
			e.logger.Warn("spool: dropping undecodable batch", "file", f.path, "err", err)
			if rmErr := os.Remove(f.path); rmErr == nil {
				e.curBytes.Add(-f.size)
				e.curCount.Add(-1)
				selfobs.SpoolDropped.Inc()
			}
			continue
		}
		if err := e.inner.Export(ctx, b); err != nil {
			if errors.Is(err, pipeline.ErrPermanent) {
				// Downstream rejects this batch permanently (malformed/oversized).
				// Discard it so it can't wedge the head of the queue forever;
				// newer batches behind it still get a chance to drain.
				e.logger.Warn("spool: quarantining permanently-rejected batch", "file", f.path, "err", err)
				if rmErr := os.Remove(f.path); rmErr == nil {
					e.curBytes.Add(-f.size)
					e.curCount.Add(-1)
					selfobs.SpoolQuarantined.Inc()
				}
				continue
			}
			e.updatePressure()
			return // still failing; try again next tick
		}
		if rmErr := os.Remove(f.path); rmErr == nil {
			e.curBytes.Add(-f.size)
			e.curCount.Add(-1)
			selfobs.SpoolDrained.Inc()
		}
	}
	e.updatePressure()
}

// timestampOf extracts the unix-nanos prefix from a spool filename
// ("<nanos>-<seq>.batch"). Returns false if the name isn't in that form.
func timestampOf(path string) (int64, bool) {
	name := filepath.Base(path)
	dash := strings.IndexByte(name, '-')
	if dash <= 0 {
		return 0, false
	}
	ts, err := strconv.ParseInt(name[:dash], 10, 64)
	if err != nil {
		return 0, false
	}
	return ts, true
}

type spoolFile struct {
	path string
	size int64
}

// sortedFiles lists spool entries oldest-first (names are time-ordered).
func (e *Exporter) sortedFiles() []spoolFile {
	entries, err := os.ReadDir(e.dir)
	if err != nil {
		return nil
	}
	var files []spoolFile
	for _, ent := range entries {
		if ent.IsDir() || filepath.Ext(ent.Name()) != fileSuffix {
			continue
		}
		info, err := ent.Info()
		if err != nil {
			continue
		}
		files = append(files, spoolFile{path: filepath.Join(e.dir, ent.Name()), size: info.Size()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	return files
}

// Flush makes a best-effort final drain of the spool, bounded by ctx. The
// pipeline calls it on graceful shutdown so a clean stop doesn't strand spooled
// data when downstream is healthy. If downstream is still down it returns
// quickly (a drain pass that makes no progress) - the data stays durable on
// disk for the next start.
func (e *Exporter) Flush(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		before := e.curCount.Load()
		e.drain(ctx)
		after := e.curCount.Load()
		if after == 0 || after >= before {
			return nil // emptied, or no progress (downstream down)
		}
	}
}

func (e *Exporter) Close() error {
	e.cancel()
	e.wg.Wait()
	return e.inner.Close()
}

func encode(b model.Batch) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decode(data []byte) (model.Batch, error) {
	var b model.Batch
	err := gob.NewDecoder(bytes.NewReader(data)).Decode(&b)
	return b, err
}
