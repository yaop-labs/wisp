// Package retry wraps an exporter with bounded exponential backoff for transient
// failures. Persistent failures fall through to the caller (the spool), so retry
// handles blips and the spool handles outages.
package retry

import (
	"context"
	"errors"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/signal"
)

// Config tunes the backoff.
type Config struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

// Exporter retries inner.Export with exponential backoff.
type Exporter struct {
	inner pipeline.Exporter
	cfg   Config
}

func Wrap(inner pipeline.Exporter, cfg Config) *Exporter {
	cfg = normalize(cfg)
	return &Exporter{inner: inner, cfg: cfg}
}

func normalize(cfg Config) Config {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = 200 * time.Millisecond
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 10 * time.Second
	}
	return cfg
}

func (e *Exporter) Export(ctx context.Context, b model.Batch) error {
	backoff := e.cfg.InitialBackoff
	var err error
	for attempt := 0; attempt < e.cfg.MaxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
			backoff *= 2
			if backoff > e.cfg.MaxBackoff {
				backoff = e.cfg.MaxBackoff
			}
		}
		if err = e.inner.Export(ctx, b); err == nil {
			return nil
		}
		if errors.Is(err, pipeline.ErrPermanent) {
			return err // the batch is bad; retrying can't help (spool quarantines it)
		}
	}
	return err
}

func (e *Exporter) Close() error { return e.inner.Close() }

// SignalSender applies the same retry policy to signal-neutral exporters.
type SignalSender struct {
	inner signal.Sender
	cfg   Config
}

func WrapSender(inner signal.Sender, cfg Config) *SignalSender {
	return &SignalSender{inner: inner, cfg: normalize(cfg)}
}

func (s *SignalSender) Send(ctx context.Context, envelope signal.Envelope) error {
	backoff := s.cfg.InitialBackoff
	var err error
	for attempt := 0; attempt < s.cfg.MaxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
			backoff *= 2
			if backoff > s.cfg.MaxBackoff {
				backoff = s.cfg.MaxBackoff
			}
		}
		if err = s.inner.Send(ctx, envelope); err == nil {
			return nil
		}
		if errors.Is(err, pipeline.ErrPermanent) {
			return err
		}
	}
	return err
}

func (s *SignalSender) Close() error { return s.inner.Close() }
