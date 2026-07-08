// Package reset normalizes counter resets at the edge. amber's rate/increase
// engine assumes monotonic cumulative counters; when a scrape target restarts,
// its counter drops back toward zero and the rate goes negative. This processor
// tracks each counter series and carries the pre-reset total forward as an
// offset, so the shipped counter stays monotonic across target restarts.
package reset

import (
	"context"
	"math"
	"sync"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/selfobs"
)

// defaultMaxSeries bounds the per-series state map so a long-running agent with
// churning series (e.g. pods coming and going) can't leak memory without limit.
// ~1M counter series of state is tens of MB; beyond it, new series pass through
// un-normalized and wisp_reset_untracked_total counts them.
const defaultMaxSeries = 1 << 20

// Processor rewrites monotonic counters to be reset-free. Gauges and
// non-monotonic sums pass through untouched.
type Processor struct {
	maxSeries int

	mu    sync.Mutex
	state map[string]*counterState
}

type counterState struct {
	lastRaw float64
	offset  float64
}

func New() *Processor {
	return &Processor{maxSeries: defaultMaxSeries, state: make(map[string]*counterState)}
}

func (p *Processor) Process(_ context.Context, b model.Batch) (model.Batch, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for si := range b.Series {
		s := &b.Series[si]
		if s.Type != model.MetricSum || !s.Monotonic {
			continue
		}
		key := seriesKey(s)
		for pi := range s.Points {
			pt := &s.Points[pi]
			raw := pointValue(pt)
			st := p.state[key]
			if st == nil {
				if len(p.state) >= p.maxSeries {
					// Tracker is full: pass the point through un-normalized rather
					// than grow state without bound.
					selfobs.ResetUntracked.Inc()
					continue
				}
				// First observation of this series: adopt it as the baseline.
				st = &counterState{lastRaw: raw}
				p.state[key] = st
			} else {
				if raw < st.lastRaw {
					st.offset += st.lastRaw // reset: carry the pre-reset total forward
				}
				st.lastRaw = raw
			}
			setPointValue(pt, raw+st.offset)
		}
	}
	return b, nil
}

func (p *Processor) Close() error { return nil }

func pointValue(p *model.Point) float64 {
	if p.IsFloat {
		return p.FloatValue
	}
	return float64(p.IntValue)
}

// setPointValue writes v back, keeping the exact int path when the input was an
// integer counter and v is still integral (the common case - amber stores int
// counters without a scale factor).
func setPointValue(p *model.Point, v float64) {
	if !p.IsFloat && v == math.Trunc(v) && math.Abs(v) < 9.2e18 {
		p.IntValue = int64(v)
		return
	}
	p.FloatValue = v
	p.IsFloat = true
}

func seriesKey(s *model.Series) string {
	return s.Name + "\x00" + model.CanonicalKey(s.Resource) + "\x00" + model.CanonicalKey(s.Attrs)
}
