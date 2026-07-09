// Package reset normalizes counter resets at the edge. amber's rate/increase
// engine assumes monotonic cumulative counters; when a scrape target restarts,
// its counter drops back toward zero and the rate goes negative. This processor
// tracks each counter series and carries the pre-reset total forward as an
// offset, so the shipped counter stays monotonic across target restarts.
package reset

import (
	"context"
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
	lastRaw  float64
	offset   float64
	lastTime uint64 // TimeUnixNano of the newest point that advanced this state
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
			raw := pt.Value()
			st := p.state[key]
			switch {
			case st == nil:
				if len(p.state) >= p.maxSeries {
					// Tracker is full: pass the point through un-normalized rather
					// than grow state without bound.
					selfobs.ResetUntracked.Inc()
					continue
				}
				// First observation of this series: adopt it as the baseline.
				st = &counterState{lastRaw: raw, lastTime: pt.TimeUnixNano}
				p.state[key] = st
			case pt.TimeUnixNano < st.lastTime:
				// Out-of-order point. The pipeline hands batches to NumCPU workers
				// off one queue with no per-source ordering, so a newer scrape of
				// this series can be processed before an older one. Reading
				// raw < lastRaw as a reset here would carry lastRaw into the offset
				// permanently (a phantom rate spike in amber that never
				// self-corrects). Emit with the current offset but let the newer
				// point keep ownership of the state.
				selfobs.ResetReordered.Inc()
			default:
				if raw < st.lastRaw {
					st.offset += st.lastRaw // reset: carry the pre-reset total forward
				}
				st.lastRaw = raw
				st.lastTime = pt.TimeUnixNano
			}
			setPointValue(pt, raw+st.offset)
		}
	}
	return b, nil
}

func (p *Processor) Close() error { return nil }

// setPointValue writes v back, keeping the exact int path when the input was an
// integer counter (amber stores int counters without a scale factor); a float
// counter stays float.
func setPointValue(p *model.Point, v float64) {
	if p.IsFloat {
		p.FloatValue = v
		return
	}
	p.SetValue(v)
}

func seriesKey(s *model.Series) string {
	return s.Name + "\x00" + model.CanonicalKey(s.Resource) + "\x00" + model.CanonicalKey(s.Attrs)
}
