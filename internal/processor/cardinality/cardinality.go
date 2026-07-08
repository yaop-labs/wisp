// Package cardinality bounds series growth at the edge, before export. Each
// target (resource) gets its own series budget; once full, new series are
// dropped and counted while already-admitted series keep flowing.
package cardinality

import (
	"context"
	"sync"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/selfobs"
)

// defaultMaxSeries caps the total number of tracked series identities so a
// churning target population (e.g. pods with unique instance IDs) can't grow the
// tracker without bound. Beyond it, new series pass through un-budgeted and
// wisp_cardinality_untracked_total counts them. Matches the reset processor's
// bound.
const defaultMaxSeries = 1 << 20

// Processor enforces a per-resource active-series budget plus a per-series label
// limit - the two edge guards that mirror amber's MaxActiveSeries /
// MaxLabelsPerSeries, applied before data hits the network.
type Processor struct {
	maxPerTarget int
	maxLabels    int
	maxSeries    int

	mu      sync.Mutex
	seen    map[string]map[string]struct{} // resourceKey -> set of series identities
	tracked int                            // total identities across all targets
}

// New builds a guard. maxPerTarget <= 0 disables the series budget; maxLabels
// <= 0 disables the label-count limit (both passthrough when zero).
func New(maxPerTarget, maxLabels int) *Processor {
	return &Processor{
		maxPerTarget: maxPerTarget,
		maxLabels:    maxLabels,
		maxSeries:    defaultMaxSeries,
		seen:         make(map[string]map[string]struct{}),
	}
}

func (p *Processor) Process(_ context.Context, b model.Batch) (model.Batch, error) {
	if p.maxPerTarget <= 0 && p.maxLabels <= 0 {
		return b, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make([]model.Series, 0, len(b.Series))
	for _, s := range b.Series {
		// Label-count guard: drop label-set explosions amber would reject anyway.
		if p.maxLabels > 0 && len(s.Resource)+len(s.Attrs) > p.maxLabels {
			selfobs.LabelLimitDropped.Inc()
			continue
		}
		if p.maxPerTarget <= 0 {
			out = append(out, s)
			continue
		}
		rk := model.CanonicalKey(s.Resource)
		set := p.seen[rk]
		fp := seriesKey(s.Name, s.Attrs)
		if set != nil {
			if _, ok := set[fp]; ok {
				out = append(out, s) // already admitted; keep it flowing
				continue
			}
			if len(set) >= p.maxPerTarget {
				selfobs.CardinalityDropped.Inc()
				continue
			}
		}
		// A new series identity. Bound the total tracked set so a churning target
		// population can't grow state without limit; once full, admit new series
		// un-budgeted rather than drop or leak, and count them.
		if p.tracked >= p.maxSeries {
			selfobs.CardinalityUntracked.Inc()
			out = append(out, s)
			continue
		}
		if set == nil {
			set = make(map[string]struct{})
			p.seen[rk] = set
		}
		set[fp] = struct{}{}
		p.tracked++
		out = append(out, s)
	}
	return model.Batch{Series: out}, nil
}

func (p *Processor) Close() error { return nil }

func seriesKey(name string, attrs model.Labels) string {
	return name + "\x00" + model.CanonicalKey(attrs)
}
