package reset

import (
	"context"
	"testing"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/selfobs"
)

func counter(name string, v int64) model.Batch {
	return model.Batch{Series: []model.Series{{
		Name: name, Type: model.MetricSum, Monotonic: true,
		Resource: model.Labels{{Name: "service.name", Value: "app"}},
		Points:   []model.Point{{IntValue: v}},
	}}}
}

func adjusted(b model.Batch) (int64, bool) {
	p := b.Series[0].Points[0]
	return p.IntValue, p.IsFloat
}

func TestResetNormalization(t *testing.T) {
	p := New()
	ctx := context.Background()

	steps := []struct {
		raw  int64
		want int64
	}{
		{100, 100}, // first: baseline
		{150, 150}, // climbs
		{20, 170},  // RESET: 20 + carried 150
		{30, 180},  // continues: 30 + 150
		{15, 195},  // RESET again: 15 + carried 180
	}
	for i, s := range steps {
		out, _ := p.Process(ctx, counter("c", s.raw))
		got, isFloat := adjusted(out)
		if isFloat {
			t.Errorf("step %d: int counter became float", i)
		}
		if got != s.want {
			t.Errorf("step %d: raw=%d adjusted=%d, want %d", i, s.raw, got, s.want)
		}
	}
}

func TestResetTrackerCap(t *testing.T) {
	p := New()
	p.maxSeries = 2 // tiny cap for the test
	ctx := context.Background()

	// Two distinct series fit and are tracked (reset-normalized).
	p.Process(ctx, counter("a", 100))
	p.Process(ctx, counter("b", 100))
	if len(p.state) != 2 {
		t.Fatalf("tracked %d series, want 2", len(p.state))
	}

	// A third new series exceeds the cap: passed through un-normalized, counted.
	before := selfobs.ResetUntracked.Get()
	out, _ := p.Process(ctx, counter("c", 42))
	if len(p.state) != 2 {
		t.Fatalf("state grew past cap to %d", len(p.state))
	}
	if got, _ := adjusted(out); got != 42 {
		t.Errorf("untracked series should pass through unchanged, got %d", got)
	}
	if selfobs.ResetUntracked.Get() == before {
		t.Error("ResetUntracked counter should have incremented")
	}

	// An already-tracked series still normalizes across a reset.
	p.Process(ctx, counter("a", 200)) // climbs
	out, _ = p.Process(ctx, counter("a", 5))
	if got, _ := adjusted(out); got != 205 { // 5 + carried 200
		t.Errorf("tracked series lost normalization after cap: got %d, want 205", got)
	}
}

func TestResetIgnoresOutOfOrderBatch(t *testing.T) {
	p := New()
	ctx := context.Background()
	tc := func(raw int64, ts uint64) model.Batch {
		return model.Batch{Series: []model.Series{{
			Name: "c", Type: model.MetricSum, Monotonic: true,
			Resource: model.Labels{{Name: "service.name", Value: "app"}},
			Points:   []model.Point{{IntValue: raw, TimeUnixNano: ts}},
		}}}
	}

	// The newer scrape (t=200, raw=1000) is processed before the older one
	// (t=100, raw=990) — the exact reordering a multi-worker pool allows.
	out, _ := p.Process(ctx, tc(1000, 200))
	if got, _ := adjusted(out); got != 1000 {
		t.Fatalf("baseline adjusted=%d, want 1000", got)
	}

	before := selfobs.ResetReordered.Get()
	out, _ = p.Process(ctx, tc(990, 100)) // stale: must NOT be read as a reset
	if out.Len() != 0 {
		t.Errorf("out-of-order point was emitted: %+v", out)
	}
	if selfobs.ResetReordered.Get() == before {
		t.Error("ResetReordered should have incremented for the out-of-order point")
	}

	// A later in-order point must be unaffected — no phantom offset carried.
	out, _ = p.Process(ctx, tc(1100, 300))
	if got, _ := adjusted(out); got != 1100 {
		t.Errorf("after out-of-order point adjusted=%d, want 1100", got)
	}

	// A genuine reset (newer time, lower raw) still normalizes.
	out, _ = p.Process(ctx, tc(5, 400))
	if got, _ := adjusted(out); got != 1105 { // 5 + carried 1100
		t.Errorf("genuine reset adjusted=%d, want 1105", got)
	}
}

func TestResetDropsOutOfOrderPointAcrossRealReset(t *testing.T) {
	p := New()
	ctx := context.Background()
	tc := func(raw int64, ts uint64) model.Batch {
		return model.Batch{Series: []model.Series{{
			Name: "c", Type: model.MetricSum, Monotonic: true,
			Resource: model.Labels{{Name: "service.name", Value: "app"}},
			Points:   []model.Point{{IntValue: raw, TimeUnixNano: ts}},
		}}}
	}

	_, _ = p.Process(ctx, tc(900, 100))
	newer, _ := p.Process(ctx, tc(10, 300)) // post-reset point wins the worker race
	if got, _ := adjusted(newer); got != 910 {
		t.Fatalf("post-reset adjusted=%d, want 910", got)
	}

	stale, _ := p.Process(ctx, tc(1000, 200)) // pre-reset point arrives too late
	if stale.Len() != 0 {
		t.Fatalf("stale pre-reset point was emitted: %+v", stale)
	}

	next, _ := p.Process(ctx, tc(20, 400))
	if got, _ := adjusted(next); got != 920 {
		t.Errorf("counter after stale point adjusted=%d, want 920", got)
	}
}

func TestGaugeUntouched(t *testing.T) {
	p := New()
	b := model.Batch{Series: []model.Series{{
		Name: "g", Type: model.MetricGauge,
		Points: []model.Point{{IntValue: 50}},
	}}}
	// A gauge that "drops" must not be rewritten.
	_, _ = p.Process(context.Background(), b)
	out, _ := p.Process(context.Background(), model.Batch{Series: []model.Series{{
		Name: "g", Type: model.MetricGauge,
		Points: []model.Point{{IntValue: 10}},
	}}})
	if out.Series[0].Points[0].IntValue != 10 {
		t.Errorf("gauge rewritten to %d, want 10", out.Series[0].Points[0].IntValue)
	}
}
