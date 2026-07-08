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
