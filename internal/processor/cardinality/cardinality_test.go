package cardinality

import (
	"context"
	"testing"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/selfobs"
)

func series(name, target string, attr string) model.Series {
	s := model.Series{
		Name:     name,
		Resource: model.Labels{{Name: "service.name", Value: target}},
		Points:   []model.Point{{IntValue: 1}},
	}
	if attr != "" {
		s.Attrs = model.Labels{{Name: "id", Value: attr}}
	}
	return s
}

func TestPerTargetBudget(t *testing.T) {
	p := New(2, 0)
	ctx := context.Background()

	// Target "a": 3 distinct series, budget 2 -> one dropped.
	b, _ := p.Process(ctx, model.Batch{Series: []model.Series{
		series("m", "a", "1"),
		series("m", "a", "2"),
		series("m", "a", "3"),
	}})
	if b.Len() != 2 {
		t.Fatalf("target a: kept %d, want 2", b.Len())
	}

	// Target "b" has its own budget - not affected by a.
	b, _ = p.Process(ctx, model.Batch{Series: []model.Series{series("m", "b", "1"), series("m", "b", "2")}})
	if b.Len() != 2 {
		t.Fatalf("target b: kept %d, want 2", b.Len())
	}

	// Re-sending an already-admitted series for a is allowed (not new).
	b, _ = p.Process(ctx, model.Batch{Series: []model.Series{series("m", "a", "1")}})
	if b.Len() != 1 {
		t.Fatalf("re-admit: kept %d, want 1", b.Len())
	}
}

func TestDisabled(t *testing.T) {
	p := New(0, 0)
	in := model.Batch{Series: []model.Series{series("m", "a", "1"), series("m", "a", "2"), series("m", "a", "3")}}
	out, _ := p.Process(context.Background(), in)
	if out.Len() != 3 {
		t.Fatalf("disabled guard should pass all, got %d", out.Len())
	}
}

func TestTrackerCapAdmitsUntracked(t *testing.T) {
	p := New(100, 0) // generous per-target budget
	p.maxSeries = 2  // but only 2 identities tracked globally
	ctx := context.Background()

	// Two new identities fill the tracker.
	b, _ := p.Process(ctx, model.Batch{Series: []model.Series{series("m", "a", "1"), series("m", "a", "2")}})
	if b.Len() != 2 {
		t.Fatalf("kept %d, want 2", b.Len())
	}

	// A third new identity: tracker full -> admitted un-budgeted and counted,
	// not dropped and not leaked into state.
	before := selfobs.CardinalityUntracked.Get()
	b, _ = p.Process(ctx, model.Batch{Series: []model.Series{series("m", "a", "3")}})
	if b.Len() != 1 {
		t.Fatalf("kept %d, want 1 (untracked passthrough)", b.Len())
	}
	if got := selfobs.CardinalityUntracked.Get() - before; got != 1 {
		t.Fatalf("untracked counter delta = %d, want 1", got)
	}

	// An already-tracked identity keeps flowing without consuming budget.
	b, _ = p.Process(ctx, model.Batch{Series: []model.Series{series("m", "a", "1")}})
	if b.Len() != 1 {
		t.Fatalf("re-admit kept %d, want 1", b.Len())
	}
}

func TestMaxLabelsPerSeries(t *testing.T) {
	// Limit = 2 total labels (resource + attrs). series() has 1 resource label
	// (service.name) + 1 attr (id) = 2 -> kept; a 3rd label -> dropped.
	p := New(0, 2)
	wide := series("m", "a", "1")
	wide.Attrs = append(wide.Attrs, model.Label{Name: "extra", Value: "x"}) // now 3 labels

	out, _ := p.Process(context.Background(), model.Batch{Series: []model.Series{
		series("m", "a", "1"), // 2 labels -> keep
		wide,                  // 3 labels -> drop
	}})
	if out.Len() != 1 {
		t.Fatalf("kept %d, want 1 (wide series dropped)", out.Len())
	}
	if out.Series[0].Name != "m" || len(out.Series[0].Attrs) != 1 {
		t.Fatalf("wrong series kept: %+v", out.Series[0])
	}
}
