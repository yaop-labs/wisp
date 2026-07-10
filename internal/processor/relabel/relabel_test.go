package relabel

import (
	"context"
	"testing"

	"github.com/yaop-labs/wisp/internal/model"
)

func mk(name string, attrs ...string) model.Series {
	s := model.Series{Name: name, Resource: model.Labels{{Name: "service.name", Value: "app"}}}
	for i := 0; i+1 < len(attrs); i += 2 {
		s.Attrs = append(s.Attrs, model.Label{Name: attrs[i], Value: attrs[i+1]})
	}
	return s
}

func run(t *testing.T, rules []Rule, in []model.Series) []model.Series {
	t.Helper()
	p, err := New(rules)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := p.Process(context.Background(), model.Batch{Series: in})
	return out.Series
}

func TestDropByName(t *testing.T) {
	out := run(t, []Rule{{
		SourceLabels: []string{"__name__"},
		Regex:        "go_.*",
		Action:       "drop",
	}}, []model.Series{mk("go_gc_duration"), mk("http_requests_total")})

	if len(out) != 1 || out[0].Name != "http_requests_total" {
		t.Fatalf("expected only http_requests_total to survive, got %d series", len(out))
	}
}

func TestKeepByLabel(t *testing.T) {
	out := run(t, []Rule{{
		SourceLabels: []string{"env"},
		Regex:        "prod",
		Action:       "keep",
	}}, []model.Series{
		mk("m", "env", "prod"),
		mk("m", "env", "dev"),
		mk("m"),
	})
	if len(out) != 1 || out[0].Attrs[0].Value != "prod" {
		t.Fatalf("keep should retain only env=prod, got %d", len(out))
	}
}

func TestReplaceAndRename(t *testing.T) {
	out := run(t, []Rule{
		{ // copy code -> status
			SourceLabels: []string{"code"},
			Regex:        "(.*)",
			TargetLabel:  "status",
			Replacement:  "$1",
		},
		{ // rename the metric via __name__
			SourceLabels: []string{"__name__"},
			Regex:        "http_(.*)",
			TargetLabel:  "__name__",
			Replacement:  "wisp_$1",
		},
	}, []model.Series{mk("http_requests_total", "code", "200")})

	s := out[0]
	if s.Name != "wisp_requests_total" {
		t.Errorf("metric not renamed: %s", s.Name)
	}
	var status string
	for _, l := range s.Attrs {
		if l.Name == "status" {
			status = l.Value
		}
	}
	if status != "200" {
		t.Errorf("status label = %q, want 200", status)
	}
}

func TestLabelDrop(t *testing.T) {
	out := run(t, []Rule{{Regex: "tmp_.*", Action: "labeldrop"}},
		[]model.Series{mk("m", "tmp_internal", "x", "keep_me", "y")})
	for _, l := range out[0].Attrs {
		if l.Name == "tmp_internal" {
			t.Error("tmp_internal should have been dropped")
		}
	}
	if len(out[0].Attrs) != 1 || out[0].Attrs[0].Name != "keep_me" {
		t.Errorf("labeldrop removed wrong labels: %+v", out[0].Attrs)
	}
}
