package relabel

import (
	"context"
	"testing"

	"github.com/yaop-labs/wisp/internal/model"
)

func oneSeries(name string, attrs ...model.Label) model.Batch {
	return model.Batch{Series: []model.Series{{
		Name: name, Type: model.MetricGauge, Attrs: attrs,
		Points: []model.Point{{IntValue: 1}},
	}}}
}

func attr(s *model.Series, name string) (string, bool) {
	for _, l := range s.Attrs {
		if l.Name == name {
			return l.Value, true
		}
	}
	return "", false
}

func TestLabelKeep(t *testing.T) {
	p, err := New([]Rule{{Regex: "keep_.*", Action: "labelkeep"}})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := p.Process(context.Background(), oneSeries("m",
		model.Label{Name: "keep_a", Value: "1"},
		model.Label{Name: "drop_b", Value: "2"},
		model.Label{Name: "keep_c", Value: "3"},
	))
	s := &out.Series[0]
	if _, ok := attr(s, "drop_b"); ok {
		t.Error("labelkeep should have removed drop_b")
	}
	if _, ok := attr(s, "keep_a"); !ok {
		t.Error("labelkeep should have kept keep_a")
	}
	if len(s.Attrs) != 2 {
		t.Errorf("kept %d labels, want 2", len(s.Attrs))
	}
}

func TestReplaceEmptyReplacementRemovesLabel(t *testing.T) {
	// Matching with a replacement that expands to empty removes the target label.
	p, err := New([]Rule{{SourceLabels: []string{"drop_me"}, Regex: "(.*)", TargetLabel: "drop_me", Replacement: "$2", Action: "replace"}})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := p.Process(context.Background(), oneSeries("m", model.Label{Name: "drop_me", Value: "x"}))
	if _, ok := attr(&out.Series[0], "drop_me"); ok {
		t.Error("replace with empty result should remove the label")
	}
}

func TestReplaceDoesNotCorruptSharedBackingArray(t *testing.T) {
	// host.go emits sibling series (receive+transmit) that share one Attrs
	// backing array. Process shallow-copies each Series, so a replace rule
	// matching only the receive series must not rewrite the transmit series'
	// label through the shared array.
	shared := model.Labels{{Name: "device", Value: "eth0"}}
	in := []model.Series{
		{Name: "node_network_receive_bytes_total", Attrs: shared, Points: []model.Point{{IntValue: 1}}},
		{Name: "node_network_transmit_bytes_total", Attrs: shared, Points: []model.Point{{IntValue: 2}}},
	}
	out := run(t, []Rule{{
		SourceLabels: []string{"__name__"},
		Regex:        "node_network_receive_bytes_total",
		TargetLabel:  "device",
		Replacement:  "renamed",
		Action:       "replace",
	}}, in)

	if got, _ := attr(&out[0], "device"); got != "renamed" {
		t.Errorf("receive series device = %q, want renamed", got)
	}
	if got, _ := attr(&out[1], "device"); got != "eth0" {
		t.Errorf("transmit series device corrupted through shared array: = %q, want eth0", got)
	}
}

func TestNewErrors(t *testing.T) {
	if _, err := New([]Rule{{Regex: "(", Action: "keep"}}); err == nil {
		t.Error("bad regex should error")
	}
	if _, err := New([]Rule{{Action: "frobnicate"}}); err == nil {
		t.Error("unsupported action should error")
	}
}

func TestKeepDropsNonMatching(t *testing.T) {
	p, _ := New([]Rule{{SourceLabels: []string{"__name__"}, Regex: "keepme", Action: "keep"}})
	out, _ := p.Process(context.Background(), model.Batch{Series: []model.Series{
		{Name: "keepme", Points: []model.Point{{IntValue: 1}}},
		{Name: "dropme", Points: []model.Point{{IntValue: 1}}},
	}})
	if out.Len() != 1 || out.Series[0].Name != "keepme" {
		t.Fatalf("keep kept %d series, want only keepme", out.Len())
	}
}
