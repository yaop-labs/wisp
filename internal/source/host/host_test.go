package host

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
)

func collectOnce(t *testing.T) model.Batch {
	t.Helper()
	s := New(time.Hour, nil, model.Labels{{Name: "service.name", Value: "wisp"}}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan model.Batch, 1)
	emit := func(_ context.Context, b model.Batch) error {
		select {
		case got <- b:
		default:
		}
		cancel() // stop after the immediate first collection
		return nil
	}
	_ = s.Start(ctx, emit)

	select {
	case b := <-got:
		return b
	default:
		t.Fatal("no batch emitted")
		return model.Batch{}
	}
}

func TestHostCollectEmitsSeries(t *testing.T) {
	b := collectOnce(t)
	if b.Len() == 0 {
		t.Fatal("expected at least one data point from host collectors")
	}

	byName := map[string]model.Series{}
	for _, s := range b.Series {
		byName[s.Name] = s
		if len(s.Resource) == 0 || s.Resource[0].Name != "service.name" {
			t.Errorf("series %q missing stamped resource", s.Name)
		}
	}

	// /proc/loadavg exists on any Linux test host.
	load, ok := byName["node_load1"]
	if !ok {
		t.Fatal("expected node_load1 series")
	}
	if load.Type != model.MetricGauge {
		t.Errorf("node_load1 type = %v, want gauge", load.Type)
	}

	// cpu is a monotonic integer counter (ms) with cpu/mode attributes.
	if cpu, ok := byName["node_cpu_milliseconds_total"]; ok {
		if cpu.Type != model.MetricSum || !cpu.Monotonic {
			t.Errorf("node_cpu_milliseconds_total should be a monotonic sum")
		}
		if len(cpu.Points) > 0 && cpu.Points[0].IsFloat {
			t.Errorf("node_cpu_milliseconds_total should be an integer counter, not float")
		}
		if len(cpu.Attrs) != 2 {
			t.Errorf("node_cpu_milliseconds_total should carry cpu+mode attrs, got %d", len(cpu.Attrs))
		}
	}
}
