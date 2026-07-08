package relabel

import (
	"context"
	"fmt"
	"testing"

	"github.com/yaop-labs/wisp/internal/model"
)

func benchProcessor(b *testing.B) *Processor {
	p, err := New([]Rule{
		{SourceLabels: []string{"__name__"}, Regex: "go_gc_.*", Action: "drop"},
		{SourceLabels: []string{"method"}, Regex: "(.*)", TargetLabel: "http_method", Replacement: "$1", Action: "replace"},
		{Regex: "code", Action: "labelkeep"},
	})
	if err != nil {
		b.Fatal(err)
	}
	return p
}

func benchBatch(n int) model.Batch {
	series := make([]model.Series, n)
	for i := 0; i < n; i++ {
		series[i] = model.Series{
			Name:     "http_requests_total",
			Type:     model.MetricSum,
			Resource: model.Labels{{Name: "service.name", Value: "app"}},
			Attrs:    model.Labels{{Name: "method", Value: "get"}, {Name: "code", Value: fmt.Sprintf("%d", 200+i%5)}},
			Points:   []model.Point{{TimeUnixNano: uint64(i + 1), IntValue: int64(i)}},
		}
	}
	return model.Batch{Series: series}
}

func BenchmarkRelabel(b *testing.B) {
	p := benchProcessor(b)
	batch := benchBatch(200)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.Process(ctx, batch); err != nil {
			b.Fatal(err)
		}
	}
}
