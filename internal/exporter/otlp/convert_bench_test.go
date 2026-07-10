package otlp

import (
	"fmt"
	"testing"

	"github.com/yaop-labs/wisp/internal/model"
)

// benchBatch builds a batch of n counter series (the export conversion hot path).
func benchBatch(n int) model.Batch {
	resource := model.Labels{{Name: "service.name", Value: "app"}, {Name: "host.name", Value: "node-1"}}
	series := make([]model.Series, n)
	for i := range n {
		series[i] = model.Series{
			Name:      "http_requests_total",
			Type:      model.MetricSum,
			Monotonic: true,
			Resource:  resource,
			Attrs:     model.Labels{{Name: "method", Value: "get"}, {Name: "code", Value: fmt.Sprintf("%d", 200+i%5)}},
			Points:    []model.Point{{TimeUnixNano: uint64(i + 1), IntValue: int64(i * 7)}},
		}
	}
	return model.Batch{Series: series}
}

func BenchmarkToRequest(b *testing.B) {
	batch := benchBatch(200)
	b.ReportAllocs()

	for b.Loop() {
		_ = toRequest(batch)
	}
}
