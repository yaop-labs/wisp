package otlp

import (
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"

	"github.com/yaop-labs/wisp/internal/model"
)

const scopeName = "wisp"

// toRequest converts an internal batch into an OTLP ExportMetricsServiceRequest,
// grouping series that share a resource into one ResourceMetrics so amber sees
// a single resource block per host/target.
func toRequest(b model.Batch) *colmetricspb.ExportMetricsServiceRequest {
	groups := make(map[string]*metricspb.ResourceMetrics)
	var order []string

	for i := range b.Series {
		s := &b.Series[i]
		key := model.CanonicalKey(s.Resource)
		rm := groups[key]
		if rm == nil {
			rm = &metricspb.ResourceMetrics{
				Resource:     &resourcepb.Resource{Attributes: keyValues(s.Resource)},
				ScopeMetrics: []*metricspb.ScopeMetrics{{Scope: &commonpb.InstrumentationScope{Name: scopeName}}},
			}
			groups[key] = rm
			order = append(order, key)
		}
		rm.ScopeMetrics[0].Metrics = append(rm.ScopeMetrics[0].Metrics, metricFromSeries(s))
	}

	req := &colmetricspb.ExportMetricsServiceRequest{}
	for _, k := range order {
		req.ResourceMetrics = append(req.ResourceMetrics, groups[k])
	}
	return req
}

func metricFromSeries(s *model.Series) *metricspb.Metric {
	attrs := keyValues(s.Attrs)
	m := &metricspb.Metric{Name: s.Name, Unit: s.Unit}

	if s.Type == model.MetricExponentialHistogram {
		m.Data = &metricspb.Metric_ExponentialHistogram{ExponentialHistogram: &metricspb.ExponentialHistogram{
			AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
			DataPoints:             expHistPoints(s.Points, attrs),
		}}
		return m
	}

	dps := scalarPoints(s.Points, attrs)
	switch s.Type {
	case model.MetricSum:
		m.Data = &metricspb.Metric_Sum{Sum: &metricspb.Sum{
			DataPoints:             dps,
			AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
			IsMonotonic:            s.Monotonic,
		}}
	default: // gauge
		m.Data = &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: dps}}
	}
	return m
}

func scalarPoints(points []model.Point, attrs []*commonpb.KeyValue) []*metricspb.NumberDataPoint {
	dps := make([]*metricspb.NumberDataPoint, len(points))
	for i, p := range points {
		dp := &metricspb.NumberDataPoint{Attributes: attrs, TimeUnixNano: p.TimeUnixNano}
		if p.IsFloat {
			dp.Value = &metricspb.NumberDataPoint_AsDouble{AsDouble: p.FloatValue}
		} else {
			dp.Value = &metricspb.NumberDataPoint_AsInt{AsInt: p.IntValue}
		}
		dps[i] = dp
	}
	return dps
}

func expHistPoints(points []model.Point, attrs []*commonpb.KeyValue) []*metricspb.ExponentialHistogramDataPoint {
	out := make([]*metricspb.ExponentialHistogramDataPoint, 0, len(points))
	for _, p := range points {
		if p.Hist == nil {
			continue
		}
		sum := p.Hist.Sum
		out = append(out, &metricspb.ExponentialHistogramDataPoint{
			Attributes:   attrs,
			TimeUnixNano: p.TimeUnixNano,
			Count:        p.Hist.Count,
			Sum:          &sum,
			Scale:        p.Hist.Scale,
			ZeroCount:    p.Hist.ZeroCount,
			Positive: &metricspb.ExponentialHistogramDataPoint_Buckets{
				Offset:       p.Hist.PositiveOffset,
				BucketCounts: p.Hist.PositiveCounts,
			},
		})
	}
	return out
}

func keyValues(labels model.Labels) []*commonpb.KeyValue {
	if len(labels) == 0 {
		return nil
	}
	out := make([]*commonpb.KeyValue, len(labels))
	for i, l := range labels {
		out[i] = &commonpb.KeyValue{
			Key:   l.Name,
			Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: l.Value}},
		}
	}
	return out
}
