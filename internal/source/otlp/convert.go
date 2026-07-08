package otlp

import (
	"strconv"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"

	"github.com/yaop-labs/wisp/internal/model"
)

// seriesFromRequest converts a received OTLP request into internal series (the
// inverse of the exporter's conversion). Gauge, Sum, and ExponentialHistogram
// points map directly; explicit Histogram and Summary points are not modeled and
// are reported via the unsupported count (senders should emit exponential
// histograms, which amber's engine is built around).
func seriesFromRequest(req *colmetricspb.ExportMetricsServiceRequest) (series []model.Series, unsupported int) {
	for _, rm := range req.GetResourceMetrics() {
		resource := labelsFromKV(rm.GetResource().GetAttributes())
		for _, sm := range rm.GetScopeMetrics() {
			for _, m := range sm.GetMetrics() {
				switch d := m.GetData().(type) {
				case *metricspb.Metric_Gauge:
					series = append(series, scalarSeries(m, model.MetricGauge, false, resource, d.Gauge.GetDataPoints())...)
				case *metricspb.Metric_Sum:
					series = append(series, scalarSeries(m, model.MetricSum, d.Sum.GetIsMonotonic(), resource, d.Sum.GetDataPoints())...)
				case *metricspb.Metric_ExponentialHistogram:
					series = append(series, expHistSeries(m, resource, d.ExponentialHistogram.GetDataPoints())...)
				case *metricspb.Metric_Histogram:
					unsupported += len(d.Histogram.GetDataPoints())
				case *metricspb.Metric_Summary:
					unsupported += len(d.Summary.GetDataPoints())
				}
			}
		}
	}
	return series, unsupported
}

func scalarSeries(m *metricspb.Metric, typ model.MetricType, monotonic bool, resource model.Labels, dps []*metricspb.NumberDataPoint) []model.Series {
	out := make([]model.Series, 0, len(dps))
	for _, dp := range dps {
		p := model.Point{TimeUnixNano: dp.GetTimeUnixNano()}
		switch v := dp.GetValue().(type) {
		case *metricspb.NumberDataPoint_AsInt:
			p.IntValue = v.AsInt
		case *metricspb.NumberDataPoint_AsDouble:
			p.FloatValue = v.AsDouble
			p.IsFloat = true
		default:
			continue
		}
		out = append(out, model.Series{
			Name:      m.GetName(),
			Unit:      m.GetUnit(),
			Type:      typ,
			Monotonic: monotonic,
			Resource:  resource,
			Attrs:     labelsFromKV(dp.GetAttributes()),
			Points:    []model.Point{p},
		})
	}
	return out
}

func expHistSeries(m *metricspb.Metric, resource model.Labels, dps []*metricspb.ExponentialHistogramDataPoint) []model.Series {
	out := make([]model.Series, 0, len(dps))
	for _, dp := range dps {
		pos := dp.GetPositive()
		eh := &model.ExpHistogram{
			Scale:          dp.GetScale(),
			ZeroCount:      dp.GetZeroCount(),
			PositiveOffset: pos.GetOffset(),
			PositiveCounts: pos.GetBucketCounts(),
			Sum:            dp.GetSum(),
			Count:          dp.GetCount(),
		}
		out = append(out, model.Series{
			Name:     m.GetName(),
			Unit:     m.GetUnit(),
			Type:     model.MetricExponentialHistogram,
			Resource: resource,
			Attrs:    labelsFromKV(dp.GetAttributes()),
			Points:   []model.Point{{TimeUnixNano: dp.GetTimeUnixNano(), Hist: eh}},
		})
	}
	return out
}

func labelsFromKV(kvs []*commonpb.KeyValue) model.Labels {
	if len(kvs) == 0 {
		return nil
	}
	out := make(model.Labels, 0, len(kvs))
	for _, kv := range kvs {
		out = append(out, model.Label{Name: kv.GetKey(), Value: anyValueString(kv.GetValue())})
	}
	return out
}

func anyValueString(v *commonpb.AnyValue) string {
	switch val := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return val.StringValue
	case *commonpb.AnyValue_BoolValue:
		return strconv.FormatBool(val.BoolValue)
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(val.IntValue, 10)
	case *commonpb.AnyValue_DoubleValue:
		return strconv.FormatFloat(val.DoubleValue, 'f', -1, 64)
	default:
		return ""
	}
}
