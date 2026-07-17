package spool

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/signal"
)

const (
	metricSchema   = "wisp.metric-batch.gob/v1"
	metricEncoding = "application/x-gob"
)

var envelopeIdentityKeys = map[string]struct{}{
	"service.name": {}, "service.namespace": {}, "service.instance.id": {},
	"service.version": {}, "host.id": {}, "host.name": {}, "process.pid": {},
	"process.executable.name": {}, "process.executable.path": {},
	"process.executable.build_id.gnu": {}, "process.executable.build_id.go": {},
	"process.runtime.name": {}, "process.runtime.version": {},
	"container.id": {}, "container.name": {}, "k8s.cluster.name": {},
	"k8s.namespace.name": {}, "k8s.node.name": {}, "k8s.pod.name": {},
	"k8s.pod.uid": {}, "k8s.container.name": {}, "k8s.deployment.name": {},
	"k8s.statefulset.name": {}, "k8s.daemonset.name": {}, "k8s.job.name": {},
	"wisp.profile.executable.build_id": {}, "wisp.profile.executable.debug_name": {},
}

// Exporter preserves the existing metric pipeline API while delegating all
// durability mechanics to the signal-neutral Queue.
type Exporter struct {
	*Queue
}

type metricSender struct {
	inner pipeline.Exporter
}

func (s *metricSender) Send(ctx context.Context, envelope signal.Envelope) error {
	batch, err := decodeMetricEnvelope(envelope)
	if err != nil {
		return fmt.Errorf("%w: %v", pipeline.ErrPermanent, err)
	}
	return s.inner.Export(ctx, batch)
}

func (s *metricSender) Close() error { return s.inner.Close() }

func New(inner pipeline.Exporter, cfg Config, logger *slog.Logger) (*Exporter, error) {
	queue, err := NewQueue(&metricSender{inner: inner}, cfg, logger)
	if err != nil {
		return nil, err
	}
	queue.depth(signal.Metrics)
	return &Exporter{Queue: queue}, nil
}

func (e *Exporter) Export(ctx context.Context, batch model.Batch) error {
	envelope, err := metricEnvelope(batch)
	if err != nil {
		return err
	}
	return e.Accept(ctx, envelope)
}

func encode(batch model.Batch) ([]byte, error) {
	envelope, err := metricEnvelope(batch)
	if err != nil {
		return nil, err
	}
	return envelope.MarshalBinary()
}

func metricEnvelope(batch model.Batch) (signal.Envelope, error) {
	payload, err := encodeLegacy(batch)
	if err != nil {
		return signal.Envelope{}, err
	}
	return signal.New(signal.Metrics, metricSchema, metricEncoding, payload, commonResource(batch))
}

func encodeLegacy(batch model.Batch) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(batch); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decode(data []byte) (model.Batch, error) {
	envelope, err := decodeEnvelope(data)
	if err != nil {
		return model.Batch{}, err
	}
	return decodeMetricEnvelope(envelope)
}

func decodeMetricEnvelope(envelope signal.Envelope) (model.Batch, error) {
	if envelope.Kind != signal.Metrics {
		return model.Batch{}, fmt.Errorf("spool: unsupported signal kind %q", envelope.Kind)
	}
	if envelope.Schema != metricSchema || envelope.Encoding != metricEncoding {
		return model.Batch{}, fmt.Errorf(
			"spool: unsupported metrics payload schema=%q encoding=%q",
			envelope.Schema, envelope.Encoding,
		)
	}
	return decodeLegacy(envelope.Payload)
}

func decodeLegacy(data []byte) (model.Batch, error) {
	var batch model.Batch
	err := gob.NewDecoder(bytes.NewReader(data)).Decode(&batch)
	return batch, err
}

func commonResource(batch model.Batch) map[string]string {
	if len(batch.Series) == 0 {
		return nil
	}
	first, ok := identityFromLabels(batch.Series[0].Resource)
	if !ok {
		return nil
	}
	for i := 1; i < len(batch.Series); i++ {
		resource, valid := identityFromLabels(batch.Series[i].Resource)
		if !valid || !maps.Equal(first, resource) {
			return nil
		}
	}
	return first
}

func identityFromLabels(labels model.Labels) (map[string]string, bool) {
	if len(labels) == 0 {
		return nil, true
	}
	out := make(map[string]string, len(labels))
	for _, label := range labels {
		if _, keep := envelopeIdentityKeys[label.Name]; !keep {
			continue
		}
		if _, duplicate := out[label.Name]; duplicate {
			return nil, false
		}
		if len(label.Value) > 4096 || !utf8.ValidString(label.Value) ||
			strings.IndexFunc(label.Value, unicode.IsControl) >= 0 {
			return nil, false
		}
		out[label.Name] = label.Value
	}
	return out, true
}
