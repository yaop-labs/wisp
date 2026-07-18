package otlp

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/yaop-labs/reef/edge"
	"github.com/yaop-labs/reef/grpcreef"
	"github.com/yaop-labs/reef/reefclient"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"

	"github.com/yaop-labs/wisp/internal/httpx"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
	"github.com/yaop-labs/wisp/internal/signal"
)

type tracesTransport interface {
	sendTraces(context.Context, *coltracepb.ExportTraceServiceRequest, string) (*coltracepb.ExportTraceServiceResponse, error)
	close() error
}

// TracesExporter forwards opaque OTLP Traces envelopes without interpreting,
// sampling, or rewriting spans.
type TracesExporter struct {
	tr      tracesTransport
	timeout time.Duration
	logger  *slog.Logger
}

func NewTraces(cfg Config, logger *slog.Logger) (*TracesExporter, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("otlp traces exporter: endpoint required")
	}
	if hasHeader(cfg.Headers, "authorization") {
		return nil, fmt.Errorf("otlp traces exporter: configure bearer credentials via auth, not headers.authorization")
	}
	for _, reserved := range []string{"x-wisp-envelope-id", "x-wisp-signal-kind"} {
		if hasHeader(cfg.Headers, reserved) {
			return nil, fmt.Errorf("otlp traces exporter: header %q is reserved", reserved)
		}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var (
		tr       tracesTransport
		warnings []edge.Warning
		err      error
	)
	switch cfg.Protocol {
	case "", "grpc":
		var conn *grpcreef.Client
		conn, warnings, err = grpcreef.NewEdgeClient(edge.ClientConfig{
			Target:                         cfg.Endpoint,
			TLS:                            cfg.TLS,
			Auth:                           cfg.Auth,
			Insecure:                       cfg.Insecure,
			DangerAllowBearerOverPlaintext: cfg.DangerAllowBearerOverPlaintext,
		})
		if err == nil {
			tr = &grpcTracesTransport{
				conn: conn, client: coltracepb.NewTraceServiceClient(conn),
				md: metadataFrom(cfg.Headers),
			}
		}
	case "http":
		target := otlpHTTPURL(cfg.Endpoint, "/v1/traces", cfg.TLS != nil && cfg.TLS.Enabled)
		var edgeClient *reefclient.EdgeClient
		edgeClient, warnings, err = reefclient.NewEdgeTransport(edge.ClientConfig{
			Target:                         target,
			TLS:                            cfg.TLS,
			Auth:                           cfg.Auth,
			Insecure:                       cfg.Insecure,
			DangerAllowBearerOverPlaintext: cfg.DangerAllowBearerOverPlaintext,
		}, nil)
		if err == nil {
			tr = &httpTracesTransport{
				url: target, client: &http.Client{Transport: edgeClient},
				edge: edgeClient, headers: cfg.Headers,
			}
		}
	default:
		return nil, fmt.Errorf("otlp traces exporter: unknown protocol %q (use grpc or http)", cfg.Protocol)
	}
	if err != nil {
		return nil, fmt.Errorf("otlp traces exporter: %w", err)
	}
	for _, warning := range warnings {
		logger.Warn("reef configuration warning", "edge", "otlp-traces-exporter", "warning", warning)
	}
	return &TracesExporter{tr: tr, timeout: timeout, logger: logger}, nil
}

func (e *TracesExporter) Send(ctx context.Context, envelope signal.Envelope) error {
	if envelope.Kind != signal.Traces ||
		envelope.Schema != signal.OTLPTracesSchema ||
		envelope.Encoding != signal.OTLPProtobufEncoding {
		return fmt.Errorf("%w: otlp traces exporter: unsupported envelope kind=%q schema=%q encoding=%q",
			pipeline.ErrPermanent, envelope.Kind, envelope.Schema, envelope.Encoding)
	}
	var request coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(envelope.Payload, &request); err != nil {
		return fmt.Errorf("%w: otlp traces exporter: decode payload: %v", pipeline.ErrPermanent, err)
	}

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	response, err := e.tr.sendTraces(ctx, &request, envelope.ID)
	if err != nil {
		selfobs.ExportFailures.Inc()
		return fmt.Errorf("otlp traces export: %w", err)
	}
	if partial := response.GetPartialSuccess(); partial != nil && partial.RejectedSpans > 0 {
		selfobs.OTLPTraceSpansRejected.Add(uint64(partial.RejectedSpans))
		e.logger.Warn("otlp traces downstream partial success",
			"rejected_spans", partial.RejectedSpans,
			"message", boundedOTLPText(partial.ErrorMessage, 1024),
			"envelope_id", envelope.ID)
	}
	selfobs.OTLPTraceRequestsExported.Inc()
	selfobs.BatchesExported.Inc()
	return nil
}

func (e *TracesExporter) Close() error { return e.tr.close() }

type grpcTracesTransport struct {
	conn   *grpcreef.Client
	client coltracepb.TraceServiceClient
	md     metadata.MD
}

func (t *grpcTracesTransport) sendTraces(ctx context.Context, request *coltracepb.ExportTraceServiceRequest, envelopeID string) (*coltracepb.ExportTraceServiceResponse, error) {
	md := t.md.Copy()
	if md == nil {
		md = metadata.MD{}
	}
	md.Set("x-wisp-envelope-id", envelopeID)
	md.Set("x-wisp-signal-kind", string(signal.Traces))
	ctx = metadata.NewOutgoingContext(ctx, md)
	response, err := t.client.Export(ctx, request)
	if err != nil && permanentGRPC(status.Code(err)) {
		return nil, fmt.Errorf("%w: %w", pipeline.ErrPermanent, err)
	}
	return response, err
}

func (t *grpcTracesTransport) close() error { return t.conn.Close() }

type httpTracesTransport struct {
	url     string
	client  *http.Client
	edge    *reefclient.EdgeClient
	headers map[string]string
}

func (t *httpTracesTransport) sendTraces(ctx context.Context, request *coltracepb.ExportTraceServiceRequest, envelopeID string) (*coltracepb.ExportTraceServiceResponse, error) {
	body, err := proto.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal traces: %v", pipeline.ErrPermanent, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	httpReq.Header.Set("Content-Type", signal.OTLPProtobufEncoding)
	for _, key := range sortedKeys(t.headers) {
		httpReq.Header.Set(key, t.headers[key])
	}
	httpReq.Header.Set("X-Wisp-Envelope-Id", envelopeID)
	httpReq.Header.Set("X-Wisp-Signal-Kind", string(signal.Traces))
	response, err := t.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("post: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		err := httpx.ErrorFromResponse(response)
		if permanentHTTP(response.StatusCode) {
			return nil, fmt.Errorf("%w: %w", pipeline.ErrPermanent, err)
		}
		return nil, err
	}
	data, err := readBoundedOTLPResponse(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	var out coltracepb.ExportTraceServiceResponse
	if len(data) > 0 {
		if err := proto.Unmarshal(data, &out); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
	}
	return &out, nil
}

func (t *httpTracesTransport) close() error { return t.edge.Close() }
