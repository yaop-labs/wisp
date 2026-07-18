package otlp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yaop-labs/reef/edge"
	"github.com/yaop-labs/reef/grpcreef"
	"github.com/yaop-labs/reef/reefclient"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"

	"github.com/yaop-labs/wisp/internal/httpx"
	"github.com/yaop-labs/wisp/internal/otlpwire"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
	"github.com/yaop-labs/wisp/internal/signal"
)

type logsTransport interface {
	sendLogs(context.Context, *collogspb.ExportLogsServiceRequest, string) (*collogspb.ExportLogsServiceResponse, error)
	close() error
}

// LogsExporter forwards opaque OTLP Logs envelopes without converting log
// records into Wisp's metric model.
type LogsExporter struct {
	tr              logsTransport
	timeout         time.Duration
	logger          *slog.Logger
	maxRequestBytes int
}

func NewLogs(cfg Config, logger *slog.Logger) (*LogsExporter, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("otlp logs exporter: endpoint required")
	}
	if hasHeader(cfg.Headers, "authorization") {
		return nil, fmt.Errorf("otlp logs exporter: configure bearer credentials via auth, not headers.authorization")
	}
	for _, reserved := range []string{"x-wisp-envelope-id", "x-wisp-signal-kind"} {
		if hasHeader(cfg.Headers, reserved) {
			return nil, fmt.Errorf("otlp logs exporter: header %q is reserved", reserved)
		}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var (
		tr       logsTransport
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
			tr = &grpcLogsTransport{
				conn: conn, client: collogspb.NewLogsServiceClient(conn),
				md: metadataFrom(cfg.Headers),
			}
		}
	case "http":
		target := otlpHTTPURL(cfg.Endpoint, "/v1/logs", cfg.TLS != nil && cfg.TLS.Enabled)
		var edgeClient *reefclient.EdgeClient
		edgeClient, warnings, err = reefclient.NewEdgeTransport(edge.ClientConfig{
			Target:                         target,
			TLS:                            cfg.TLS,
			Auth:                           cfg.Auth,
			Insecure:                       cfg.Insecure,
			DangerAllowBearerOverPlaintext: cfg.DangerAllowBearerOverPlaintext,
		}, nil)
		if err == nil {
			tr = &httpLogsTransport{
				url: target, client: &http.Client{Transport: edgeClient},
				edge: edgeClient, headers: cfg.Headers,
			}
		}
	default:
		return nil, fmt.Errorf("otlp logs exporter: unknown protocol %q (use grpc or http)", cfg.Protocol)
	}
	if err != nil {
		return nil, fmt.Errorf("otlp logs exporter: %w", err)
	}
	for _, warning := range warnings {
		logger.Warn("reef configuration warning", "edge", "otlp-logs-exporter", "warning", warning)
	}
	return &LogsExporter{
		tr: tr, timeout: timeout, logger: logger,
		maxRequestBytes: normalizedMaxLogRequestBytes(cfg.MaxLogRequestBytes),
	}, nil
}

func (e *LogsExporter) Send(ctx context.Context, envelope signal.Envelope) error {
	if envelope.Kind != signal.Logs ||
		envelope.Schema != signal.OTLPLogsSchema ||
		envelope.Encoding != signal.OTLPProtobufEncoding {
		return fmt.Errorf("%w: otlp logs exporter: unsupported envelope kind=%q schema=%q encoding=%q",
			pipeline.ErrPermanent, envelope.Kind, envelope.Schema, envelope.Encoding)
	}
	var request collogspb.ExportLogsServiceRequest
	if err := proto.Unmarshal(envelope.Payload, &request); err != nil {
		return fmt.Errorf("%w: otlp logs exporter: decode payload: %v", pipeline.ErrPermanent, err)
	}

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	maxRequestBytes := normalizedMaxLogRequestBytes(e.maxRequestBytes)
	split := proto.Size(&request) > maxRequestBytes
	if split {
		selfobs.OTLPLogsCompatSplits.Inc()
	}
	err := otlpwire.ForEachLogsChunk(&request, maxRequestBytes, func(chunk otlpwire.LogsChunk) error {
		deliveryID := envelope.ID
		if split {
			deliveryID = derivedChunkID(envelope.ID, chunk.Index)
		}
		response, err := e.tr.sendLogs(ctx, chunk.Request, deliveryID)
		if err != nil {
			return err
		}
		if partial := response.GetPartialSuccess(); partial != nil && partial.RejectedLogRecords > 0 {
			selfobs.OTLPLogsRejected.Add(uint64(partial.RejectedLogRecords))
			e.logger.Warn("otlp logs downstream partial success",
				"rejected_log_records", partial.RejectedLogRecords,
				"message", boundedLogText(partial.ErrorMessage, 1024),
				"envelope_id", deliveryID)
		}
		selfobs.OTLPLogsChunksExported.Inc()
		return nil
	})
	if err != nil {
		selfobs.ExportFailures.Inc()
		if errors.Is(err, otlpwire.ErrLogRecordTooLarge) {
			return fmt.Errorf("otlp logs export: %w: %w", pipeline.ErrPermanent, err)
		}
		return fmt.Errorf("otlp logs export: %w", err)
	}
	selfobs.BatchesExported.Inc()
	return nil
}

func (e *LogsExporter) Close() error { return e.tr.close() }

type grpcLogsTransport struct {
	conn   *grpcreef.Client
	client collogspb.LogsServiceClient
	md     metadata.MD
}

func (t *grpcLogsTransport) sendLogs(ctx context.Context, request *collogspb.ExportLogsServiceRequest, envelopeID string) (*collogspb.ExportLogsServiceResponse, error) {
	md := t.md.Copy()
	if md == nil {
		md = metadata.MD{}
	}
	md.Set("x-wisp-envelope-id", envelopeID)
	md.Set("x-wisp-signal-kind", string(signal.Logs))
	ctx = metadata.NewOutgoingContext(ctx, md)
	response, err := t.client.Export(ctx, request)
	if err != nil && permanentGRPC(status.Code(err)) {
		return nil, fmt.Errorf("%w: %w", pipeline.ErrPermanent, err)
	}
	return response, err
}

func (t *grpcLogsTransport) close() error { return t.conn.Close() }

type httpLogsTransport struct {
	url     string
	client  *http.Client
	edge    *reefclient.EdgeClient
	headers map[string]string
}

func (t *httpLogsTransport) sendLogs(ctx context.Context, request *collogspb.ExportLogsServiceRequest, envelopeID string) (*collogspb.ExportLogsServiceResponse, error) {
	body, err := proto.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal logs: %v", pipeline.ErrPermanent, err)
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
	httpReq.Header.Set("X-Wisp-Signal-Kind", string(signal.Logs))
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
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	var out collogspb.ExportLogsServiceResponse
	if len(data) > 0 {
		if err := proto.Unmarshal(data, &out); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
	}
	return &out, nil
}

func (t *httpLogsTransport) close() error { return t.edge.Close() }

func otlpHTTPURL(endpoint, path string, tlsEnabled bool) string {
	target := strings.TrimRight(endpoint, "/")
	if !strings.Contains(target, "://") {
		scheme := "http"
		if tlsEnabled {
			scheme = "https"
		}
		target = scheme + "://" + target
	}
	for _, known := range []string{"/v1/metrics", "/v1/logs", "/v1/traces"} {
		target = strings.TrimSuffix(target, known)
	}
	return target + path
}

func boundedLogText(value string, maxBytes int) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	if len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value + "…"
}

func normalizedMaxLogRequestBytes(value int) int {
	if value <= 0 {
		return otlpwire.DefaultMaxRequestBytes
	}
	return value
}

func derivedChunkID(envelopeID string, index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", envelopeID, index)))
	return hex.EncodeToString(sum[:16])
}
