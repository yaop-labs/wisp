// Package otlp ships metric batches to coral (or amber directly) over OTLP,
// converting wisp's internal model into ExportMetricsServiceRequest and sending
// it over one of two transports:
//
//   - grpc: ExportMetricsServiceRequest to a MetricsService.
//   - http: protobuf POST /v1/metrics.
//
// Both coral and amber accept metrics over either transport (amber's gRPC server
// registers MetricsService when its metric store is enabled). TLS/mTLS and auth
// headers are configured via Config. Durability (retry + on-disk spool) is
// layered on top by the retry and spool exporters; this exporter is the raw OTLP
// egress.
package otlp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/edge"
	"github.com/yaop-labs/reef/grpcreef"
	"github.com/yaop-labs/reef/reefclient"
	"github.com/yaop-labs/reef/tlsconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"

	"github.com/yaop-labs/wisp/internal/httpx"
	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
)

// transport sends an OTLP request; grpc and http implement it.
type transport interface {
	send(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) error
	close() error
}

// Exporter is an OTLP metrics exporter over gRPC or HTTP.
type Exporter struct {
	tr      transport
	timeout time.Duration
	logger  *slog.Logger
}

// Config configures the exporter.
type Config struct {
	Endpoint string
	Protocol string // "grpc" (default) | "http"
	Timeout  time.Duration
	// TLS, when non-nil, secures the transport (server auth, or mTLS when a
	// client certificate is present). nil -> plaintext.
	TLS *tlsconf.ClientConfig
	// Auth is Reef's bearer-token source (inline, file, or environment).
	Auth *bearer.ClientConfig
	// Insecure explicitly allows plaintext to a non-loopback target.
	Insecure bool
	// DangerAllowBearerOverPlaintext is a separate explicit opt-in to expose a
	// bearer token over plaintext.
	DangerAllowBearerOverPlaintext bool
	// Headers are non-auth metadata sent with every export (e.g. x-tenant).
	// Authorization must be configured through Auth so Reef can enforce policy.
	Headers map[string]string
	// MaxLogRequestBytes bounds each OTLP Logs request after splitting.
	// Zero applies the safe default.
	MaxLogRequestBytes int
}

func New(cfg Config, logger *slog.Logger) (*Exporter, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("otlp exporter: endpoint required")
	}
	if hasHeader(cfg.Headers, "authorization") {
		return nil, fmt.Errorf("otlp exporter: configure bearer credentials via auth, not headers.authorization")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var (
		tr       transport
		warnings []edge.Warning
		err      error
	)
	switch cfg.Protocol {
	case "", "grpc":
		tr, warnings, err = newGRPCTransport(
			cfg.Endpoint,
			cfg.TLS,
			cfg.Auth,
			cfg.Headers,
			cfg.Insecure,
			cfg.DangerAllowBearerOverPlaintext,
		)
	case "http":
		tr, warnings, err = newHTTPTransport(
			cfg.Endpoint,
			cfg.TLS,
			cfg.Auth,
			cfg.Headers,
			cfg.Insecure,
			cfg.DangerAllowBearerOverPlaintext,
		)
	default:
		return nil, fmt.Errorf("otlp exporter: unknown protocol %q (use grpc or http)", cfg.Protocol)
	}
	if err != nil {
		return nil, err
	}
	for _, warning := range warnings {
		logger.Warn("reef configuration warning", "edge", "otlp-exporter", "warning", warning)
	}
	return &Exporter{tr: tr, timeout: timeout, logger: logger}, nil
}

func (e *Exporter) Export(ctx context.Context, b model.Batch) error {
	req := toRequest(b)
	if len(req.ResourceMetrics) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	if err := e.tr.send(ctx, req); err != nil {
		selfobs.ExportFailures.Inc()
		return fmt.Errorf("otlp export: %w", err)
	}
	selfobs.BatchesExported.Inc()
	return nil
}

func (e *Exporter) Close() error { return e.tr.close() }

// --- gRPC transport ---

type grpcTransport struct {
	conn   *grpcreef.Client
	client colmetricspb.MetricsServiceClient
	md     metadata.MD // auth/custom headers attached to each RPC
}

func newGRPCTransport(
	endpoint string,
	tlsConf *tlsconf.ClientConfig,
	auth *bearer.ClientConfig,
	headers map[string]string,
	insecure bool,
	dangerBearer bool,
) (transport, []edge.Warning, error) {
	conn, warnings, err := grpcreef.NewEdgeClient(edge.ClientConfig{
		Target:                         endpoint,
		TLS:                            tlsConf,
		Auth:                           auth,
		Insecure:                       insecure,
		DangerAllowBearerOverPlaintext: dangerBearer,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("otlp exporter: dial %s: %w", endpoint, err)
	}
	return &grpcTransport{
		conn: conn, client: colmetricspb.NewMetricsServiceClient(conn), md: metadataFrom(headers),
	}, warnings, nil
}

func (t *grpcTransport) send(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) error {
	if len(t.md) > 0 {
		ctx = metadata.NewOutgoingContext(ctx, t.md)
	}
	_, err := t.client.Export(ctx, req)
	if err != nil && permanentGRPC(status.Code(err)) {
		return fmt.Errorf("%w: %w", pipeline.ErrPermanent, err)
	}
	return err
}

// permanentGRPC reports gRPC codes that mean the batch itself is bad and will
// never be accepted, so holding or retrying it is pointless. ResourceExhausted
// is deliberately transient: OTLP servers (including wisp's receiver) use it to
// signal rate limiting/backpressure as well as message-size limits.
func permanentGRPC(c codes.Code) bool {
	switch c {
	case codes.InvalidArgument, codes.OutOfRange:
		return true
	default:
		return false
	}
}

// metadataFrom builds gRPC metadata from header config (keys lowercased per
// gRPC convention, in a stable order).
func metadataFrom(headers map[string]string) metadata.MD {
	if len(headers) == 0 {
		return nil
	}
	md := metadata.MD{}
	for k, v := range headers {
		md.Set(strings.ToLower(k), v)
	}
	return md
}

func (t *grpcTransport) close() error { return t.conn.Close() }

// --- HTTP transport ---

type httpTransport struct {
	url     string
	client  *http.Client
	edge    *reefclient.EdgeClient
	headers map[string]string
}

func newHTTPTransport(
	endpoint string,
	tlsConf *tlsconf.ClientConfig,
	auth *bearer.ClientConfig,
	headers map[string]string,
	insecure bool,
	dangerBearer bool,
) (transport, []edge.Warning, error) {
	target := strings.TrimRight(endpoint, "/")
	if !strings.Contains(target, "://") {
		scheme := "http"
		if tlsConf != nil && tlsConf.Enabled {
			scheme = "https"
		}
		target = scheme + "://" + target
	}
	if !strings.HasSuffix(target, "/v1/metrics") {
		target += "/v1/metrics"
	}
	rt, warnings, err := reefclient.NewEdgeTransport(edge.ClientConfig{
		Target:                         target,
		TLS:                            tlsConf,
		Auth:                           auth,
		Insecure:                       insecure,
		DangerAllowBearerOverPlaintext: dangerBearer,
	}, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("otlp exporter http reef: %w", err)
	}
	client := &http.Client{Transport: rt}
	// Timeout is enforced per-request via the context; leave the client open.
	return &httpTransport{url: target, client: client, edge: rt, headers: headers}, warnings, nil
}

func (t *httpTransport) send(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) error {
	body, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	for _, k := range sortedKeys(t.headers) {
		httpReq.Header.Set(k, t.headers[k])
	}

	resp, err := t.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		err := httpx.ErrorFromResponse(resp)
		if permanentHTTP(resp.StatusCode) {
			return fmt.Errorf("%w: %w", pipeline.ErrPermanent, err)
		}
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// permanentHTTP reports HTTP statuses that unambiguously describe a bad payload.
// Authentication, authorization, routing, conflict, timeout, and rate-limit
// failures can recover after configuration or server-state changes, so they must
// remain spooled rather than being discarded.
func permanentHTTP(code int) bool {
	switch code {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}

func (t *httpTransport) close() error { return t.edge.Close() }

// sortedKeys returns map keys in deterministic order (stable header emission).
func sortedKeys(m map[string]string) []string {
	return slices.Sorted(maps.Keys(m))
}

func hasHeader(headers map[string]string, name string) bool {
	for k := range headers {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}
