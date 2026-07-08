// Package otlp ships metric batches to coral (or amber directly) over OTLP. It
// converts wisp's internal model into an OTLP request per the wisp / coral /
// amber contract and sends it over one of two transports:
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
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"

	"github.com/yaop-labs/wisp/internal/model"
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
	TLS *tls.Config
	// Headers are sent with every export (e.g. {"authorization": "Bearer ..."}).
	Headers map[string]string
}

func New(cfg Config, logger *slog.Logger) (*Exporter, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("otlp exporter: endpoint required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var (
		tr  transport
		err error
	)
	switch cfg.Protocol {
	case "", "grpc":
		tr, err = newGRPCTransport(cfg.Endpoint, cfg.TLS, cfg.Headers)
	case "http":
		tr, err = newHTTPTransport(cfg.Endpoint, cfg.TLS, cfg.Headers)
	default:
		return nil, fmt.Errorf("otlp exporter: unknown protocol %q (use grpc or http)", cfg.Protocol)
	}
	if err != nil {
		return nil, err
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
	conn   *grpc.ClientConn
	client colmetricspb.MetricsServiceClient
	md     metadata.MD // auth/custom headers attached to each RPC
}

func newGRPCTransport(endpoint string, tlsConf *tls.Config, headers map[string]string) (transport, error) {
	creds := insecure.NewCredentials()
	if tlsConf != nil {
		creds = credentials.NewTLS(tlsConf)
	}
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: dial %s: %w", endpoint, err)
	}
	return &grpcTransport{conn: conn, client: colmetricspb.NewMetricsServiceClient(conn), md: metadataFrom(headers)}, nil
}

func (t *grpcTransport) send(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) error {
	if len(t.md) > 0 {
		ctx = metadata.NewOutgoingContext(ctx, t.md)
	}
	_, err := t.client.Export(ctx, req)
	return err
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
	headers map[string]string
}

func newHTTPTransport(endpoint string, tlsConf *tls.Config, headers map[string]string) (transport, error) {
	url := strings.TrimRight(endpoint, "/")
	if !strings.HasSuffix(url, "/v1/metrics") {
		url += "/v1/metrics"
	}
	client := &http.Client{}
	if tlsConf != nil {
		client.Transport = &http.Transport{TLSClientConfig: tlsConf}
	}
	// Timeout is enforced per-request via the context; leave the client open.
	return &httpTransport{url: url, client: client, headers: headers}, nil
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
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (t *httpTransport) close() error { return nil }

// sortedKeys returns map keys in deterministic order (stable header emission).
func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
