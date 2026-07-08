// Package otlp is the OTLP receive source: wisp runs as a local gateway/sidecar
// that accepts OTLP metrics (gRPC MetricsService and HTTP /v1/metrics) from apps
// using an OTel SDK, converts them to the internal model, and emits them into
// the pipeline - the inverse of the OTLP exporter.
package otlp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
)

const maxBodyBytes = 16 << 20

// Options configures a Receiver. Empty GRPCAddr/HTTPAddr disable that transport;
// a non-nil TLS secures both (mTLS when it requires client certs); non-empty
// APIKeys gate ingest behind a bearer token.
type Options struct {
	GRPCAddr string
	HTTPAddr string
	TLS      *tls.Config
	APIKeys  []string
}

// Receiver serves OTLP metrics over gRPC and/or HTTP.
type Receiver struct {
	grpcAddr string
	httpAddr string
	tls      *tls.Config         // server-side TLS (mTLS when client CAs set); nil -> plaintext
	apiKeys  map[string]struct{} // accepted bearer tokens; empty -> auth disabled
	logger   *slog.Logger

	emit func(context.Context, model.Batch) error

	grpcSrv *grpc.Server
	httpSrv *http.Server
	grpcLn  net.Listener
	httpLn  net.Listener
	ready   chan struct{}
}

// New builds a Receiver from opts.
func New(opts Options, logger *slog.Logger) *Receiver {
	var keys map[string]struct{}
	if len(opts.APIKeys) > 0 {
		keys = make(map[string]struct{}, len(opts.APIKeys))
		for _, k := range opts.APIKeys {
			keys[k] = struct{}{}
		}
	}
	return &Receiver{
		grpcAddr: opts.GRPCAddr, httpAddr: opts.HTTPAddr, tls: opts.TLS,
		apiKeys: keys, logger: logger, ready: make(chan struct{}),
	}
}

// authorized reports whether a request's bearer credential is accepted. When no
// API keys are configured, auth is disabled (all requests pass).
func (r *Receiver) authorized(authHeader string) bool {
	if len(r.apiKeys) == 0 {
		return true
	}
	const prefix = "Bearer "
	if len(authHeader) <= len(prefix) || !strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return false
	}
	_, ok := r.apiKeys[authHeader[len(prefix):]]
	return ok
}

// Start binds the listeners and serves until ctx is canceled.
func (r *Receiver) Start(ctx context.Context, emit func(context.Context, model.Batch) error) error {
	r.emit = emit
	secure := r.tls != nil

	if r.grpcAddr != "" {
		ln, err := net.Listen("tcp", r.grpcAddr)
		if err != nil {
			close(r.ready)
			return err
		}
		r.grpcLn = ln
		opts := []grpc.ServerOption{grpc.MaxRecvMsgSize(maxBodyBytes)}
		if secure {
			opts = append(opts, grpc.Creds(credentials.NewTLS(r.tls)))
		}
		r.grpcSrv = grpc.NewServer(opts...)
		colmetricspb.RegisterMetricsServiceServer(r.grpcSrv, &grpcService{r: r})
		go func() { _ = r.grpcSrv.Serve(ln) }()
		r.logger.Info("otlp receiver grpc listening", "addr", ln.Addr().String(), "tls", secure)
	}

	if r.httpAddr != "" {
		ln, err := net.Listen("tcp", r.httpAddr)
		if err != nil {
			if r.grpcSrv != nil {
				r.grpcSrv.Stop() // don't leak the gRPC server already started above
			}
			close(r.ready)
			return err
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/metrics", r.handleHTTP)
		r.httpLn = ln
		r.httpSrv = &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second, // bound slow-header (Slowloris) clients
			IdleTimeout:       120 * time.Second,
		}
		if secure {
			r.httpSrv.TLSConfig = r.tls
			go func() { _ = r.httpSrv.ServeTLS(ln, "", "") }() // certs come from TLSConfig
		} else {
			go func() { _ = r.httpSrv.Serve(ln) }()
		}
		r.logger.Info("otlp receiver http listening", "addr", ln.Addr().String(), "tls", secure)
	}

	close(r.ready)
	<-ctx.Done()
	return nil
}

// Stop gracefully shuts the servers down.
func (r *Receiver) Stop(ctx context.Context) error {
	if r.grpcSrv != nil {
		r.grpcSrv.GracefulStop()
	}
	if r.httpSrv != nil {
		return r.httpSrv.Shutdown(ctx)
	}
	return nil
}

// GRPCAddr returns the bound gRPC address (for tests using :0).
func (r *Receiver) GRPCAddr() string {
	<-r.ready
	if r.grpcLn == nil {
		return ""
	}
	return r.grpcLn.Addr().String()
}

// HTTPAddr returns the bound HTTP address (for tests using :0).
func (r *Receiver) HTTPAddr() string {
	<-r.ready
	if r.httpLn == nil {
		return ""
	}
	return r.httpLn.Addr().String()
}

// ingest converts and emits a received OTLP request.
func (r *Receiver) ingest(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) error {
	series, unsupported := seriesFromRequest(req)
	if unsupported > 0 {
		selfobs.OTLPUnsupported.Add(uint64(unsupported))
	}
	if len(series) == 0 {
		return nil
	}
	b := model.Batch{Series: series}
	selfobs.OTLPReceived.Add(uint64(b.Len()))
	selfobs.SamplesEmitted.Add(uint64(b.Len()))
	return r.emit(ctx, b)
}

type grpcService struct {
	colmetricspb.UnimplementedMetricsServiceServer
	r *Receiver
}

func (s *grpcService) Export(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) (*colmetricspb.ExportMetricsServiceResponse, error) {
	if !s.r.authorized(bearerFromMetadata(ctx)) {
		return nil, status.Error(codes.Unauthenticated, "missing or invalid bearer token")
	}
	if err := s.r.ingest(ctx, req); err != nil {
		if errors.Is(err, pipeline.ErrBackpressure) {
			return nil, status.Error(codes.ResourceExhausted, "wisp backpressure: spool above high-water mark")
		}
		return nil, err
	}
	return &colmetricspb.ExportMetricsServiceResponse{}, nil
}

// bearerFromMetadata pulls the Authorization value from incoming gRPC metadata.
func bearerFromMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if vals := md.Get("authorization"); len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func (r *Receiver) handleHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !r.authorized(req.Header.Get("Authorization")) {
		http.Error(w, "missing or invalid bearer token", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var pb colmetricspb.ExportMetricsServiceRequest
	if err := proto.Unmarshal(body, &pb); err != nil {
		http.Error(w, "bad protobuf: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := r.ingest(req.Context(), &pb); err != nil && !errors.Is(err, context.Canceled) {
		if errors.Is(err, pipeline.ErrBackpressure) {
			http.Error(w, "wisp backpressure: spool above high-water mark", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "pipeline unavailable", http.StatusServiceUnavailable)
		return
	}
	resp, _ := proto.Marshal(&colmetricspb.ExportMetricsServiceResponse{})
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}
