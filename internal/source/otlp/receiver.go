// Package otlp is the OTLP receive source: wisp runs as a local gateway/sidecar
// that accepts OTLP metrics (gRPC MetricsService and HTTP /v1/metrics) from apps
// using an OTel SDK, converts them to the internal model, and emits them into
// the pipeline - the inverse of the OTLP exporter.
package otlp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/edge"
	"github.com/yaop-labs/reef/grpcreef"
	"github.com/yaop-labs/reef/tlsconf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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
// Reef TLS and bearer blocks secure both transports consistently.
type Options struct {
	GRPCAddr                       string
	HTTPAddr                       string
	TLS                            *tlsconf.ServerConfig
	Auth                           *bearer.ServerConfig
	Insecure                       bool
	DangerAllowBearerOverPlaintext bool
}

// Receiver serves OTLP metrics over gRPC and/or HTTP.
type Receiver struct {
	grpcAddr string
	httpAddr string
	tls      *tls.Config // HTTP server-side TLS; gRPC credentials live in grpcOpts
	secure   bool
	logger   *slog.Logger

	grpcOpts       []grpc.ServerOption
	httpMiddleware func(http.Handler) http.Handler
	grpcEdge       *grpcreef.ServerEdge
	httpEdge       *edge.HTTPServer

	emit func(context.Context, model.Batch) error

	grpcSrv *grpc.Server
	httpSrv *http.Server
	grpcLn  net.Listener
	httpLn  net.Listener
	ready   chan struct{}
}

// New builds a Receiver from opts, materializing Reef's TLS and bearer layers
// before any listener is opened so invalid credentials fail startup.
func New(opts Options, logger *slog.Logger) (*Receiver, error) {
	if logger == nil {
		logger = slog.Default()
	}
	var grpcOpts []grpc.ServerOption
	var grpcEdge *grpcreef.ServerEdge
	if opts.GRPCAddr != "" {
		secured, err := grpcreef.NewServerEdge(edge.ServerConfig{
			Bind:                           opts.GRPCAddr,
			TLS:                            opts.TLS,
			Auth:                           opts.Auth,
			Insecure:                       opts.Insecure,
			DangerAllowBearerOverPlaintext: opts.DangerAllowBearerOverPlaintext,
		})
		if err != nil {
			return nil, fmt.Errorf("otlp receiver grpc reef: %w", err)
		}
		grpcEdge = secured
		grpcOpts = secured.Options
		logWarnings(logger, "otlp-grpc-receiver", secured.Warnings)
	}

	httpMiddleware := func(next http.Handler) http.Handler { return next }
	var httpTLS *tls.Config
	var httpEdge *edge.HTTPServer
	if opts.HTTPAddr != "" {
		secured, err := edge.NewHTTPServer(edge.ServerConfig{
			Bind:                           opts.HTTPAddr,
			TLS:                            opts.TLS,
			Auth:                           opts.Auth,
			Insecure:                       opts.Insecure,
			DangerAllowBearerOverPlaintext: opts.DangerAllowBearerOverPlaintext,
		})
		if err != nil {
			_ = grpcEdge.Close()
			return nil, fmt.Errorf("otlp receiver http reef: %w", err)
		}
		httpEdge = secured
		httpTLS = secured.TLSConfig
		httpMiddleware = secured.Middleware
		logWarnings(logger, "otlp-http-receiver", secured.Warnings)
	}
	return &Receiver{
		grpcAddr: opts.GRPCAddr, httpAddr: opts.HTTPAddr, tls: httpTLS,
		secure: opts.TLS != nil && opts.TLS.Enabled, logger: logger,
		grpcOpts: grpcOpts, httpMiddleware: httpMiddleware,
		grpcEdge: grpcEdge, httpEdge: httpEdge, ready: make(chan struct{}),
	}, nil
}

func logWarnings(logger *slog.Logger, edgeName string, warnings []edge.Warning) {
	for _, warning := range warnings {
		logger.Warn("reef configuration warning", "edge", edgeName, "warning", warning)
	}
}

// Start binds the listeners and serves until ctx is canceled.
func (r *Receiver) Start(ctx context.Context, emit func(context.Context, model.Batch) error) error {
	r.emit = emit
	secure := r.secure

	if r.grpcAddr != "" {
		ln, err := net.Listen("tcp", r.grpcAddr)
		if err != nil {
			close(r.ready)
			_ = r.closeEdges()
			return err
		}
		r.grpcLn = ln
		opts := append([]grpc.ServerOption{grpc.MaxRecvMsgSize(maxBodyBytes)}, r.grpcOpts...)
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
			_ = r.closeEdges()
			return err
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/metrics", r.handleHTTP)
		r.httpLn = ln
		r.httpSrv = &http.Server{
			Handler:           r.httpMiddleware(mux),
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
	var shutdownErr error
	if r.grpcSrv != nil {
		// GracefulStop waits for in-flight RPCs with no deadline of its own, so a
		// stalled client would hold it past the shutdown budget and block the
		// spool flush. Run it in the background and hard-Stop when ctx expires.
		done := make(chan struct{})
		go func() {
			r.grpcSrv.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			// Force-close connections and cancel RPC contexts; the GracefulStop
			// goroutine unwinds as ctx-respecting handlers return (a handler that
			// ignores its context is left to the exiting process).
			r.grpcSrv.Stop()
		}
	}
	if r.httpSrv != nil {
		shutdownErr = r.httpSrv.Shutdown(ctx)
	}
	return errors.Join(shutdownErr, r.closeEdges())
}

func (r *Receiver) closeEdges() error {
	return errors.Join(r.httpEdge.Close(), r.grpcEdge.Close())
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
	return r.emit(ctx, b)
}

type grpcService struct {
	colmetricspb.UnimplementedMetricsServiceServer
	r *Receiver
}

func (s *grpcService) Export(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) (*colmetricspb.ExportMetricsServiceResponse, error) {
	if err := s.r.ingest(ctx, req); err != nil {
		if errors.Is(err, pipeline.ErrBackpressure) {
			return nil, status.Error(codes.ResourceExhausted, "wisp backpressure: spool above high-water mark")
		}
		return nil, err
	}
	return &colmetricspb.ExportMetricsServiceResponse{}, nil
}

func (r *Receiver) handleHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
