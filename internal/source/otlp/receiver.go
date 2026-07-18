// Package otlp is the OTLP receive source. Metrics are converted into Wisp's
// typed pipeline model; logs and traces retain their protobuf representation
// and enter the signal-neutral durability path directly.
package otlp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"time"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/edge"
	"github.com/yaop-labs/reef/grpcreef"
	"github.com/yaop-labs/reef/tlsconf"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/otlpwire"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
	"github.com/yaop-labs/wisp/internal/signal"
)

const maxBodyBytes = otlpwire.MaxReceiverRequestBytes

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
	MaxLogRequestBytes             int
	MaxTraceRequestBytes           int
	Traces                         TraceOptions
}

// Receiver serves OTLP metrics and enabled opaque signal capabilities over
// gRPC and/or HTTP.
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
	// logsEmit bypasses metric processors and preserves the OTLP protobuf as an
	// opaque durable envelope.
	logsEmit             func(context.Context, signal.Envelope) error
	tracesEmit           func(context.Context, signal.Envelope) error
	maxLogRequestBytes   int
	maxTraceRequestBytes int
	traceProcessing      traceProcessing

	grpcSrv *grpc.Server
	httpSrv *http.Server
	grpcLn  net.Listener
	httpLn  net.Listener
	ready   chan struct{}
}

// SetLogsEmitter enables OTLP Logs on the same listeners. It must be called
// before Start.
func (r *Receiver) SetLogsEmitter(emit func(context.Context, signal.Envelope) error) {
	r.logsEmit = emit
}

// SetTracesEmitter enables OTLP Traces on the same listeners. It must be called
// before Start.
func (r *Receiver) SetTracesEmitter(emit func(context.Context, signal.Envelope) error) {
	r.tracesEmit = emit
}

// New builds a Receiver from opts, materializing Reef's TLS and bearer layers
// before any listener is opened so invalid credentials fail startup.
func New(opts Options, logger *slog.Logger) (*Receiver, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if opts.MaxTraceRequestBytes < 0 ||
		opts.MaxTraceRequestBytes >
			otlpwire.MaxReceiverRequestBytes {
		return nil, fmt.Errorf(
			"otlp traces: max request bytes must be between 0 and %d",
			otlpwire.MaxReceiverRequestBytes,
		)
	}
	traceProcessing, err := newTraceProcessing(opts.Traces)
	if err != nil {
		return nil, err
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
		maxLogRequestBytes: normalizedLogRequestBytes(
			opts.MaxLogRequestBytes,
		),
		maxTraceRequestBytes: normalizedTraceRequestBytes(
			opts.MaxTraceRequestBytes,
		),
		traceProcessing: traceProcessing,
	}, nil
}

func normalizedLogRequestBytes(value int) int {
	if value <= 0 {
		return otlpwire.DefaultMaxRequestBytes
	}
	return value
}

func normalizedTraceRequestBytes(value int) int {
	if value <= 0 {
		return otlpwire.DefaultMaxRequestBytes
	}
	return value
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
		if r.logsEmit != nil {
			collogspb.RegisterLogsServiceServer(r.grpcSrv, &grpcLogsService{r: r})
		}
		if r.tracesEmit != nil {
			coltracepb.RegisterTraceServiceServer(r.grpcSrv, &grpcTracesService{r: r})
		}
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
		if r.logsEmit != nil {
			mux.HandleFunc("/v1/logs", r.handleLogsHTTP)
		}
		if r.tracesEmit != nil {
			mux.HandleFunc("/v1/traces", r.handleTracesHTTP)
		}
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

func (r *Receiver) ingestLogs(ctx context.Context, request *collogspb.ExportLogsServiceRequest) error {
	if r.logsEmit == nil {
		return fmt.Errorf("%w: OTLP Logs capability is disabled", pipeline.ErrPermanent)
	}
	records := otlpwire.LogRecordCount(request)
	if records == 0 {
		return nil
	}
	maxRequestBytes := normalizedLogRequestBytes(r.maxLogRequestBytes)
	if proto.Size(request) > maxRequestBytes {
		selfobs.OTLPLogsSplitRequests.Inc()
	}
	err := otlpwire.ForEachLogsChunk(
		request,
		maxRequestBytes,
		func(chunk otlpwire.LogsChunk) error {
			payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(chunk.Request)
			if err != nil {
				return fmt.Errorf("%w: encode OTLP Logs: %v", pipeline.ErrPermanent, err)
			}
			envelope, err := signal.New(
				signal.Logs, signal.OTLPLogsSchema, signal.OTLPProtobufEncoding,
				payload, commonLogsResource(chunk.Request),
			)
			if err != nil {
				return err
			}
			if err := r.logsEmit(ctx, envelope); err != nil {
				return err
			}
			selfobs.OTLPLogsReceived.Add(uint64(chunk.Records))
			selfobs.OTLPLogsChunks.Inc()
			return nil
		},
	)
	if errors.Is(err, otlpwire.ErrLogRecordTooLarge) {
		return fmt.Errorf("%w: %w", pipeline.ErrPermanent, err)
	}
	return err
}

func commonLogsResource(request *collogspb.ExportLogsServiceRequest) map[string]string {
	return commonResourceIdentity(len(request.ResourceLogs), func(i int) *resourcepb.Resource {
		if request.ResourceLogs[i] == nil {
			return nil
		}
		return request.ResourceLogs[i].Resource
	})
}

func commonResourceIdentity(count int, resourceAt func(int) *resourcepb.Resource) map[string]string {
	var common map[string]string
	for i := range count {
		attributes := make(map[string]string)
		if resource := resourceAt(i); resource != nil {
			for _, attribute := range resource.Attributes {
				if attribute == nil {
					continue
				}
				if !signal.IsIdentityKey(attribute.Key) {
					continue
				}
				if _, duplicate := attributes[attribute.Key]; duplicate {
					return nil
				}
				if attribute.Value == nil {
					return nil
				}
				value, ok := attribute.Value.GetValue().(*commonpb.AnyValue_StringValue)
				if !ok {
					return nil
				}
				attributes[attribute.Key] = value.StringValue
			}
		}
		identity, ok := signal.ResourceIdentity(attributes)
		if !ok {
			return nil
		}
		if i == 0 {
			common = identity
		} else if !maps.Equal(common, identity) {
			return nil
		}
	}
	return common
}

type traceIngestResult struct {
	rejectedTraces int
	rejectedSpans  int
}

func (r *Receiver) ingestTraces(
	ctx context.Context,
	request *coltracepb.ExportTraceServiceRequest,
) error {
	_, err := r.ingestTracesResult(ctx, request)
	return err
}

func (r *Receiver) ingestTracesResult(
	ctx context.Context,
	request *coltracepb.ExportTraceServiceRequest,
) (traceIngestResult, error) {
	var ingestResult traceIngestResult
	if r.tracesEmit == nil {
		return ingestResult, fmt.Errorf(
			"%w: OTLP Traces capability is disabled",
			pipeline.ErrPermanent,
		)
	}
	spans := otlpwire.TraceSpanCount(request)
	if spans == 0 {
		return ingestResult, nil
	}
	if r.traceProcessing.validation != TraceValidationOff {
		report := validateTraceCorrelation(request)
		recordTraceValidation(report)
		if report.invalid() &&
			r.traceProcessing.validation == TraceValidationReject {
			return ingestResult, fmt.Errorf(
				"%w: OTLP Traces correlation validation failed: %s",
				pipeline.ErrPermanent,
				report.message(),
			)
		}
	}
	processed, err := r.traceProcessing.enrich(request)
	if err != nil {
		selfobs.OTLPTraceResourceConflicts.Inc()
		return ingestResult, fmt.Errorf(
			"%w: OTLP Traces resource enrichment: %v",
			pipeline.ErrPermanent,
			err,
		)
	}
	maxRequestBytes := normalizedTraceRequestBytes(
		r.maxTraceRequestBytes,
	)
	if proto.Size(processed) > maxRequestBytes {
		selfobs.OTLPTraceSplitRequests.Inc()
	}
	emitChunk := func(chunk otlpwire.TracesChunk) error {
		payload, err := (proto.MarshalOptions{
			Deterministic: true,
		}).Marshal(chunk.Request)
		if err != nil {
			return fmt.Errorf(
				"%w: encode OTLP Traces: %v",
				pipeline.ErrPermanent,
				err,
			)
		}
		envelope, err := signal.New(
			signal.Traces,
			signal.OTLPTracesSchema,
			signal.OTLPProtobufEncoding,
			payload,
			commonTracesResource(chunk.Request),
		)
		if err != nil {
			return fmt.Errorf(
				"%w: create OTLP Traces envelope: %v",
				pipeline.ErrPermanent,
				err,
			)
		}
		if err := r.tracesEmit(ctx, envelope); err != nil {
			return err
		}
		selfobs.OTLPTraceSpansReceived.Add(
			uint64(chunk.Spans),
		)
		selfobs.OTLPTraceChunks.Inc()
		if len(r.traceProcessing.resourceKeys) > 0 {
			selfobs.OTLPTraceResourceEnrichedSpans.Add(
				uint64(chunk.Spans),
			)
		}
		return nil
	}
	var splitResult otlpwire.TracesSplitResult
	if r.traceProcessing.sampling.enabled {
		splitResult, err = otlpwire.ForEachSelectedTracesChunk(
			processed,
			maxRequestBytes,
			r.traceProcessing.sampling.selectTrace,
			emitChunk,
		)
	} else {
		splitResult, err = otlpwire.ForEachTracesChunk(
			processed,
			maxRequestBytes,
			emitChunk,
		)
	}
	if err != nil {
		if errors.Is(
			err,
			otlpwire.ErrTraceRequestMetadataTooLarge,
		) {
			return ingestResult, fmt.Errorf(
				"%w: %w",
				pipeline.ErrPermanent,
				err,
			)
		}
		return ingestResult, err
	}
	ingestResult.rejectedTraces = splitResult.RejectedTraces
	ingestResult.rejectedSpans = splitResult.RejectedSpans
	selfobs.OTLPTraceOversizedTraces.Add(
		uint64(splitResult.RejectedTraces),
	)
	selfobs.OTLPTraceOversizedSpans.Add(
		uint64(splitResult.RejectedSpans),
	)
	if r.traceProcessing.sampling.enabled {
		selfobs.OTLPTraceSamplingRequests.Inc()
		selfobs.OTLPTraceSamplingKeptTraces.Add(
			uint64(splitResult.SelectedTraces),
		)
		selfobs.OTLPTraceSamplingKeptSpans.Add(
			uint64(splitResult.SelectedSpans),
		)
		selfobs.OTLPTraceSamplingDroppedTraces.Add(
			uint64(splitResult.ExcludedTraces),
		)
		selfobs.OTLPTraceSamplingDroppedSpans.Add(
			uint64(splitResult.ExcludedSpans),
		)
		selfobs.OTLPTraceSamplingInvalidUnitsBypassed.Add(
			uint64(splitResult.BypassedInvalidTraces),
		)
	}
	selfobs.OTLPTraceRequestsReceived.Inc()
	return ingestResult, nil
}

func recordTraceValidation(report traceValidationReport) {
	selfobs.OTLPTraceValidationRequests.Inc()
	if !report.invalid() {
		return
	}
	selfobs.OTLPTraceValidationFailures.Inc()
	selfobs.OTLPTraceInvalidSpans.Add(uint64(report.invalidSpans))
	selfobs.OTLPTraceInvalidTraceIDs.Add(uint64(report.invalidTraceIDs))
	selfobs.OTLPTraceInvalidSpanIDs.Add(uint64(report.invalidSpanIDs))
	selfobs.OTLPTraceInvalidParentIDs.Add(uint64(report.invalidParentIDs))
	selfobs.OTLPTraceInvalidLinks.Add(uint64(report.invalidLinks))
	selfobs.OTLPTraceInvalidTraceStates.Add(
		uint64(report.invalidTraceStates),
	)
	selfobs.OTLPTraceDuplicateSpanIDs.Add(uint64(report.duplicateSpanIDs))
	selfobs.OTLPTraceParentCycleSpans.Add(uint64(report.parentCycleSpans))
	selfobs.OTLPTraceMissingNames.Add(uint64(report.missingNames))
	selfobs.OTLPTraceInvalidTimestamps.Add(
		uint64(report.invalidTimestamps),
	)
}

func commonTracesResource(request *coltracepb.ExportTraceServiceRequest) map[string]string {
	return commonResourceIdentity(len(request.ResourceSpans), func(i int) *resourcepb.Resource {
		if request.ResourceSpans[i] == nil {
			return nil
		}
		return request.ResourceSpans[i].Resource
	})
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

type grpcLogsService struct {
	collogspb.UnimplementedLogsServiceServer
	r *Receiver
}

type grpcTracesService struct {
	coltracepb.UnimplementedTraceServiceServer
	r *Receiver
}

func (s *grpcTracesService) Export(ctx context.Context, request *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	result, err := s.r.ingestTracesResult(ctx, request)
	if err != nil {
		switch {
		case errors.Is(err, pipeline.ErrBackpressure):
			return nil, status.Error(codes.ResourceExhausted, "wisp backpressure: traces spool above high-water mark")
		case errors.Is(err, pipeline.ErrPermanent):
			return nil, status.Error(codes.InvalidArgument, err.Error())
		default:
			return nil, status.Error(codes.Unavailable, "wisp traces pipeline unavailable")
		}
	}
	return traceServiceResponse(result), nil
}

func (s *grpcLogsService) Export(ctx context.Context, request *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	if err := s.r.ingestLogs(ctx, request); err != nil {
		switch {
		case errors.Is(err, pipeline.ErrBackpressure):
			return nil, status.Error(codes.ResourceExhausted, "wisp backpressure: logs spool above high-water mark")
		case errors.Is(err, pipeline.ErrPermanent):
			return nil, status.Error(codes.InvalidArgument, err.Error())
		default:
			return nil, status.Error(codes.Unavailable, "wisp logs pipeline unavailable")
		}
	}
	return &collogspb.ExportLogsServiceResponse{}, nil
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

func (r *Receiver) handleLogsHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var request collogspb.ExportLogsServiceRequest
	if err := proto.Unmarshal(body, &request); err != nil {
		http.Error(w, "bad protobuf: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := r.ingestLogs(req.Context(), &request); err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			return
		case errors.Is(err, pipeline.ErrBackpressure):
			http.Error(w, "wisp backpressure: logs spool above high-water mark", http.StatusTooManyRequests)
		case errors.Is(err, otlpwire.ErrLogRecordTooLarge):
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		case errors.Is(err, pipeline.ErrPermanent):
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			http.Error(w, "logs pipeline unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	response, _ := proto.Marshal(&collogspb.ExportLogsServiceResponse{})
	w.Header().Set("Content-Type", signal.OTLPProtobufEncoding)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

func (r *Receiver) handleTracesHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeOTLPHTTPStatus(
			w,
			http.StatusMethodNotAllowed,
			codes.InvalidArgument,
			"method not allowed",
		)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeOTLPHTTPStatus(
				w,
				http.StatusRequestEntityTooLarge,
				codes.InvalidArgument,
				"OTLP Traces request body too large",
			)
			return
		}
		writeOTLPHTTPStatus(
			w,
			http.StatusBadRequest,
			codes.InvalidArgument,
			"could not read OTLP Traces request body",
		)
		return
	}
	var request coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(body, &request); err != nil {
		writeOTLPHTTPStatus(
			w,
			http.StatusBadRequest,
			codes.InvalidArgument,
			"invalid OTLP Traces protobuf",
		)
		return
	}
	result, err := r.ingestTracesResult(req.Context(), &request)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			return
		case errors.Is(err, pipeline.ErrBackpressure):
			writeOTLPHTTPStatus(
				w,
				http.StatusTooManyRequests,
				codes.ResourceExhausted,
				"wisp backpressure: traces spool above high-water mark",
			)
		case errors.Is(err, pipeline.ErrPermanent):
			writeOTLPHTTPStatus(
				w,
				http.StatusBadRequest,
				codes.InvalidArgument,
				err.Error(),
			)
		default:
			writeOTLPHTTPStatus(
				w,
				http.StatusServiceUnavailable,
				codes.Unavailable,
				"traces pipeline unavailable",
			)
		}
		return
	}
	response, _ := proto.Marshal(traceServiceResponse(result))
	w.Header().Set("Content-Type", signal.OTLPProtobufEncoding)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

func traceServiceResponse(
	result traceIngestResult,
) *coltracepb.ExportTraceServiceResponse {
	response := &coltracepb.ExportTraceServiceResponse{}
	if result.rejectedSpans == 0 {
		return response
	}
	response.PartialSuccess = &coltracepb.ExportTracePartialSuccess{
		RejectedSpans: int64(result.rejectedSpans),
		ErrorMessage: fmt.Sprintf(
			"%d spans in %d complete traces exceeded "+
				"max_trace_request_bytes",
			result.rejectedSpans,
			result.rejectedTraces,
		),
	}
	return response
}

func writeOTLPHTTPStatus(
	writer http.ResponseWriter,
	httpStatus int,
	code codes.Code,
	message string,
) {
	body, err := proto.Marshal(&statuspb.Status{
		Code: int32(code), Message: message,
	})
	if err != nil {
		http.Error(writer, "OTLP response encoding failed", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", signal.OTLPProtobufEncoding)
	writer.WriteHeader(httpStatus)
	_, _ = writer.Write(body)
}
