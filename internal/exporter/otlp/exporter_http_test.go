package otlp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/pipeline"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestNewProtocolSelection(t *testing.T) {
	if _, err := New(Config{Endpoint: ""}, discardLog()); err == nil {
		t.Error("empty endpoint should error")
	}
	if _, err := New(Config{Endpoint: "x:4317", Protocol: "carrier-pigeon"}, discardLog()); err == nil {
		t.Error("unknown protocol should error")
	}
	for _, p := range []string{"", "grpc", "http"} {
		e, err := New(Config{Endpoint: "127.0.0.1:4317", Protocol: p}, discardLog())
		if err != nil {
			t.Fatalf("protocol %q: %v", p, err)
		}
		_ = e.Close()
	}
}

func TestToRequestGroupsTwoResources(t *testing.T) {
	b := model.Batch{Series: []model.Series{
		{Name: "m1", Type: model.MetricGauge, Resource: model.Labels{{Name: "service.name", Value: "a"}}, Points: []model.Point{{IntValue: 1}}},
		{Name: "m2", Type: model.MetricSum, Monotonic: true, Resource: model.Labels{{Name: "service.name", Value: "a"}}, Points: []model.Point{{IntValue: 2}}},
		{Name: "m3", Type: model.MetricGauge, Resource: model.Labels{{Name: "service.name", Value: "b"}}, Points: []model.Point{{FloatValue: 1.5, IsFloat: true}}},
	}}
	req := toRequest(b)
	if len(req.ResourceMetrics) != 2 {
		t.Fatalf("ResourceMetrics = %d, want 2 (grouped by resource)", len(req.ResourceMetrics))
	}
}

func TestToRequestEmptyBatch(t *testing.T) {
	if rm := toRequest(model.Batch{}).ResourceMetrics; len(rm) != 0 {
		t.Errorf("empty batch -> %d ResourceMetrics, want 0", len(rm))
	}
}

func TestHTTPTransportSuccessWithHeaders(t *testing.T) {
	var (
		mu      sync.Mutex
		gotPath string
		gotCT   string
		gotAuth string
		gotReq  colmetricspb.ExportMetricsServiceRequest
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotPath, gotCT, gotAuth = r.URL.Path, r.Header.Get("Content-Type"), r.Header.Get("Authorization")
		_ = proto.Unmarshal(body, &gotReq)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Endpoint without /v1/metrics must be normalized to it.
	e, err := New(Config{Endpoint: srv.URL, Protocol: "http", Timeout: 2 * time.Second,
		Headers: map[string]string{"authorization": "Bearer tok"}}, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	b := model.Batch{Series: []model.Series{{Name: "m", Type: model.MetricGauge,
		Resource: model.Labels{{Name: "service.name", Value: "app"}}, Points: []model.Point{{IntValue: 7}}}}}
	if err := e.Export(context.Background(), b); err != nil {
		t.Fatalf("export: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotPath != "/v1/metrics" {
		t.Errorf("path = %q, want /v1/metrics (normalized)", gotPath)
	}
	if gotCT != "application/x-protobuf" {
		t.Errorf("content-type = %q", gotCT)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth header = %q, want 'Bearer tok'", gotAuth)
	}
	if len(gotReq.ResourceMetrics) != 1 {
		t.Errorf("server got %d resource metrics, want 1", len(gotReq.ResourceMetrics))
	}
}

func TestHTTPTransportErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	e, err := New(Config{Endpoint: srv.URL + "/v1/metrics", Protocol: "http", Timeout: 2 * time.Second}, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	b := model.Batch{Series: []model.Series{{Name: "m", Type: model.MetricGauge, Points: []model.Point{{IntValue: 1}}}}}
	if err := e.Export(context.Background(), b); err == nil {
		t.Fatal("export to a 500 endpoint should error")
	}
}

func TestHTTPTransportClassifiesStatus(t *testing.T) {
	cases := []struct {
		code      int
		permanent bool
	}{
		{http.StatusBadRequest, true},            // 400: malformed
		{http.StatusRequestEntityTooLarge, true}, // 413: oversized
		{http.StatusUnprocessableEntity, true},   // 422
		{http.StatusUnauthorized, false},         // 401: credentials can be rotated
		{http.StatusForbidden, false},            // 403: authorization can change
		{http.StatusNotFound, false},             // 404: endpoint/config can change
		{http.StatusConflict, false},             // 409: server state can change
		{http.StatusTooManyRequests, false},      // 429: back off, don't drop
		{http.StatusInternalServerError, false},  // 500: transient
		{http.StatusServiceUnavailable, false},   // 503: transient
	}
	b := model.Batch{Series: []model.Series{{Name: "m", Type: model.MetricGauge, Points: []model.Point{{IntValue: 1}}}}}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "nope", tc.code)
		}))
		e, err := New(Config{Endpoint: srv.URL + "/v1/metrics", Protocol: "http", Timeout: 2 * time.Second}, discardLog())
		if err != nil {
			srv.Close()
			t.Fatal(err)
		}
		gotErr := e.Export(context.Background(), b)
		if gotErr == nil {
			t.Errorf("status %d: expected an error", tc.code)
		} else if got := errors.Is(gotErr, pipeline.ErrPermanent); got != tc.permanent {
			t.Errorf("status %d: permanent=%v, want %v", tc.code, got, tc.permanent)
		}
		_ = e.Close()
		srv.Close()
	}
}

func TestGRPCPermanentClassification(t *testing.T) {
	cases := []struct {
		code      codes.Code
		permanent bool
	}{
		{codes.InvalidArgument, true},
		{codes.OutOfRange, true},
		{codes.Unimplemented, false},     // server capability/config can change
		{codes.ResourceExhausted, false}, // receiver backpressure / rate limiting
		{codes.Unauthenticated, false},   // credentials can be rotated
		{codes.PermissionDenied, false},  // authorization can change
		{codes.Unavailable, false},
	}
	for _, tc := range cases {
		if got := permanentGRPC(tc.code); got != tc.permanent {
			t.Errorf("code %s: permanent=%v, want %v", tc.code, got, tc.permanent)
		}
	}
}
