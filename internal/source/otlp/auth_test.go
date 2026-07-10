package otlp

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"

	"github.com/yaop-labs/wisp/internal/model"
)

// TestReceiverAPIKeyAuth: with API keys configured, only a valid bearer token
// is accepted over both gRPC and HTTP.
func TestReceiverAPIKeyAuth(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := New(Options{GRPCAddr: "127.0.0.1:0", HTTPAddr: "127.0.0.1:0", APIKeys: []string{"s3cr3t"}}, logger)
	ctx := t.Context()
	go func() {
		_ = r.Start(ctx, func(context.Context, model.Batch) error { return nil })
	}()

	conn, err := grpc.NewClient(r.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := colmetricspb.NewMetricsServiceClient(conn)

	grpcExport := func(token string) codes.Code {
		c := ctx
		if token != "" {
			c = metadata.AppendToOutgoingContext(ctx, "authorization", token)
		}
		cc, cancel := context.WithTimeout(c, 3*time.Second)
		defer cancel()
		_, err := client.Export(cc, onePointRequest())
		return status.Code(err)
	}

	if code := grpcExport(""); code != codes.Unauthenticated {
		t.Errorf("grpc no-token = %v, want Unauthenticated", code)
	}
	if code := grpcExport("Bearer wrong"); code != codes.Unauthenticated {
		t.Errorf("grpc wrong-token = %v, want Unauthenticated", code)
	}
	if code := grpcExport("Bearer s3cr3t"); code != codes.OK {
		t.Errorf("grpc valid-token = %v, want OK", code)
	}

	httpExport := func(token string) int {
		body, _ := proto.Marshal(onePointRequest())
		req, _ := http.NewRequest(http.MethodPost, "http://"+r.HTTPAddr()+"/v1/metrics", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/x-protobuf")
		if token != "" {
			req.Header.Set("Authorization", token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if code := httpExport(""); code != http.StatusUnauthorized {
		t.Errorf("http no-token = %d, want 401", code)
	}
	if code := httpExport("Bearer wrong"); code != http.StatusUnauthorized {
		t.Errorf("http wrong-token = %d, want 401", code)
	}
	if code := httpExport("Bearer s3cr3t"); code != http.StatusOK {
		t.Errorf("http valid-token = %d, want 200", code)
	}
}
