package otlp

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/yaop-labs/reef/reeftest"
	"github.com/yaop-labs/reef/tlsconf"

	exp "github.com/yaop-labs/wisp/internal/exporter/otlp"
	"github.com/yaop-labs/wisp/internal/model"
)

func exportOne(e *exp.Exporter) error {
	return e.Export(context.Background(), model.Batch{Series: []model.Series{{
		Name: "m", Type: model.MetricGauge,
		Resource: model.Labels{{Name: "service.name", Value: "app"}},
		Points:   []model.Point{{TimeUnixNano: 1, IntValue: 1}},
	}}})
}

// TestTLSRoundTrip: a TLS receiver and a TLS exporter complete a handshake and
// deliver a batch (server authentication only).
func TestTLSRoundTrip(t *testing.T) {
	cp := reeftest.GenCerts(t, t.TempDir())
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	srvTLS := &tlsconf.ServerConfig{Enabled: true, CertFile: cp.ServerCert, KeyFile: cp.ServerKey}
	r := mustReceiver(t, Options{GRPCAddr: "127.0.0.1:0", TLS: srvTLS}, logger)
	ctx := t.Context()
	got := make(chan model.Batch, 1)
	go func() {
		_ = r.Start(ctx, func(_ context.Context, b model.Batch) error { got <- b; return nil })
	}()

	cliTLS := &tlsconf.ClientConfig{Enabled: true, CAFile: cp.CACert, ServerName: "127.0.0.1"}
	e, err := exp.New(exp.Config{Endpoint: r.GRPCAddr(), Protocol: "grpc", Timeout: 5 * time.Second, TLS: cliTLS}, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := exportOne(e); err != nil {
		t.Fatalf("tls export: %v", err)
	}
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for TLS-delivered batch")
	}
}

// TestMutualTLS: the receiver requires a client certificate. Export succeeds
// with one and fails without (the handshake is rejected).
func TestMutualTLS(t *testing.T) {
	cp := reeftest.GenCerts(t, t.TempDir())
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	srvTLS := &tlsconf.ServerConfig{
		Enabled: true, CertFile: cp.ServerCert, KeyFile: cp.ServerKey, ClientCAFile: cp.CACert,
	}
	r := mustReceiver(t, Options{GRPCAddr: "127.0.0.1:0", TLS: srvTLS}, logger)
	ctx := t.Context()
	go func() {
		_ = r.Start(ctx, func(context.Context, model.Batch) error { return nil })
	}()
	addr := r.GRPCAddr()

	// With a client cert -> success.
	withCert := &tlsconf.ClientConfig{
		Enabled: true, CAFile: cp.CACert, ServerName: "127.0.0.1", CertFile: cp.ClientCert, KeyFile: cp.ClientKey,
	}
	e1, err := exp.New(exp.Config{Endpoint: addr, Protocol: "grpc", Timeout: 5 * time.Second, TLS: withCert}, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer e1.Close()
	if err := exportOne(e1); err != nil {
		t.Fatalf("mTLS export with client cert should succeed: %v", err)
	}

	// Without a client cert -> the server rejects the handshake.
	noCert := &tlsconf.ClientConfig{Enabled: true, CAFile: cp.CACert, ServerName: "127.0.0.1"}
	e2, err := exp.New(exp.Config{Endpoint: addr, Protocol: "grpc", Timeout: 3 * time.Second, TLS: noCert}, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	if err := exportOne(e2); err == nil {
		t.Fatal("mTLS export without client cert should fail")
	}
}
