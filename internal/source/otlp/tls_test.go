package otlp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	exp "github.com/yaop-labs/wisp/internal/exporter/otlp"
	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/tlsconfig"
)

type certPaths struct{ ca, serverCert, serverKey, clientCert, clientKey string }

// genCerts mints a throwaway CA and a server cert (SAN 127.0.0.1) + client cert
// signed by it, writing PEM files to a temp dir.
func genCerts(t *testing.T) certPaths {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pemCert := func(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }
	pemKey := func(k *ecdsa.PrivateKey) []byte {
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	}

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "wisp-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leaf := func(cn string, server bool) (string, string) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		if server {
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		return write(cn+".crt", pemCert(der)), write(cn+".key", pemKey(key))
	}
	sc, sk := leaf("server", true)
	cc, ck := leaf("client", false)
	return certPaths{ca: write("ca.crt", pemCert(caDER)), serverCert: sc, serverKey: sk, clientCert: cc, clientKey: ck}
}

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
	cp := genCerts(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	srvTLS, err := tlsconfig.Server(tlsconfig.Settings{CertFile: cp.serverCert, KeyFile: cp.serverKey})
	if err != nil {
		t.Fatal(err)
	}
	r := New(Options{GRPCAddr: "127.0.0.1:0", TLS: srvTLS}, logger)
	ctx := t.Context()
	got := make(chan model.Batch, 1)
	go func() {
		_ = r.Start(ctx, func(_ context.Context, b model.Batch) error { got <- b; return nil })
	}()

	cliTLS, err := tlsconfig.Client(tlsconfig.Settings{CAFile: cp.ca, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
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
	cp := genCerts(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	srvTLS, err := tlsconfig.Server(tlsconfig.Settings{CertFile: cp.serverCert, KeyFile: cp.serverKey, ClientCAFile: cp.ca})
	if err != nil {
		t.Fatal(err)
	}
	r := New(Options{GRPCAddr: "127.0.0.1:0", TLS: srvTLS}, logger)
	ctx := t.Context()
	go func() {
		_ = r.Start(ctx, func(context.Context, model.Batch) error { return nil })
	}()
	addr := r.GRPCAddr()

	// With a client cert -> success.
	withCert, err := tlsconfig.Client(tlsconfig.Settings{CAFile: cp.ca, ServerName: "127.0.0.1", CertFile: cp.clientCert, KeyFile: cp.clientKey})
	if err != nil {
		t.Fatal(err)
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
	noCert, err := tlsconfig.Client(tlsconfig.Settings{CAFile: cp.ca, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	e2, err := exp.New(exp.Config{Endpoint: addr, Protocol: "grpc", Timeout: 3 * time.Second, TLS: noCert}, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	if err := exportOne(e2); err == nil {
		t.Fatal("mTLS export without client cert should fail")
	}
}
