package tlsconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCertAndCA mints a self-signed cert+key and a separate CA PEM in a temp
// dir, returning their paths.
func writeCertAndCA(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return write("c.crt", certPEM),
		write("c.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		write("ca.crt", certPEM)
}

func TestClientConfig(t *testing.T) {
	cert, key, ca := writeCertAndCA(t)

	// CA + server name only (server auth).
	c, err := Client(Settings{CAFile: ca, ServerName: "host"})
	if err != nil {
		t.Fatal(err)
	}
	if c.RootCAs == nil || c.ServerName != "host" || c.MinVersion != tls.VersionTLS12 {
		t.Errorf("client config not built as expected: %+v", c)
	}
	if len(c.Certificates) != 0 {
		t.Error("no client cert expected without CertFile")
	}

	// With a client cert (mTLS client side).
	c2, err := Client(Settings{CAFile: ca, CertFile: cert, KeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	if len(c2.Certificates) != 1 {
		t.Error("client cert should be loaded for mTLS")
	}

	if _, err := Client(Settings{CAFile: filepath.Join(t.TempDir(), "missing.crt")}); err == nil {
		t.Error("missing CA file should error")
	}
	if _, err := Client(Settings{CertFile: cert}); err == nil {
		t.Error("cert without key should error")
	}
}

func TestServerConfig(t *testing.T) {
	cert, key, ca := writeCertAndCA(t)

	s, err := Server(Settings{CertFile: cert, KeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Certificates) != 1 || s.ClientAuth != tls.NoClientCert {
		t.Errorf("server config without client CA should not require client certs: %+v", s)
	}

	// mTLS: client CA set -> require + verify.
	sm, err := Server(Settings{CertFile: cert, KeyFile: key, ClientCAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	if sm.ClientAuth != tls.RequireAndVerifyClientCert || sm.ClientCAs == nil {
		t.Errorf("client_ca_file should enable mTLS: %+v", sm)
	}

	if _, err := Server(Settings{}); err == nil {
		t.Error("server without cert/key should error")
	}
	if _, err := Server(Settings{CertFile: cert, KeyFile: key, ClientCAFile: "nope.crt"}); err == nil {
		t.Error("bad client CA file should error")
	}
}
