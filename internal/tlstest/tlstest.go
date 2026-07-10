// Package tlstest mints throwaway certificates for tests: a CA plus a server
// (SAN 127.0.0.1) and a client leaf signed by it.
package tlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Paths holds the PEM file paths of a generated CA and its server/client leaves.
type Paths struct{ CA, ServerCert, ServerKey, ClientCert, ClientKey string }

// Generate mints a throwaway CA plus a server cert (SAN 127.0.0.1) and a client
// cert signed by it, writing PEM files to a temp dir.
func Generate(t *testing.T) Paths {
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

	leaf := func(cn string, server bool) (certFile, keyFile string) {
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
	return Paths{CA: write("ca.crt", pemCert(caDER)), ServerCert: sc, ServerKey: sk, ClientCert: cc, ClientKey: ck}
}
