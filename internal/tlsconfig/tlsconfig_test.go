package tlsconfig

import (
	"crypto/tls"
	"path/filepath"
	"testing"

	"github.com/yaop-labs/wisp/internal/tlstest"
)

func TestClientConfig(t *testing.T) {
	cp := tlstest.Generate(t)
	cert, key, ca := cp.ServerCert, cp.ServerKey, cp.CA

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
	cp := tlstest.Generate(t)
	cert, key, ca := cp.ServerCert, cp.ServerKey, cp.CA

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
