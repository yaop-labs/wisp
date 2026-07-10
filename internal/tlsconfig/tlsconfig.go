/*
/
/
https://github.com/yaop-labs/reef --   sec here
/
/
/
*/

// Package tlsconfig builds *tls.Config for wisp's OTLP transports from agent
// config. It is transport-agnostic: the same Settings drive the gRPC and HTTP
// client (exporter) and server (receiver) sides, including mutual TLS
package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// Settings is the resolved TLS configuration (no YAML tags; the config package
// maps its own struct onto this).
type Settings struct {
	Enabled bool

	// CAFile is the trust roots used to verify the peer. On the client side it
	// verifies the server; empty means use the system roots.
	CAFile string
	// CertFile/KeyFile is this side's certificate: the server certificate on the
	// receiver, or the client certificate (for mTLS) on the exporter.
	CertFile string
	KeyFile  string
	// ServerName overrides the name verified against the server certificate
	// (client side); useful when dialing by IP.
	ServerName string
	// InsecureSkipVerify disables peer verification (client side). Dev only.
	InsecureSkipVerify bool
	// ClientCAFile, when set on the server side, requires and verifies client
	// certificates against these roots - i.e. enables mutual TLS.
	ClientCAFile string
}

func base() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }

func loadCertPool(file string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("tls: read %s: %w", file, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tls: no PEM certificates in %s", file)
	}
	return pool, nil
}

// Client builds a *tls.Config for an outbound connection (the OTLP exporter).
func Client(s Settings) (*tls.Config, error) {
	cfg := base()
	cfg.ServerName = s.ServerName
	cfg.InsecureSkipVerify = s.InsecureSkipVerify //nolint:gosec // opt-in dev flag
	if s.CAFile != "" {
		pool, err := loadCertPool(s.CAFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	if s.CertFile != "" || s.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls: load client keypair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// Server builds a *tls.Config for an inbound listener (the OTLP receiver). When
// ClientCAFile is set it requires and verifies client certificates (mTLS).
func Server(s Settings) (*tls.Config, error) {
	if s.CertFile == "" || s.KeyFile == "" {
		return nil, fmt.Errorf("tls: server cert_file and key_file are required when tls is enabled")
	}
	cert, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: load server keypair: %w", err)
	}
	cfg := base()
	cfg.Certificates = []tls.Certificate{cert}
	if s.ClientCAFile != "" {
		pool, err := loadCertPool(s.ClientCAFile)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
