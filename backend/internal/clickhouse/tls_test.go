package clickhouse

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/config"
)

func generateTestCertAndKey(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "clickhouse.test",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM
}

func TestBuildTLSConfig(t *testing.T) {
	t.Run("secure false returns nil", func(t *testing.T) {
		cfg := &config.Config{
			ClickHouseSecure: false,
		}
		tlsConfig, err := buildTLSConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tlsConfig != nil {
			t.Fatalf("expected nil tls.Config, got %+v", tlsConfig)
		}
	})

	t.Run("secure true without custom CA", func(t *testing.T) {
		cfg := &config.Config{
			ClickHouseHost:       "ch.internal",
			ClickHouseSecure:     true,
			ClickHouseSkipVerify: true,
		}
		tlsConfig, err := buildTLSConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tlsConfig == nil {
			t.Fatal("expected non-nil tls.Config")
		}
		if tlsConfig.ServerName != "ch.internal" {
			t.Errorf("expected ServerName ch.internal, got %s", tlsConfig.ServerName)
		}
		if !tlsConfig.InsecureSkipVerify {
			t.Error("expected InsecureSkipVerify=true")
		}
	})

	t.Run("secure true with custom CA and client cert", func(t *testing.T) {
		dir := t.TempDir()
		certPEM, keyPEM := generateTestCertAndKey(t)

		caFile := filepath.Join(dir, "ca.crt")
		certFile := filepath.Join(dir, "client.crt")
		keyFile := filepath.Join(dir, "client.key")

		if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
			t.Fatal(err)
		}

		cfg := &config.Config{
			ClickHouseHost:     "secure-clickhouse.example.com",
			ClickHouseSecure:   true,
			ClickHouseCAFile:   caFile,
			ClickHouseCertFile: certFile,
			ClickHouseKeyFile:  keyFile,
		}

		tlsConfig, err := buildTLSConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tlsConfig == nil {
			t.Fatal("expected non-nil tls.Config")
		}
		if tlsConfig.RootCAs == nil {
			t.Fatal("expected RootCAs to be set")
		}
		if len(tlsConfig.Certificates) != 1 {
			t.Fatalf("expected 1 client certificate, got %d", len(tlsConfig.Certificates))
		}
	})

	t.Run("invalid CA file fails cleanly", func(t *testing.T) {
		cfg := &config.Config{
			ClickHouseSecure: true,
			ClickHouseCAFile: "nonexistent-ca.crt",
		}
		_, err := buildTLSConfig(cfg)
		if err == nil {
			t.Fatal("expected error for nonexistent CA file, got nil")
		}
	})
}
