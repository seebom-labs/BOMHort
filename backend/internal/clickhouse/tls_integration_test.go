package clickhouse

import (
	"os"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/config"
)

// TestClickHouseVerifiedTLSIntegration runs against a real TLS-enabled
// ClickHouse server when CLICKHOUSE_TLS_INTEGRATION=1. The CI job creates a
// disposable server that requires a client certificate signed by the test CA.
func TestClickHouseVerifiedTLSIntegration(t *testing.T) {
	if os.Getenv("CLICKHOUSE_TLS_INTEGRATION") != "1" {
		t.Skip("requires the TLS ClickHouse integration job")
	}

	base := &config.Config{
		ClickHouseHost:     os.Getenv("CLICKHOUSE_HOST"),
		ClickHousePort:     9440,
		ClickHouseDatabase: "bomhort",
		ClickHouseUser:     "default",
		ClickHouseSecure:   true,
		ClickHouseCAFile:   os.Getenv("CLICKHOUSE_CA_FILE"),
		ClickHouseCertFile: os.Getenv("CLICKHOUSE_CERT_FILE"),
		ClickHouseKeyFile:  os.Getenv("CLICKHOUSE_KEY_FILE"),
	}

	client, err := NewClient(base)
	if err != nil {
		t.Fatalf("verified TLS/mTLS connection failed: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close verified TLS connection: %v", err)
	}

	withoutClientIdentity := *base
	withoutClientIdentity.ClickHouseCertFile = ""
	withoutClientIdentity.ClickHouseKeyFile = ""
	if client, err := NewClient(&withoutClientIdentity); err == nil {
		_ = client.Close()
		t.Fatal("TLS server accepted a connection without the required client certificate")
	}
}
