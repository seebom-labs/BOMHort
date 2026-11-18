package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/internal/extrafields"
	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/sbom"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func TestIngestExtraFieldsIntoIsolatedClickHouse(t *testing.T) {
	// VEX rescue can touch unrelated rows, so this test requires a dedicated database.
	if os.Getenv("BOMHORT_WORKER_TEST_ISOLATED_DB") != "1" {
		t.Skip("set BOMHORT_WORKER_TEST_ISOLATED_DB=1 for a dedicated migrated ClickHouse")
	}
	host := os.Getenv("CLICKHOUSE_HOST")
	if host == "" {
		t.Fatal("CLICKHOUSE_HOST is required")
	}
	port := os.Getenv("CLICKHOUSE_PORT")
	if port == "" {
		port = "9000"
	}
	db := os.Getenv("CLICKHOUSE_DATABASE")
	if db == "" {
		db = "bomhort"
	}
	user := os.Getenv("CLICKHOUSE_USER")
	if user == "" {
		user = "default"
	}
	conn, err := chdriver.Open(&chdriver.Options{
		Addr: []string{host + ":" + port},
		Auth: chdriver.Auth{Database: db, Username: user, Password: os.Getenv("CLICKHOUSE_PASSWORD")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := &clickhouse.Client{Conn: conn}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	fields, err := extrafields.Parse([]byte(extraFieldsTestConfig))
	if err != nil {
		t.Fatal(err)
	}
	defer sbom.SetUseProtobom(false)

	for _, proto := range []bool{false, true} {
		t.Run(fmt.Sprintf("protobom=%v", proto), func(t *testing.T) {
			sbom.SetUseProtobom(proto)
			job := models.IngestionJob{SourceFile: "payments.cdx.json", SHA256Hash: uuid.NewString()}
			id := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(job.SHA256Hash))
			t.Cleanup(func() {
				for _, table := range []string{"license_compliance", "sbom_packages", "sboms"} {
					if err := conn.Exec(context.Background(), "ALTER TABLE "+table+" DELETE WHERE sbom_id = ? SETTINGS mutations_sync = 1", id); err != nil {
						t.Errorf("cleanup %s: %v", table, err)
					}
				}
			})
			raw := extraFieldsTestBOM
			open := func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(raw)), nil }
			process := func() error {
				return processSBOMJob(ctx, &config.Config{SkipOSV: true}, client, nil,
					func() *license.ExceptionIndex { return nil }, nil, nil, open, nil, fields, job)
			}
			if err := process(); err != nil {
				t.Fatal(err)
			}
			raw = strings.Replace(raw, "payments@example.com", "changed@example.com", 1)
			if err := process(); err != nil {
				t.Fatal(err)
			}
			var got map[string][]string
			if err := conn.QueryRow(ctx, "SELECT extra_fields FROM sboms FINAL WHERE sbom_id = ?", id).Scan(&got); err != nil {
				t.Fatal(err)
			}
			want := map[string][]string{
				"owner_contact": {"payments@example.com", "platform@example.com"},
				"tracker":       {"https://example.test/issues"},
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("stored extra fields = %v, want %v", got, want)
			}
			var count uint64
			if err := conn.QueryRow(ctx, "SELECT count() FROM sboms WHERE sbom_id = ?", id).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Errorf("duplicate produced %d SBOM rows, want 1", count)
			}
		})
	}
}
