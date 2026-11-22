package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"reflect"
	"strings"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/extrafields"
	"github.com/seebom-labs/bomhort/backend/internal/sbom"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

const extraFieldsTestConfig = `{"fields":[{"name":"owner_contact","from":[
  {"cyclonedx":"metadata.component.properties","property":"bomhort:owner:contact"},
  {"cyclonedx":"metadata.properties","property":"bomhort:owner:contact"}
]},{"name":"tracker","from":[
  {"cyclonedx":"metadata.component.externalReferences","type":"issue-tracker"}
]}]}`

const extraFieldsTestBOM = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
  "metadata": {
    "properties": [{"name": "bomhort:owner:contact", "value": "platform@example.com"}],
    "component": {
      "type": "application", "bom-ref": "app", "name": "payments", "version": "1.0.0",
      "properties": [{"name": "bomhort:owner:contact", "value": "payments@example.com"}],
      "externalReferences": [{"type": "issue-tracker", "url": "https://example.test/issues"}]
    }
  },
  "components": [{"bom-ref": "lib", "name": "lib", "version": "1.0.0", "purl": "pkg:golang/example.com/lib@1.0.0"}]
}`

// The parsed document and the extracted fields end up on the same SBOM row,
// for either parser backend.
func TestApplyExtraFields_BothParserBackends(t *testing.T) {
	defer sbom.SetUseProtobom(false)
	cfg, err := extrafields.Parse([]byte(extraFieldsTestConfig))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"owner_contact": {"payments@example.com", "platform@example.com"},
		"tracker":       {"https://example.test/issues"},
	}

	for _, protobom := range []bool{false, true} {
		sbom.SetUseProtobom(protobom)
		res, err := sbom.Parse(bytes.NewReader([]byte(extraFieldsTestBOM)), "payments.cdx.json", "deadbeef", true)
		if err != nil {
			t.Fatalf("protobom=%v: parse: %v", protobom, err)
		}
		applyExtraFields(&res.SBOM, res.CycloneDXMetadata, cfg)
		if !reflect.DeepEqual(res.SBOM.ExtraFields, want) {
			t.Errorf("protobom=%v: ExtraFields = %#v, want %#v", protobom, res.SBOM.ExtraFields, want)
		}
	}
}

type existenceConn struct {
	driver.Conn
	count uint64
	err   error
	id    any
}

func (c *existenceConn) QueryRow(_ context.Context, _ string, args ...any) driver.Row {
	c.id = args[0]
	return existenceRow{count: c.count, err: c.err}
}

type existenceRow struct {
	driver.Row
	count uint64
	err   error
}

func (r existenceRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*uint64) = r.count
	return nil
}

func TestProcessSBOMJobChecksDuplicateBeforeExtracting(t *testing.T) {
	cfg, err := extrafields.Parse([]byte(extraFieldsTestConfig))
	if err != nil {
		t.Fatal(err)
	}
	conn := &existenceConn{count: 1}
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })
	job := models.IngestionJob{SourceFile: "payments.cdx.json", SHA256Hash: "deadbeef"}
	err = processSBOMJob(context.Background(), nil, &clickhouse.Client{Conn: conn}, nil, nil, nil, nil,
		func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(extraFieldsTestBOM)), nil },
		nil, cfg, job)
	if err != nil {
		t.Fatal(err)
	}
	if conn.id != uuid.NewSHA1(uuid.NameSpaceDNS, []byte(job.SHA256Hash)) {
		t.Fatalf("checked SBOM ID %v, want the parsed document ID", conn.id)
	}
	if !strings.Contains(logs.String(), "already ingested") || strings.Contains(logs.String(), "Recognised extra fields") {
		t.Fatalf("duplicate was not skipped before extraction: %s", logs.String())
	}
}

func TestProcessSBOMJobStopsWhenDuplicateCheckFails(t *testing.T) {
	failure := errors.New("database unavailable")
	conn := &existenceConn{err: failure}
	job := models.IngestionJob{SourceFile: "payments.cdx.json", SHA256Hash: "deadbeef"}
	err := processSBOMJob(context.Background(), nil, &clickhouse.Client{Conn: conn}, nil, nil, nil, nil,
		func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(extraFieldsTestBOM)), nil },
		nil, nil, job)
	if !errors.Is(err, failure) {
		t.Fatalf("error = %v, want duplicate-check failure", err)
	}
}

func TestApplyExtraFields_NoConfigLeavesRowUnchanged(t *testing.T) {
	res, err := sbom.Parse(bytes.NewReader([]byte(extraFieldsTestBOM)), "payments.cdx.json", "deadbeef", false)
	if err != nil {
		t.Fatal(err)
	}
	applyExtraFields(&res.SBOM, res.CycloneDXMetadata, nil)
	if res.SBOM.ExtraFields != nil {
		t.Fatalf("ExtraFields = %#v, want nil without config", res.SBOM.ExtraFields)
	}
}
