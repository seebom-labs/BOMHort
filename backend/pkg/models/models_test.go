package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSBOM_ClusterField(t *testing.T) {
	sbom := SBOM{
		IngestedAt:   time.Now(),
		SBOMID:       uuid.New(),
		SourceFile:   "test.spdx.json",
		DocumentName: "test-doc",
		Cluster:      "prod-eu-1",
	}

	if sbom.Cluster != "prod-eu-1" {
		t.Errorf("expected Cluster=\"prod-eu-1\", got %q", sbom.Cluster)
	}

	// Verify JSON serialization includes cluster.
	data, err := json.Marshal(sbom)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if m["cluster"] != "prod-eu-1" {
		t.Errorf("JSON cluster field = %v, want \"prod-eu-1\"", m["cluster"])
	}
}

func TestSBOM_ClusterOmitEmpty(t *testing.T) {
	sbom := SBOM{
		IngestedAt:   time.Now(),
		SBOMID:       uuid.New(),
		SourceFile:   "test.spdx.json",
		DocumentName: "test-doc",
		Cluster:      "", // empty = default cluster
	}

	data, err := json.Marshal(sbom)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// With omitempty, empty cluster should not appear in JSON.
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if _, exists := m["cluster"]; exists {
		t.Error("expected cluster to be omitted for empty value")
	}
}

func TestIngestionJob_ClusterPropagation(t *testing.T) {
	job := IngestionJob{
		CreatedAt:  time.Now(),
		JobID:      uuid.New(),
		SourceFile: "s3://bucket/path.spdx.json",
		SHA256Hash: "abc123",
		Status:     JobStatusPending,
		JobType:    JobTypeSBOM,
		Cluster:    "staging-us-east",
	}

	if job.Cluster != "staging-us-east" {
		t.Errorf("expected Cluster=\"staging-us-east\", got %q", job.Cluster)
	}
}

func TestVulnerability_ClusterField(t *testing.T) {
	vuln := Vulnerability{
		DiscoveredAt: time.Now(),
		SBOMID:       uuid.New(),
		VulnID:       "CVE-2024-1234",
		Cluster:      "prod-cluster",
	}

	if vuln.Cluster != "prod-cluster" {
		t.Errorf("expected Cluster=\"prod-cluster\", got %q", vuln.Cluster)
	}
}

func TestLicenseCompliance_ClusterField(t *testing.T) {
	lc := LicenseCompliance{
		CheckedAt: time.Now(),
		SBOMID:    uuid.New(),
		LicenseID: "MIT",
		Category:  "permissive",
		Cluster:   "dev-local",
	}

	if lc.Cluster != "dev-local" {
		t.Errorf("expected Cluster=\"dev-local\", got %q", lc.Cluster)
	}
}

func TestVEXStatement_ClusterField(t *testing.T) {
	stmt := VEXStatement{
		IngestedAt: time.Now(),
		VEXID:      uuid.New(),
		VulnID:     "CVE-2024-5678",
		Status:     VEXStatusNotAffected,
		Cluster:    "fleet-asia",
	}

	if stmt.Cluster != "fleet-asia" {
		t.Errorf("expected Cluster=\"fleet-asia\", got %q", stmt.Cluster)
	}
}

func TestSBOM_WorkloadIdentityFields(t *testing.T) {
	sbom := SBOM{
		IngestedAt:   time.Now(),
		SBOMID:       uuid.New(),
		SourceFile:   "test.spdx.json",
		DocumentName: "test-doc",
		WorkloadKind: "Deployment",
		WorkloadName: "payment-service",
		WorkloadUID:  "1234-5678-uid",
	}

	data, err := json.Marshal(sbom)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if m["workload_kind"] != "Deployment" {
		t.Errorf("JSON workload_kind = %v, want Deployment", m["workload_kind"])
	}
	if m["workload_name"] != "payment-service" {
		t.Errorf("JSON workload_name = %v, want payment-service", m["workload_name"])
	}
	if m["workload_uid"] != "1234-5678-uid" {
		t.Errorf("JSON workload_uid = %v, want 1234-5678-uid", m["workload_uid"])
	}
}

func TestSBOM_WorkloadIdentityOmitEmpty(t *testing.T) {
	sbom := SBOM{
		IngestedAt:   time.Now(),
		SBOMID:       uuid.New(),
		SourceFile:   "test.spdx.json",
		DocumentName: "test-doc",
	}

	data, err := json.Marshal(sbom)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	for _, f := range []string{"workload_kind", "workload_name", "workload_uid"} {
		if _, exists := m[f]; exists {
			t.Errorf("expected %s to be omitted for empty value", f)
		}
	}
}
