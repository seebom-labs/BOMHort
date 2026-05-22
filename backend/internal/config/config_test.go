package config

import (
	"os"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	// Clear any env vars that might interfere.
	for _, key := range []string{
		"CLICKHOUSE_HOST", "CLICKHOUSE_PORT", "CLICKHOUSE_DATABASE",
		"SBOM_DIR", "API_PORT", "WORKER_BATCH_SIZE", "SKIP_OSV", "SBOM_LIMIT",
		"S3_BUCKETS", "S3_BUCKET",
	} {
		os.Unsetenv(key)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.ClickHouseHost != "localhost" {
		t.Errorf("expected default host localhost, got %s", cfg.ClickHouseHost)
	}
	if cfg.ClickHousePort != 9000 {
		t.Errorf("expected default port 9000, got %d", cfg.ClickHousePort)
	}
	if cfg.ClickHouseDatabase != "seebom" {
		t.Errorf("expected default database seebom, got %s", cfg.ClickHouseDatabase)
	}
	if cfg.SBOMDir != "./sboms" {
		t.Errorf("expected default SBOM dir ./sboms, got %s", cfg.SBOMDir)
	}
	if cfg.APIPort != 8080 {
		t.Errorf("expected default API port 8080, got %d", cfg.APIPort)
	}
	if cfg.SkipOSV != false {
		t.Error("expected default SkipOSV=false")
	}
	if cfg.SBOMLimit != 0 {
		t.Errorf("expected default SBOMLimit=0, got %d", cfg.SBOMLimit)
	}
	if cfg.WorkerID == "" {
		t.Error("expected non-empty WorkerID (should be hostname)")
	}
	if len(cfg.S3Buckets) != 0 {
		t.Errorf("expected no S3 buckets by default, got %d", len(cfg.S3Buckets))
	}
	if cfg.HasS3Sources() {
		t.Error("expected HasS3Sources()=false by default")
	}
}

func TestLoad_CustomEnv(t *testing.T) {
	t.Setenv("CLICKHOUSE_HOST", "ch-prod")
	t.Setenv("CLICKHOUSE_PORT", "9440")
	t.Setenv("CLICKHOUSE_DATABASE", "mydb")
	t.Setenv("SBOM_DIR", "/data/sboms")
	t.Setenv("API_PORT", "9090")
	t.Setenv("WORKER_BATCH_SIZE", "100")
	t.Setenv("SKIP_OSV", "true")
	t.Setenv("SBOM_LIMIT", "500")
	t.Setenv("WORKER_ID", "test-worker-1")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.ClickHouseHost != "ch-prod" {
		t.Errorf("expected ch-prod, got %s", cfg.ClickHouseHost)
	}
	if cfg.ClickHousePort != 9440 {
		t.Errorf("expected 9440, got %d", cfg.ClickHousePort)
	}
	if cfg.ClickHouseDatabase != "mydb" {
		t.Errorf("expected mydb, got %s", cfg.ClickHouseDatabase)
	}
	if cfg.SBOMDir != "/data/sboms" {
		t.Errorf("expected /data/sboms, got %s", cfg.SBOMDir)
	}
	if cfg.APIPort != 9090 {
		t.Errorf("expected 9090, got %d", cfg.APIPort)
	}
	if cfg.WorkerBatchSize != 100 {
		t.Errorf("expected 100, got %d", cfg.WorkerBatchSize)
	}
	if cfg.SkipOSV != true {
		t.Error("expected SkipOSV=true")
	}
	if cfg.SBOMLimit != 500 {
		t.Errorf("expected 500, got %d", cfg.SBOMLimit)
	}
	if cfg.WorkerID != "test-worker-1" {
		t.Errorf("expected test-worker-1, got %s", cfg.WorkerID)
	}
}

func TestLoad_S3BucketsJSON(t *testing.T) {
	t.Setenv("S3_BUCKETS", `[{"name":"cncf-subproject-sboms","endpoint":"https://s3.amazonaws.com","region":"us-east-1","prefix":"k3s-io/"},{"name":"cncf-project-sboms","region":"eu-west-1","useSSL":true}]`)
	// Clear single-bucket env to avoid interference.
	os.Unsetenv("S3_BUCKET")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if len(cfg.S3Buckets) != 2 {
		t.Fatalf("expected 2 S3 buckets, got %d", len(cfg.S3Buckets))
	}
	if !cfg.HasS3Sources() {
		t.Error("expected HasS3Sources()=true")
	}

	b0 := cfg.S3Buckets[0]
	if b0.Name != "cncf-subproject-sboms" {
		t.Errorf("bucket[0].Name = %q, want %q", b0.Name, "cncf-subproject-sboms")
	}
	if b0.Prefix != "k3s-io/" {
		t.Errorf("bucket[0].Prefix = %q, want %q", b0.Prefix, "k3s-io/")
	}
	if b0.Region != "us-east-1" {
		t.Errorf("bucket[0].Region = %q, want %q", b0.Region, "us-east-1")
	}

	b1 := cfg.S3Buckets[1]
	if b1.Name != "cncf-project-sboms" {
		t.Errorf("bucket[1].Name = %q, want %q", b1.Name, "cncf-project-sboms")
	}
	if b1.Region != "eu-west-1" {
		t.Errorf("bucket[1].Region = %q, want %q", b1.Region, "eu-west-1")
	}
	// Endpoint should be empty (auto-resolved from region at client creation time).
	if b1.Endpoint != "" {
		t.Errorf("bucket[1].Endpoint = %q, want empty (auto-resolve from region)", b1.Endpoint)
	}
}

func TestLoad_S3SingleBucket(t *testing.T) {
	os.Unsetenv("S3_BUCKETS")
	t.Setenv("S3_BUCKET", "my-sbom-bucket")
	t.Setenv("S3_ENDPOINT", "minio.local:9000")
	t.Setenv("S3_REGION", "us-west-2")
	t.Setenv("S3_PREFIX", "sboms/")
	t.Setenv("S3_USE_PATH_STYLE", "true")
	t.Setenv("S3_USE_SSL", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if len(cfg.S3Buckets) != 1 {
		t.Fatalf("expected 1 S3 bucket, got %d", len(cfg.S3Buckets))
	}

	b := cfg.S3Buckets[0]
	if b.Name != "my-sbom-bucket" {
		t.Errorf("Name = %q, want %q", b.Name, "my-sbom-bucket")
	}
	if b.Endpoint != "minio.local:9000" {
		t.Errorf("Endpoint = %q, want %q", b.Endpoint, "minio.local:9000")
	}
	if b.Region != "us-west-2" {
		t.Errorf("Region = %q, want %q", b.Region, "us-west-2")
	}
	if b.Prefix != "sboms/" {
		t.Errorf("Prefix = %q, want %q", b.Prefix, "sboms/")
	}
	if !b.UsePathStyle {
		t.Error("expected UsePathStyle=true")
	}
}

func TestLoad_S3SharedCredentials(t *testing.T) {
	t.Setenv("S3_BUCKETS", `[{"name":"bucket-a"},{"name":"bucket-b","accessKey":"own-key","secretKey":"own-secret"}]`)
	t.Setenv("S3_ACCESS_KEY", "shared-key")
	t.Setenv("S3_SECRET_KEY", "shared-secret")
	os.Unsetenv("S3_BUCKET")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if len(cfg.S3Buckets) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(cfg.S3Buckets))
	}

	// bucket-a should inherit shared credentials.
	if cfg.S3Buckets[0].AccessKey != "shared-key" {
		t.Errorf("bucket-a.AccessKey = %q, want shared-key", cfg.S3Buckets[0].AccessKey)
	}
	// bucket-b should keep its own credentials.
	if cfg.S3Buckets[1].AccessKey != "own-key" {
		t.Errorf("bucket-b.AccessKey = %q, want own-key", cfg.S3Buckets[1].AccessKey)
	}
}

func TestLoad_S3InvalidJSON(t *testing.T) {
	t.Setenv("S3_BUCKETS", `not-valid-json`)
	os.Unsetenv("S3_BUCKET")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid S3_BUCKETS JSON")
	}
}

func TestS3BucketNames(t *testing.T) {
	cfg := &Config{
		S3Buckets: []S3BucketConfig{
			{Name: "bucket-a", Prefix: "v1/"},
			{Name: "bucket-b"},
		},
	}
	got := cfg.S3BucketNames()
	if got != "bucket-a/v1/, bucket-b" {
		t.Errorf("S3BucketNames() = %q, want %q", got, "bucket-a/v1/, bucket-b")
	}
}

func TestLoad_ClusterName_Default(t *testing.T) {
	os.Unsetenv("CLUSTER_NAME")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.ClusterName != "" {
		t.Errorf("expected default ClusterName=\"\", got %q", cfg.ClusterName)
	}
}

func TestLoad_ClusterName_Custom(t *testing.T) {
	t.Setenv("CLUSTER_NAME", "production-eu-west-1")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.ClusterName != "production-eu-west-1" {
		t.Errorf("expected ClusterName=\"production-eu-west-1\", got %q", cfg.ClusterName)
	}
}

func TestLoad_S3BucketClusterOverride(t *testing.T) {
	t.Setenv("S3_BUCKETS", `[{"name":"prod-bucket","cluster":"prod-eu"},{"name":"staging-bucket","cluster":"staging"},{"name":"default-bucket"}]`)
	t.Setenv("CLUSTER_NAME", "global-fallback")
	os.Unsetenv("S3_BUCKET")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if len(cfg.S3Buckets) != 3 {
		t.Fatalf("expected 3 buckets, got %d", len(cfg.S3Buckets))
	}

	// Bucket with explicit cluster.
	if cfg.S3Buckets[0].Cluster != "prod-eu" {
		t.Errorf("bucket[0].Cluster = %q, want \"prod-eu\"", cfg.S3Buckets[0].Cluster)
	}
	if cfg.S3Buckets[1].Cluster != "staging" {
		t.Errorf("bucket[1].Cluster = %q, want \"staging\"", cfg.S3Buckets[1].Cluster)
	}
	// Bucket without cluster — stays empty (watcher resolves to ClusterName at runtime).
	if cfg.S3Buckets[2].Cluster != "" {
		t.Errorf("bucket[2].Cluster = %q, want \"\" (empty, fallback to ClusterName)", cfg.S3Buckets[2].Cluster)
	}

	// Global ClusterName is the fallback.
	if cfg.ClusterName != "global-fallback" {
		t.Errorf("ClusterName = %q, want \"global-fallback\"", cfg.ClusterName)
	}
}
