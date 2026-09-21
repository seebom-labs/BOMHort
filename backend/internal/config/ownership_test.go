package config

import (
	"os"
	"testing"
)

// setEnvs sets the given env vars for the duration of the test and clears
// everything else this package reads for ownership, so a stray value from the
// developer's shell cannot make a test pass or fail spuriously.
func setEnvs(t *testing.T, kv map[string]string) {
	t.Helper()
	for _, k := range []string{"CLUSTER_NAME", "NAMESPACE", "PROJECT", "INGEST_PATH_LAYOUT", "TAGS", "S3_BUCKETS", "S3_BUCKET"} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func TestLoad_OwnershipDefaults(t *testing.T) {
	setEnvs(t, nil)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.Namespace != "" {
		t.Errorf("Namespace = %q, want empty by default", cfg.Namespace)
	}
	if cfg.Project != "" {
		t.Errorf("Project = %q, want empty by default", cfg.Project)
	}
	if cfg.IngestPathLayout != "" {
		t.Errorf("IngestPathLayout = %q, want empty by default", cfg.IngestPathLayout)
	}
	if cfg.IngestLayout().Enabled() {
		t.Error("path derivation must be off unless explicitly configured")
	}
}

func TestLoad_OwnershipFromEnv(t *testing.T) {
	setEnvs(t, map[string]string{
		"NAMESPACE": "payments",
		"PROJECT":   "payment-service",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.Namespace != "payments" {
		t.Errorf("Namespace = %q, want payments", cfg.Namespace)
	}
	if cfg.Project != "payment-service" {
		t.Errorf("Project = %q, want payment-service", cfg.Project)
	}
}

func TestLoad_IngestPathLayout(t *testing.T) {
	setEnvs(t, map[string]string{"INGEST_PATH_LAYOUT": "cluster/namespace/project"})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	layout := cfg.IngestLayout()
	if !layout.Enabled() {
		t.Fatal("layout should be enabled")
	}
	attrs := layout.Derive("prod-eu/payments/payment-service/sbom.spdx.json")
	if attrs.Cluster != "prod-eu" || attrs.Namespace != "payments" || attrs.Project != "payment-service" {
		t.Errorf("Derive() = %+v, want prod-eu/payments/payment-service", attrs)
	}
}

// A typo in the layout must fail at startup. Accepting it would ingest the
// whole fleet with empty namespace/project columns, which DEFAULT ” makes
// indistinguishable from "genuinely unassigned" and only a re-ingest fixes.
func TestLoad_InvalidIngestPathLayoutFails(t *testing.T) {
	setEnvs(t, map[string]string{"INGEST_PATH_LAYOUT": "cluster/tenant"})

	if _, err := Load(); err == nil {
		t.Fatal("Load() should reject an unknown layout segment")
	}
}

func TestLoad_InvalidBucketPathLayoutFails(t *testing.T) {
	setEnvs(t, map[string]string{
		"S3_BUCKETS": `[{"name":"sboms","pathLayout":"cluster/bogus"}]`,
	})

	if _, err := Load(); err == nil {
		t.Fatal("Load() should reject an unknown per-bucket layout segment")
	}
}

func TestLoad_BucketOwnershipOverrides(t *testing.T) {
	setEnvs(t, map[string]string{
		"CLUSTER_NAME": "global-cluster",
		"NAMESPACE":    "global-ns",
		"PROJECT":      "global-proj",
		"S3_BUCKETS": `[
			{"name":"team-a","cluster":"prod-eu","namespace":"payments","project":"payment-service"},
			{"name":"team-b"}
		]`,
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if len(cfg.S3Buckets) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(cfg.S3Buckets))
	}

	a := cfg.S3Buckets[0]
	if a.Cluster != "prod-eu" || a.Namespace != "payments" || a.Project != "payment-service" {
		t.Errorf("bucket team-a = (%q, %q, %q), want the per-bucket values", a.Cluster, a.Namespace, a.Project)
	}

	// team-b sets nothing; the fields stay empty here and the *watcher* is
	// what falls back to the instance-wide defaults, so assert that the
	// config layer does not silently pre-fill them.
	b := cfg.S3Buckets[1]
	if b.Cluster != "" || b.Namespace != "" || b.Project != "" {
		t.Errorf("bucket team-b = (%q, %q, %q), want all empty", b.Cluster, b.Namespace, b.Project)
	}
}

func TestBucketIngestLayout(t *testing.T) {
	setEnvs(t, map[string]string{
		"INGEST_PATH_LAYOUT": "cluster/namespace",
		"S3_BUCKETS": `[
			{"name":"nested","pathLayout":"cluster/namespace/project"},
			{"name":"inherits"}
		]`,
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	nested := cfg.BucketIngestLayout(cfg.S3Buckets[0])
	if got := nested.String(); got != "cluster/namespace/project" {
		t.Errorf("per-bucket layout = %q, want it to override the global one", got)
	}

	inherits := cfg.BucketIngestLayout(cfg.S3Buckets[1])
	if got := inherits.String(); got != "cluster/namespace" {
		t.Errorf("bucket without pathLayout = %q, want the instance-wide layout", got)
	}
}

func TestBucketIngestLayout_DisabledGlobally(t *testing.T) {
	setEnvs(t, map[string]string{
		"S3_BUCKETS": `[{"name":"flat"}]`,
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.BucketIngestLayout(cfg.S3Buckets[0]).Enabled() {
		t.Error("a bucket must not derive anything when no layout is configured at all")
	}
}

// TAGS is a comma-separated string in the environment because a ConfigMap
// value is a scalar; it must arrive as a normalised list.
func TestLoad_TagsFromEnv(t *testing.T) {
	setEnvs(t, map[string]string{"TAGS": " CNCF ,sandbox-applications, "})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	want := []string{"cncf", "sandbox-applications"}
	if len(cfg.Tags) != len(want) {
		t.Fatalf("Tags = %v, want %v", cfg.Tags, want)
	}
	for i := range want {
		if cfg.Tags[i] != want[i] {
			t.Errorf("Tags = %v, want %v", cfg.Tags, want)
			break
		}
	}
}

// Tags merge across levels instead of overriding, which is what separates
// them from namespace/project. An operator who sets an instance-wide "cncf"
// and a per-bucket "sandbox-applications" means both -- if the bucket value
// replaced the global one, every bucket would have to repeat it.
func TestBucketTags_MergesGlobalAndBucket(t *testing.T) {
	setEnvs(t, map[string]string{
		"TAGS":       "cncf",
		"S3_BUCKETS": `[{"name":"sandbox","tags":["sandbox-applications"]},{"name":"plain"}]`,
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	got := cfg.BucketTags(cfg.S3Buckets[0])
	want := []string{"cncf", "sandbox-applications"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("BucketTags(sandbox) = %v, want %v", got, want)
	}
	// A bucket that names no tags still inherits the instance-wide ones.
	if got := cfg.BucketTags(cfg.S3Buckets[1]); len(got) != 1 || got[0] != "cncf" {
		t.Errorf("BucketTags(plain) = %v, want [cncf]", got)
	}
}

// An untagged instance must produce no tags at all, so untagged SBOMs store a
// clean empty array rather than a list holding one empty string.
func TestBucketTags_NoneConfigured(t *testing.T) {
	setEnvs(t, map[string]string{"S3_BUCKETS": `[{"name":"plain"}]`})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if got := cfg.BucketTags(cfg.S3Buckets[0]); len(got) != 0 {
		t.Errorf("BucketTags() = %v, want empty", got)
	}
}
