package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/seebom-labs/bomhort/backend/internal/ingestpath"
	"github.com/seebom-labs/bomhort/backend/internal/tags"
)

// S3BucketConfig holds the configuration for a single S3 bucket source.
// Note: this is a separate, hand-maintained struct — not a type alias for
// s3.BucketConfig — so any new field added there (like SkipScan below) must
// also be added here and threaded through the manual field-by-field
// conversion in each cmd/*/main.go that builds an s3.BucketConfig from it.
type S3BucketConfig struct {
	Name         string `json:"name"`
	Endpoint     string `json:"endpoint"`
	Region       string `json:"region"`
	AccessKey    string `json:"accessKey"`
	SecretKey    string `json:"secretKey"`
	Prefix       string `json:"prefix"`
	UsePathStyle bool   `json:"usePathStyle"`
	UseSSL       *bool  `json:"useSSL"`
	Cluster      string `json:"cluster"` // Optional: override ClusterName for this bucket
	// Namespace/Project (#138, #57) optionally pin every object in this
	// bucket to one namespace/project, for the common case of a bucket per
	// team. Being explicit configuration, they outrank both the global
	// NAMESPACE/PROJECT defaults and anything derived from the object key.
	Namespace string `json:"namespace,omitempty"`
	Project   string `json:"project,omitempty"`
	// PathLayout overrides INGEST_PATH_LAYOUT for this bucket, for fleets
	// where buckets are organised differently (e.g. one laid out
	// "cluster/namespace/project", another flat).
	PathLayout string `json:"pathLayout,omitempty"`
	// Tags (#357) label every object in this bucket with deployment-neutral
	// grouping labels, e.g. ["sandbox-applications"] for a bucket holding a
	// foundation's sandbox project SBOMs. Unlike Namespace/Project these are
	// additive rather than an override: bucket tags are merged with the
	// global TAGS default, because a bucket saying "these are sandbox apps"
	// does not contradict an instance-wide "these are all CNCF" label.
	Tags []string `json:"tags,omitempty"`
	// SkipScan designates this bucket as the push-model upload target (#135):
	// excluded from the ingestion-watcher's ListObjects scan, but still used
	// for GetObject/PutObject. See s3.BucketConfig.SkipScan for why this
	// matters (ETag-vs-SHA256 dedup mismatch).
	SkipScan bool `json:"skipScan,omitempty"`
}

// Config holds all configuration values, read from environment variables.
type Config struct {
	// ClickHouse connection
	ClickHouseHost     string
	ClickHousePort     int
	ClickHouseDatabase string
	ClickHouseUser     string
	ClickHousePassword string

	// SBOM source directory (local filesystem)
	SBOMDir string

	// S3 bucket sources (multiple buckets supported)
	S3Buckets []S3BucketConfig

	// API Gateway
	APIPort            int
	CORSAllowedOrigins string // Comma-separated allowed origins (default "*" for dev)

	// Worker
	WorkerID        string
	WorkerBatchSize int

	// Feature flags
	SkipOSV           bool   // Skip OSV vulnerability lookups (fast ingestion, licenses only)
	SkipGitHubResolve bool   // Skip GitHub license resolution for unknown licenses
	SkipNPMResolve    bool   // Skip npm registry license resolution for unknown licenses
	SkipNuGetResolve  bool   // Skip NuGet license resolution for unknown licenses
	SBOMLimit         int    // Max number of SBOMs to enqueue (0 = unlimited)
	IgnorePrefix      string // Files with this prefix are skipped during local scan (default "_")
	ExceptionsFile    string // Path to license-exceptions.json
	LicensePolicyFile string // Path to license-policy.json
	GitHubToken       string // GitHub personal access token (optional, increases rate limit)

	// Multi-cluster
	ClusterName string // Cluster identifier for this instance (default "" = unassigned)

	// Ownership dimensions orthogonal to cluster (#138 namespace, #57 project).
	// Instance-wide defaults, used when nothing more specific (per-bucket
	// config, path derivation, upload query param) supplies a value.
	Namespace string // Default namespace (default "" = unassigned)
	Project   string // Default project   (default "" = unassigned)

	// Tags (#357) are instance-wide grouping labels applied to every ingested
	// SBOM, from a comma-separated TAGS env var. They group projects along an
	// axis that has nothing to do with where a workload runs, which is what
	// makes them work on catalogue-style instances that have no cluster.
	// Additive, not an override: per-bucket and per-upload tags are merged on
	// top rather than replacing these.
	Tags []string

	// IngestPathLayout opts into deriving cluster/namespace/project from an
	// object's position in the source, e.g. "cluster/namespace/project" for
	// keys like prod-eu/payments/payment-service/sbom.spdx.json. Empty (the
	// default) disables derivation entirely. Validated at Load() time --
	// see internal/ingestpath.
	IngestPathLayout string

	// API Authentication (opt-in, all empty by default)
	AuthEnabled  bool     // Enable auth middleware (default false)
	ServiceToken string   // Shared secret for upstream proxy/gateway integrations
	APIKeys      []string // Pre-shared API keys for direct API consumers (CI/CD, scripts)

	// Push-model upload (#135)
	MaxUploadSizeMB int // Max accepted body size for POST /api/v1/sboms/upload, in MB (default 50)

	// Tier-2 fidelity capture (#256): where the original SBOM bytes are kept.
	//   OriginalStoreBackend: "auto" (default) | "s3" | "fs" | "none"
	//     auto → "s3" when any S3 bucket is configured, else "fs" when
	//     OriginalStoreFSPath is set, else "none".
	//   OriginalStoreS3Bucket: bucket to write to; must be one of S3Buckets
	//     (default: first non-skipScan bucket, else first bucket).
	//   OriginalStoreS3Prefix: key prefix inside that bucket
	//     (default "_bomhort/originals/" — skipped by the ingestion watcher).
	//   OriginalStoreFSPath: directory for the fs backend (a PVC shared by
	//     parsing-worker and api-gateway).
	OriginalStoreBackend  string
	OriginalStoreS3Bucket string
	OriginalStoreS3Prefix string
	OriginalStoreFSPath   string
}

// Original-store backend identifiers (mirrors internal/docstore constants so
// config does not import docstore).
const (
	OriginalStoreAuto = "auto"
	OriginalStoreS3   = "s3"
	OriginalStoreFS   = "fs"
	OriginalStoreNone = "none"
)

// Load reads configuration from environment variables with sensible defaults.
func Load() (*Config, error) {
	cfg := &Config{
		ClickHouseHost:     getEnv("CLICKHOUSE_HOST", "localhost"),
		ClickHousePort:     getEnvInt("CLICKHOUSE_PORT", 9000),
		ClickHouseDatabase: getEnv("CLICKHOUSE_DATABASE", "bomhort"),
		ClickHouseUser:     getEnv("CLICKHOUSE_USER", "default"),
		ClickHousePassword: getEnv("CLICKHOUSE_PASSWORD", ""),
		SBOMDir:            getEnv("SBOM_DIR", "./sboms"),
		APIPort:            getEnvInt("API_PORT", 8080),
		CORSAllowedOrigins: getEnv("CORS_ALLOWED_ORIGINS", "*"),
		WorkerID:           getEnv("WORKER_ID", ""),
		WorkerBatchSize:    getEnvInt("WORKER_BATCH_SIZE", 10),
		SkipOSV:            getEnvBool("SKIP_OSV", false),
		SkipGitHubResolve:  getEnvBool("SKIP_GITHUB_RESOLVE", false),
		SkipNPMResolve:     getEnvBool("SKIP_NPM_RESOLVE", false),
		SkipNuGetResolve:   getEnvBool("SKIP_NUGET_RESOLVE", false),
		SBOMLimit:          getEnvInt("SBOM_LIMIT", 0),
		IgnorePrefix:       getEnv("SBOM_IGNORE_PREFIX", "_"),
		ExceptionsFile:     getEnv("EXCEPTIONS_FILE", "/data/config/license-exceptions.json"),
		LicensePolicyFile:  getEnv("LICENSE_POLICY_FILE", "/data/config/license-policy.json"),
		GitHubToken:        getEnv("GITHUB_TOKEN", ""),
		ClusterName:        getEnv("CLUSTER_NAME", ""),
		Namespace:          getEnv("NAMESPACE", ""),
		Project:            getEnv("PROJECT", ""),
		Tags:               tags.Parse(getEnv("TAGS", "")),
		IngestPathLayout:   getEnv("INGEST_PATH_LAYOUT", ""),
		AuthEnabled:        getEnvBool("AUTH_ENABLED", false),
		ServiceToken:       getEnv("SERVICE_TOKEN", ""),
		APIKeys:            parseAPIKeys(getEnv("API_KEYS", "")),
		MaxUploadSizeMB:    getEnvInt("MAX_UPLOAD_SIZE_MB", 50),

		OriginalStoreBackend:  strings.ToLower(getEnv("ORIGINAL_STORE_BACKEND", OriginalStoreAuto)),
		OriginalStoreS3Bucket: getEnv("ORIGINAL_STORE_S3_BUCKET", ""),
		OriginalStoreS3Prefix: getEnv("ORIGINAL_STORE_S3_PREFIX", "_bomhort/originals/"),
		OriginalStoreFSPath:   getEnv("ORIGINAL_STORE_FS_PATH", ""),
	}

	switch cfg.OriginalStoreBackend {
	case OriginalStoreAuto, OriginalStoreS3, OriginalStoreFS, OriginalStoreNone:
	default:
		return nil, fmt.Errorf("invalid ORIGINAL_STORE_BACKEND %q (want auto|s3|fs|none)", cfg.OriginalStoreBackend)
	}

	// Fail fast on a malformed layout rather than ingesting a whole fleet with
	// empty namespace/project columns: the DEFAULT '' makes that mistake
	// invisible, and fixing it afterwards requires a full re-ingest.
	if _, err := ingestpath.ParseLayout(cfg.IngestPathLayout); err != nil {
		return nil, fmt.Errorf("invalid INGEST_PATH_LAYOUT: %w", err)
	}

	if cfg.WorkerID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to get hostname for worker ID: %w", err)
		}
		cfg.WorkerID = hostname
	}

	// Parse S3 bucket configurations.
	// Option 1: JSON array in S3_BUCKETS env var.
	if bucketsJSON := getEnv("S3_BUCKETS", ""); bucketsJSON != "" {
		var buckets []S3BucketConfig
		if err := json.Unmarshal([]byte(bucketsJSON), &buckets); err != nil {
			return nil, fmt.Errorf("failed to parse S3_BUCKETS JSON: %w", err)
		}
		cfg.S3Buckets = buckets
	}

	// Option 2: Simple single-bucket env vars (merged with JSON buckets).
	if name := getEnv("S3_BUCKET", ""); name != "" {
		cfg.S3Buckets = append(cfg.S3Buckets, S3BucketConfig{
			Name:         name,
			Endpoint:     getEnv("S3_ENDPOINT", ""), // empty = auto-resolve from region
			Region:       getEnv("S3_REGION", "us-east-1"),
			AccessKey:    getEnv("S3_ACCESS_KEY", ""),
			SecretKey:    getEnv("S3_SECRET_KEY", ""),
			Prefix:       getEnv("S3_PREFIX", ""),
			UsePathStyle: getEnvBool("S3_USE_PATH_STYLE", false),
			UseSSL:       boolPtr(getEnvBool("S3_USE_SSL", true)),
		})
	}

	// Apply shared settings to buckets that don't have their own.
	sharedAccessKey := getEnv("S3_ACCESS_KEY", "")
	sharedSecretKey := getEnv("S3_SECRET_KEY", "")
	sharedEndpoint := getEnv("S3_ENDPOINT", "")
	sharedRegion := getEnv("S3_REGION", "us-east-1")
	sharedPathStyle := getEnvBool("S3_USE_PATH_STYLE", false)
	sharedUseSSL := getEnvBool("S3_USE_SSL", true)
	for i := range cfg.S3Buckets {
		if cfg.S3Buckets[i].AccessKey == "" && sharedAccessKey != "" {
			cfg.S3Buckets[i].AccessKey = sharedAccessKey
		}
		if cfg.S3Buckets[i].SecretKey == "" && sharedSecretKey != "" {
			cfg.S3Buckets[i].SecretKey = sharedSecretKey
		}
		if cfg.S3Buckets[i].Endpoint == "" && sharedEndpoint != "" {
			cfg.S3Buckets[i].Endpoint = sharedEndpoint
		}
		if cfg.S3Buckets[i].Region == "" {
			cfg.S3Buckets[i].Region = sharedRegion
		}
		if !cfg.S3Buckets[i].UsePathStyle && sharedPathStyle {
			cfg.S3Buckets[i].UsePathStyle = true
		}
		if cfg.S3Buckets[i].UseSSL == nil {
			cfg.S3Buckets[i].UseSSL = boolPtr(sharedUseSSL)
		}
	}

	// Deduplicate bucket names.
	cfg.S3Buckets = deduplicateBuckets(cfg.S3Buckets)

	// Per-bucket layouts are validated here for the same fail-fast reason.
	for _, b := range cfg.S3Buckets {
		if _, err := ingestpath.ParseLayout(b.PathLayout); err != nil {
			return nil, fmt.Errorf("invalid pathLayout for bucket %q: %w", b.Name, err)
		}
	}

	return cfg, nil
}

// IngestLayout returns the parsed instance-wide ingestion path layout.
// Load() already rejects a malformed layout, so the parse cannot fail here;
// a disabled layout is returned rather than propagating a second error to
// every call site.
func (c *Config) IngestLayout() ingestpath.Layout {
	l, err := ingestpath.ParseLayout(c.IngestPathLayout)
	if err != nil {
		return ingestpath.Layout{}
	}
	return l
}

// BucketTags returns the grouping labels for a bucket: the instance-wide
// TAGS merged with the bucket's own.
//
// Merged rather than overridden, unlike namespace/project: tags are a
// many-to-many grouping, so a bucket labelling its contents
// "sandbox-applications" adds to — it does not contradict — an instance-wide
// "cncf" label. Dropping the global one here would make the two levels
// mutually exclusive and force operators to repeat the global tag in every
// bucket.
func (c *Config) BucketTags(b S3BucketConfig) []string {
	return tags.Merge(c.Tags, b.Tags)
}

// BucketIngestLayout returns the layout for a bucket: its own pathLayout
// when set, otherwise the instance-wide one.
func (c *Config) BucketIngestLayout(b S3BucketConfig) ingestpath.Layout {
	if strings.TrimSpace(b.PathLayout) == "" {
		return c.IngestLayout()
	}
	l, err := ingestpath.ParseLayout(b.PathLayout)
	if err != nil {
		return ingestpath.Layout{}
	}
	return l
}

// HasS3Sources returns true if any S3 buckets are configured.
func (c *Config) HasS3Sources() bool {
	return len(c.S3Buckets) > 0
}

// ResolvedOriginalStoreBackend resolves "auto" to a concrete backend:
// s3 when any S3 bucket is configured, else fs when a path is set, else none.
func (c *Config) ResolvedOriginalStoreBackend() string {
	if c.OriginalStoreBackend != OriginalStoreAuto {
		return c.OriginalStoreBackend
	}
	switch {
	case c.HasS3Sources():
		return OriginalStoreS3
	case c.OriginalStoreFSPath != "":
		return OriginalStoreFS
	default:
		return OriginalStoreNone
	}
}

// OriginalStoreBucket returns the S3 bucket originals are written to:
// the explicit ORIGINAL_STORE_S3_BUCKET, else the first bucket that is not a
// skipScan (push-upload) bucket, else the first configured bucket. Returns ""
// when no S3 bucket is configured.
func (c *Config) OriginalStoreBucket() string {
	if c.OriginalStoreS3Bucket != "" {
		return c.OriginalStoreS3Bucket
	}
	for _, b := range c.S3Buckets {
		if !b.SkipScan {
			return b.Name
		}
	}
	if len(c.S3Buckets) > 0 {
		return c.S3Buckets[0].Name
	}
	return ""
}

// ClickHouseDSN returns the ClickHouse connection string.
func (c *Config) ClickHouseDSN() string {
	return fmt.Sprintf("clickhouse://%s:%s@%s:%d/%s",
		c.ClickHouseUser, c.ClickHousePassword,
		c.ClickHouseHost, c.ClickHousePort, c.ClickHouseDatabase)
}

// deduplicateBuckets removes duplicate bucket entries by name.
// Later entries override earlier ones.
func deduplicateBuckets(buckets []S3BucketConfig) []S3BucketConfig {
	seen := make(map[string]int, len(buckets))
	var result []S3BucketConfig
	for _, b := range buckets {
		key := b.Name + "|" + b.Prefix
		if idx, ok := seen[key]; ok {
			result[idx] = b // override
		} else {
			seen[key] = len(result)
			result = append(result, b)
		}
	}
	return result
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	val, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return i
}

func getEnvBool(key string, fallback bool) bool {
	val, ok := os.LookupEnv(key)
	if !ok || val == "" {
		return fallback
	}
	return val == "1" || val == "true" || val == "yes"
}

func boolPtr(v bool) *bool { return &v }

// parseAPIKeys splits a comma-separated list of API keys, trimming whitespace
// and filtering out empty entries.
func parseAPIKeys(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	keys := make([]string, 0, len(parts))
	for _, p := range parts {
		k := strings.TrimSpace(p)
		if k != "" {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	return keys
}

// S3BucketNames returns a comma-separated list of configured bucket names (for logging).
func (c *Config) S3BucketNames() string {
	names := make([]string, len(c.S3Buckets))
	for i, b := range c.S3Buckets {
		if b.Prefix != "" {
			names[i] = b.Name + "/" + b.Prefix
		} else {
			names[i] = b.Name
		}
	}
	return strings.Join(names, ", ")
}
