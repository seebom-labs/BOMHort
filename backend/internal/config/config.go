package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// S3BucketConfig holds the configuration for a single S3 bucket source.
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
	SBOMLimit         int    // Max number of SBOMs to enqueue (0 = unlimited)
	ExceptionsFile    string // Path to license-exceptions.json
	LicensePolicyFile string // Path to license-policy.json
	GitHubToken       string // GitHub personal access token (optional, increases rate limit)

	// Multi-cluster
	ClusterName string // Cluster identifier for this instance (default "" = unassigned)
}

// Load reads configuration from environment variables with sensible defaults.
func Load() (*Config, error) {
	cfg := &Config{
		ClickHouseHost:     getEnv("CLICKHOUSE_HOST", "localhost"),
		ClickHousePort:     getEnvInt("CLICKHOUSE_PORT", 9000),
		ClickHouseDatabase: getEnv("CLICKHOUSE_DATABASE", "seebom"),
		ClickHouseUser:     getEnv("CLICKHOUSE_USER", "default"),
		ClickHousePassword: getEnv("CLICKHOUSE_PASSWORD", ""),
		SBOMDir:            getEnv("SBOM_DIR", "./sboms"),
		APIPort:            getEnvInt("API_PORT", 8080),
		CORSAllowedOrigins: getEnv("CORS_ALLOWED_ORIGINS", "*"),
		WorkerID:           getEnv("WORKER_ID", ""),
		WorkerBatchSize:    getEnvInt("WORKER_BATCH_SIZE", 10),
		SkipOSV:            getEnvBool("SKIP_OSV", false),
		SkipGitHubResolve:  getEnvBool("SKIP_GITHUB_RESOLVE", false),
		SBOMLimit:          getEnvInt("SBOM_LIMIT", 0),
		ExceptionsFile:     getEnv("EXCEPTIONS_FILE", "/data/config/license-exceptions.json"),
		LicensePolicyFile:  getEnv("LICENSE_POLICY_FILE", "/data/config/license-policy.json"),
		GitHubToken:        getEnv("GITHUB_TOKEN", ""),
		ClusterName:        getEnv("CLUSTER_NAME", ""),
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

	// Apply shared credentials to buckets that don't have their own.
	sharedAccessKey := getEnv("S3_ACCESS_KEY", "")
	sharedSecretKey := getEnv("S3_SECRET_KEY", "")
	for i := range cfg.S3Buckets {
		if cfg.S3Buckets[i].AccessKey == "" && sharedAccessKey != "" {
			cfg.S3Buckets[i].AccessKey = sharedAccessKey
		}
		if cfg.S3Buckets[i].SecretKey == "" && sharedSecretKey != "" {
			cfg.S3Buckets[i].SecretKey = sharedSecretKey
		}
		// Default region.
		if cfg.S3Buckets[i].Region == "" {
			cfg.S3Buckets[i].Region = "us-east-1"
		}
		// Endpoint is resolved at client creation time from region (not here),
		// so we leave it empty to signal "use regional default".
	}

	// Deduplicate bucket names.
	cfg.S3Buckets = deduplicateBuckets(cfg.S3Buckets)

	return cfg, nil
}

// HasS3Sources returns true if any S3 buckets are configured.
func (c *Config) HasS3Sources() bool {
	return len(c.S3Buckets) > 0
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
