package s3

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// BucketConfig holds the configuration for a single S3 bucket source.
type BucketConfig struct {
	Name         string `json:"name"`         // Bucket name (e.g. "cncf-subproject-sboms")
	Endpoint     string `json:"endpoint"`     // S3 endpoint (e.g. "s3.amazonaws.com")
	Region       string `json:"region"`       // AWS region (e.g. "us-east-1")
	AccessKey    string `json:"accessKey"`    // Access key ID (optional for public buckets)
	SecretKey    string `json:"secretKey"`    // Secret access key (optional for public buckets)
	Prefix       string `json:"prefix"`       // Key prefix filter (e.g. "k3s-io/")
	UsePathStyle bool   `json:"usePathStyle"` // Use path-style URLs (required for MinIO)
	UseSSL       *bool  `json:"useSSL"`       // Use HTTPS — nil defaults to true, set false for local MinIO
	// SkipScan excludes this bucket from ListObjects's periodic scan (#135).
	// Set on the dedicated push-upload target bucket so objects written by
	// POST /api/v1/sboms/upload are never rediscovered by the ingestion
	// watcher — which dedups on S3 ETag, not the SHA256 hash the upload
	// endpoint already used to enqueue the job, so a rescan would create a
	// duplicate job for the same content. The bucket is still registered
	// normally (GetObject/PutObject work), it's just excluded from listing.
	SkipScan bool `json:"skipScan,omitempty"`
}

// ObjectInfo holds metadata about a discovered S3 object.
type ObjectInfo struct {
	Bucket   string // Bucket name
	Key      string // Full object key
	ETag     string // S3 ETag (used for deduplication, no download needed)
	FileType string // "sbom" or "vex"
	Size     int64  // Object size in bytes
}

// URI returns the canonical s3:// URI for this object.
func (o ObjectInfo) URI() string {
	return "s3://" + o.Bucket + "/" + o.Key
}

// Client wraps the MinIO S3 client for listing and fetching objects.
type Client struct {
	configs []BucketConfig
	clients map[string]*minio.Client // keyed by bucket name
}

// NewClient creates an S3 client for the given bucket configurations.
// It validates connectivity to each bucket at creation time.
func NewClient(configs []BucketConfig) (*Client, error) {
	c := &Client{
		configs: configs,
		clients: make(map[string]*minio.Client, len(configs)),
	}

	for _, cfg := range configs {
		mc, err := newMinioClient(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create S3 client for bucket %q: %w", cfg.Name, err)
		}
		c.clients[cfg.Name] = mc
	}

	return c, nil
}

// newMinioClient creates a minio.Client from a BucketConfig.
func newMinioClient(cfg BucketConfig) (*minio.Client, error) {
	opts := &minio.Options{
		Region: cfg.Region,
	}

	if cfg.AccessKey != "" {
		opts.Creds = credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, "")
	} else {
		// Anonymous access for public buckets — must use SignatureAnonymous
		// (not empty StaticV4, which still tries to sign requests).
		opts.Creds = credentials.NewStatic("", "", "", credentials.SignatureAnonymous)
	}

	// Determine the endpoint.
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		// No explicit endpoint — default to AWS regional endpoint.
		region := cfg.Region
		if region == "" {
			region = "us-east-1"
		}
		endpoint = "s3." + region + ".amazonaws.com"
	}

	// Detect SSL from the URL scheme (if present), then strip the scheme
	// because minio-go uses the Secure flag instead.
	if strings.HasPrefix(endpoint, "https://") {
		opts.Secure = true
		endpoint = strings.TrimPrefix(endpoint, "https://")
	} else if strings.HasPrefix(endpoint, "http://") {
		opts.Secure = false
		endpoint = strings.TrimPrefix(endpoint, "http://")
	} else if cfg.UseSSL != nil {
		// Explicit useSSL value in JSON config.
		opts.Secure = *cfg.UseSSL
	} else {
		// No URL scheme and useSSL not specified — default to HTTPS.
		opts.Secure = true
	}

	// Strip trailing slashes.
	endpoint = strings.TrimRight(endpoint, "/")

	if cfg.UsePathStyle {
		opts.BucketLookup = minio.BucketLookupPath
	}

	log.Printf("S3: creating client for bucket %q (endpoint: %s, region: %s, ssl: %v, path-style: %v, auth: %v)",
		cfg.Name, endpoint, cfg.Region, opts.Secure, cfg.UsePathStyle, cfg.AccessKey != "")

	return minio.New(endpoint, opts)
}

// CheckBucket verifies that a bucket is reachable by listing a single object.
// This works across all S3-compatible stores (AWS, OCI, MinIO, GCS) where
// HeadBucket may require different permissions than ListObjects.
func (c *Client) CheckBucket(ctx context.Context, bucketName, prefix string) error {
	mc, ok := c.clients[bucketName]
	if !ok {
		return fmt.Errorf("no client configured for bucket %q", bucketName)
	}

	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Attempt to list a single object as a connectivity probe.
	objCh := mc.ListObjects(checkCtx, bucketName, minio.ListObjectsOptions{
		Prefix:    prefix,
		MaxKeys:   1,
		Recursive: false,
	})

	for obj := range objCh {
		if obj.Err != nil {
			return fmt.Errorf("bucket %q not accessible: %w", bucketName, obj.Err)
		}
		// Got at least one result — bucket is reachable and readable.
		return nil
	}

	// Channel closed without error and without objects — bucket exists but might be empty
	// (or the prefix matches nothing). This is not an error.
	return nil
}

// ListObjects streams object metadata from all configured buckets.
// It filters for SBOM/VEX files by extension and uses S3 ETags for
// deduplication (no object downloads during listing). The channel is
// closed when all objects have been listed or an unrecoverable error occurs.
func (c *Client) ListObjects(ctx context.Context) <-chan ObjectResult {
	ch := make(chan ObjectResult, 100)

	go func() {
		defer close(ch)

		for _, cfg := range c.configs {
			if cfg.SkipScan {
				log.Printf("S3: skipping bucket %q (skipScan=true, reserved for push-model uploads)", cfg.Name)
				continue
			}

			mc, ok := c.clients[cfg.Name]
			if !ok {
				ch <- ObjectResult{Err: fmt.Errorf("no client for bucket %q", cfg.Name)}
				continue
			}

			// Pre-flight: verify bucket is reachable before attempting to list.
			log.Printf("S3: checking connectivity to bucket %q ...", cfg.Name)
			if err := c.CheckBucket(ctx, cfg.Name, cfg.Prefix); err != nil {
				ch <- ObjectResult{Err: err}
				continue
			}
			log.Printf("S3: bucket %q is reachable, starting object listing (prefix: %q)", cfg.Name, cfg.Prefix)

			count := 0
			skipped := 0
			lastLog := time.Now()

			objCh := mc.ListObjects(ctx, cfg.Name, minio.ListObjectsOptions{
				Prefix:    cfg.Prefix,
				Recursive: true,
			})

			for obj := range objCh {
				if obj.Err != nil {
					ch <- ObjectResult{Err: fmt.Errorf("S3 list error in bucket %q: %w", cfg.Name, obj.Err)}
					continue
				}

				// Classify by file extension.
				fileType := ClassifyKey(obj.Key)
				if fileType == "" {
					skipped++
					continue // Not an SBOM or VEX file
				}

				// Use the S3 ETag as dedup hash (available from listing metadata,
				// no object download needed). ETags change when content changes,
				// so dedup remains correct.
				etag := sanitizeETag(obj.ETag)

				ch <- ObjectResult{
					Object: ObjectInfo{
						Bucket:   cfg.Name,
						Key:      obj.Key,
						ETag:     etag,
						FileType: fileType,
						Size:     obj.Size,
					},
				}
				count++

				// Progress logging every 10 seconds for large buckets.
				if time.Since(lastLog) > 10*time.Second {
					log.Printf("S3: bucket %q progress: %d matching objects found (%d skipped)...", cfg.Name, count, skipped)
					lastLog = time.Now()
				}
			}

			log.Printf("S3: finished listing bucket %q (%d matching objects, %d skipped)", cfg.Name, count, skipped)
		}
	}()

	return ch
}

// ObjectResult wraps either a discovered object or an error from listing.
type ObjectResult struct {
	Object ObjectInfo
	Err    error
}

// GetObject returns the content of an S3 object as a ReadCloser.
// The caller must close the returned reader.
func (c *Client) GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	mc, ok := c.clients[bucket]
	if !ok {
		return nil, fmt.Errorf("no S3 client configured for bucket %q", bucket)
	}

	obj, err := mc.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get S3 object %s/%s: %w", bucket, key, err)
	}

	return obj, nil
}

// PutObject uploads content to an S3 object. Used by the push-model upload
// endpoint (#135) to route pushed content to a dedicated skipScan bucket
// instead of the local filesystem.
func (c *Client) PutObject(ctx context.Context, bucket, key string, body io.Reader, size int64) error {
	mc, ok := c.clients[bucket]
	if !ok {
		return fmt.Errorf("no S3 client configured for bucket %q", bucket)
	}

	if _, err := mc.PutObject(ctx, bucket, key, body, size, minio.PutObjectOptions{}); err != nil {
		return fmt.Errorf("failed to put S3 object %s/%s: %w", bucket, key, err)
	}

	return nil
}

// RemoveObject deletes an S3 object. Used for best-effort cleanup when a
// push-model upload (#135) is staged to S3 but the subsequent ingestion-job
// enqueue fails, mirroring the local-filesystem cleanup path.
func (c *Client) RemoveObject(ctx context.Context, bucket, key string) error {
	mc, ok := c.clients[bucket]
	if !ok {
		return fmt.Errorf("no S3 client configured for bucket %q", bucket)
	}

	if err := mc.RemoveObject(ctx, bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("failed to remove S3 object %s/%s: %w", bucket, key, err)
	}

	return nil
}

// sanitizeETag strips surrounding quotes from S3 ETags.
// S3 returns ETags like `"d41d8cd98f00b204e9800998ecf8427e"` or `"hash-partcount"` for multipart.
func sanitizeETag(etag string) string {
	return strings.Trim(etag, `"`)
}

// ClassifyKey determines the file type from an S3 object key.
// Returns "sbom", "vex", or "" (unknown/skip).
func ClassifyKey(key string) string {
	lower := strings.ToLower(key)
	switch {
	case strings.HasSuffix(lower, ".openvex.json"), strings.HasSuffix(lower, ".vex.json"):
		return "vex"
	case strings.HasSuffix(lower, ".spdx.json"), strings.HasSuffix(lower, "_spdx.json"):
		return "sbom"
	default:
		return ""
	}
}

// ParseURI parses an "s3://bucket/key" URI into bucket name and object key.
func ParseURI(uri string) (bucket, key string, err error) {
	if !strings.HasPrefix(uri, "s3://") {
		return "", "", fmt.Errorf("not an S3 URI: %q", uri)
	}
	rest := strings.TrimPrefix(uri, "s3://")
	idx := strings.IndexByte(rest, '/')
	if idx < 0 {
		return "", "", fmt.Errorf("invalid S3 URI (no key): %q", uri)
	}
	return rest[:idx], rest[idx+1:], nil
}
