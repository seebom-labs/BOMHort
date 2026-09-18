package docstore

import (
	"fmt"

	"github.com/seebom-labs/bomhort/backend/internal/config"
	s3client "github.com/seebom-labs/bomhort/backend/internal/s3"
)

// FromConfig builds the Store selected by ORIGINAL_STORE_* settings.
//
// It returns (nil, nil) when the resolved backend is "none", so callers can
// treat a nil Store as "fidelity capture disabled". s3c may be nil when the
// resolved backend is not s3.
//
// Writes go to the resolved backend. Reads additionally resolve references
// belonging to the *other* backend when that one is configured too, because a
// stored reference records where the bytes actually are — see multiStore for
// why relying on the local backend alone silently broke every download.
func FromConfig(cfg *config.Config, s3c *s3client.Client) (Store, error) {
	backend := cfg.ResolvedOriginalStoreBackend()
	if backend == config.OriginalStoreNone {
		return nil, nil
	}

	primary, err := storeFor(cfg, s3c, backend)
	if err != nil {
		return nil, err
	}

	// Best effort: a fallback that cannot be built is simply absent, and a
	// reference for it then fails with ErrBackendMismatch as before. A broken
	// fallback must never keep the configured primary from starting.
	var fallback Store
	switch backend {
	case config.OriginalStoreS3:
		if cfg.OriginalStoreFSPath != "" {
			fallback, _ = storeFor(cfg, s3c, config.OriginalStoreFS)
		}
	case config.OriginalStoreFS:
		if s3c != nil && cfg.OriginalStoreBucket() != "" {
			fallback, _ = storeFor(cfg, s3c, config.OriginalStoreS3)
		}
	}

	return newMultiStore(primary, fallback), nil
}

// storeFor constructs one concrete backend.
func storeFor(cfg *config.Config, s3c *s3client.Client, backend string) (Store, error) {
	switch backend {
	case config.OriginalStoreS3:
		if s3c == nil {
			return nil, fmt.Errorf("docstore: backend s3 selected but no S3 client is available")
		}
		bucket := cfg.OriginalStoreBucket()
		if bucket == "" {
			return nil, fmt.Errorf("docstore: backend s3 selected but no S3 bucket is configured")
		}
		if !bucketConfigured(cfg, bucket) {
			return nil, fmt.Errorf("docstore: ORIGINAL_STORE_S3_BUCKET %q is not one of the configured S3 buckets", bucket)
		}
		return NewS3Store(s3c, bucket, cfg.OriginalStoreS3Prefix)
	case config.OriginalStoreFS:
		if cfg.OriginalStoreFSPath == "" {
			return nil, fmt.Errorf("docstore: backend fs selected but ORIGINAL_STORE_FS_PATH is empty")
		}
		return NewFSStore(cfg.OriginalStoreFSPath)
	default:
		return nil, fmt.Errorf("docstore: unknown backend %q", backend)
	}
}

func bucketConfigured(cfg *config.Config, name string) bool {
	for _, b := range cfg.S3Buckets {
		if b.Name == name {
			return true
		}
	}
	return false
}
