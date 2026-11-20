package docstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	s3client "github.com/seebom-labs/bomhort/backend/internal/s3"
)

// S3Store persists originals as objects under bucket/prefix. It is the raw
// backend; NewS3Store wraps it in the shared compression layer.
type S3Store struct {
	client             *s3client.Client
	bucket             string
	prefix             string
	mu                 sync.Mutex
	conditionalChecked map[string]bool
}

// NewS3Store returns a Store writing to bucket under prefix. The client must
// already be configured for that bucket (it is looked up by name). An empty
// prefix falls back to ReservedS3Prefix.
func NewS3Store(client *s3client.Client, bucket, prefix string) (Store, error) {
	raw, err := newS3Store(client, bucket, prefix)
	if err != nil {
		return nil, err
	}
	return newEncodedStore(raw), nil
}

func newS3Store(client *s3client.Client, bucket, prefix string) (*S3Store, error) {
	if client == nil {
		return nil, errors.New("docstore: S3 client is nil")
	}
	if bucket == "" {
		return nil, errors.New("docstore: S3 bucket is required")
	}
	if prefix == "" {
		prefix = ReservedS3Prefix
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return &S3Store{client: client, bucket: bucket, prefix: prefix}, nil
}

// Backend implements rawStore.
func (s *S3Store) Backend() string { return BackendS3 }

func (s *S3Store) syncImmutable(string) error { return nil }

func (s *S3Store) immutableRef(key string) (string, error) {
	return "s3://" + s.bucket + "/" + s.prefix + strings.TrimPrefix(key, "/"), nil
}

func (s *S3Store) putRawIfAbsent(ctx context.Context, ref string, data []byte) (bool, error) {
	bucket, key, err := s.resolve(ref)
	if err != nil {
		return false, err
	}
	if err := s.checkConditionalWrites(ctx, bucket, key); err != nil {
		return false, err
	}
	return s.client.PutObjectIfAbsent(ctx, bucket, key, bytes.NewReader(data), int64(len(data)))
}

func (s *S3Store) checkConditionalWrites(ctx context.Context, bucket, key string) error {
	var prefix string
	if i := strings.LastIndex(key, "/tea/"); i >= 0 {
		prefix = key[:i+1]
	} else if !strings.HasPrefix(key, "tea/") {
		return errors.New("docstore: invalid immutable S3 key")
	}
	probe := prefix + "tea/.conditional-write-probe"
	cacheKey := bucket + "/" + probe
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conditionalChecked[cacheKey] {
		return nil
	}
	data := []byte("conditional-write-probe")
	if _, err := s.client.PutObjectIfAbsent(ctx, bucket, probe, bytes.NewReader(data), int64(len(data))); err != nil {
		return fmt.Errorf("docstore: conditional-write probe: %w", err)
	}
	created, err := s.client.PutObjectIfAbsent(ctx, bucket, probe, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("docstore: conditional-write probe: %w", err)
	}
	if created {
		return errors.New("docstore: S3 backend does not enforce conditional writes")
	}
	if s.conditionalChecked == nil {
		s.conditionalChecked = make(map[string]bool)
	}
	s.conditionalChecked[cacheKey] = true
	return nil
}

// putRaw implements rawStore.
func (s *S3Store) putRaw(ctx context.Context, key string, data []byte) (string, error) {
	objKey := s.prefix + strings.TrimPrefix(key, "/")
	if err := s.client.PutObject(ctx, s.bucket, objKey, bytes.NewReader(data), int64(len(data))); err != nil {
		return "", fmt.Errorf("docstore: put %s: %w", objKey, err)
	}
	return "s3://" + s.bucket + "/" + objKey, nil
}

// getRaw implements rawStore. Any "s3://" reference is accepted as long as
// the client knows the bucket, so a store can read originals written under a
// different prefix (e.g. after a prefix change).
func (s *S3Store) getRaw(ctx context.Context, ref string) (io.ReadCloser, error) {
	bucket, key, err := s.resolve(ref)
	if err != nil {
		return nil, err
	}
	rc, err := s.client.GetObject(ctx, bucket, key)
	if err != nil {
		return nil, fmt.Errorf("docstore: get %s: %w", ref, err)
	}
	return rc, nil
}

// deleteRaw implements rawStore. Only objects below this store's own prefix
// are ever removed — a reference pointing elsewhere (foreign prefix, source
// bucket) is refused so a misconfigured ORIGINAL_STORE_S3_PREFIX can never
// delete ingestion sources.
func (s *S3Store) deleteRaw(ctx context.Context, ref string) error {
	bucket, key, err := s.resolve(ref)
	if err != nil {
		return err
	}
	if bucket != s.bucket || !strings.HasPrefix(key, s.prefix) {
		return fmt.Errorf("docstore: refusing to delete %s outside s3://%s/%s", ref, s.bucket, s.prefix)
	}
	if err := s.client.RemoveObject(ctx, bucket, key); err != nil {
		return fmt.Errorf("docstore: remove %s: %w", ref, err)
	}
	return nil
}

func (s *S3Store) resolve(ref string) (bucket, key string, err error) {
	if _, err := splitRef(ref, "s3"); err != nil {
		return "", "", err
	}
	bucket, key, err = s3client.ParseURI(ref)
	if err != nil {
		return "", "", fmt.Errorf("docstore: %w", err)
	}
	return bucket, key, nil
}
