// Package docstore persists the original bytes of ingested SBOM documents
// (Tier-2 fidelity capture, #256).
//
// ClickHouse is an analytical store: the dependency tree lives in parallel
// Array() columns and most document-level detail (copyright text, supplier,
// external references, formatting) is dropped on parse. To be able to hand
// the exact document back later — for download, enriched export or
// re-signing (#255) — the worker stores the raw bytes in a blob store at
// ingest time and records only a reference + sha256 in the document_store
// table.
//
// Two backends are provided: S3/MinIO (object storage, typically the source
// bucket under a reserved prefix) and a local filesystem directory (a PVC for
// filesystem-only or air-gapped deployments). Both are addressed through
// opaque references ("s3://bucket/key", "fs://relative/path") so that the API
// gateway can resolve a stored reference without knowing how it was produced.
package docstore

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	s3client "github.com/seebom-labs/bomhort/backend/internal/s3"
)

// Backend identifiers as persisted in document_store.storage_backend.
const (
	BackendS3 = "s3"
	BackendFS = "fs"
)

// Content encodings as persisted in document_store.content_encoding.
const (
	EncodingIdentity = ""     // stored as-is
	EncodingGzip     = "gzip" // RFC 1952; stored key carries the .gz suffix
)

// gzipSuffix marks a stored object as gzip-encoded. The encoding is derived
// from the reference itself so a reader never needs the ClickHouse row to
// know how to decode a blob.
const gzipSuffix = ".gz"

// gzipLevel is BestSpeed on purpose: SBOM JSON is highly repetitive (PURLs,
// license ids, hashes) and already shrinks ~85–90 % at the fastest level;
// the extra few percent from DefaultCompression cost ~3x the CPU on the
// ingestion hot path.
const gzipLevel = gzip.BestSpeed

// ReservedS3Prefix is the default key prefix under which originals are stored
// when the S3 backend shares a bucket with SBOM sources. The ingestion watcher
// skips this prefix so stored originals are never re-ingested as new SBOMs.
const ReservedS3Prefix = s3client.ReservedPrefix + "originals/"

// ErrNotFound is returned by Get when the referenced object does not exist.
var ErrNotFound = errors.New("docstore: object not found")

// ErrBackendMismatch is returned by Get when the reference scheme does not
// match the store's backend (e.g. worker wrote to S3, gateway configured fs).
var ErrBackendMismatch = errors.New("docstore: reference scheme does not match configured backend")

// PutResult describes a stored object.
type PutResult struct {
	// Ref is the opaque reference to persist in document_store.storage_ref.
	Ref string
	// Encoding is the on-disk content encoding (EncodingGzip or EncodingIdentity).
	Encoding string
	// StoredBytes is the size of the object as written to the backend — i.e.
	// the compressed size when Encoding is gzip. This is what actually
	// consumes disk / bucket space.
	StoredBytes uint64
}

// Store persists and retrieves original document bytes.
//
// Objects are gzip-compressed transparently: Put compresses, Get decompresses.
// Callers that can hand the compressed bytes straight to an HTTP client with
// Content-Encoding: gzip (the API gateway) use GetEncoded to skip the
// decompression round-trip.
type Store interface {
	// Backend returns the backend identifier (BackendS3 or BackendFS).
	Backend() string
	// Put compresses and stores data under the given relative key.
	Put(ctx context.Context, key string, data []byte) (PutResult, error)
	// Get opens the object addressed by a reference previously returned by Put
	// and returns the ORIGINAL (decoded) bytes. The caller must close the reader.
	Get(ctx context.Context, ref string) (io.ReadCloser, error)
	// GetEncoded opens the object as stored, without decoding, and reports the
	// encoding. The caller must close the reader.
	GetEncoded(ctx context.Context, ref string) (rc io.ReadCloser, encoding string, err error)
	// Delete removes the object addressed by ref. Deleting a missing object is
	// not an error.
	Delete(ctx context.Context, ref string) error
}

// rawStore is the backend-specific part; the shared compression / decoding
// logic in this file wraps it. Keeping backends free of encoding concerns
// means a new backend only has to move bytes.
type rawStore interface {
	Backend() string
	putRaw(ctx context.Context, key string, data []byte) (ref string, err error)
	getRaw(ctx context.Context, ref string) (io.ReadCloser, error)
	deleteRaw(ctx context.Context, ref string) error
	immutableRef(key string) (string, error)
	putRawIfAbsent(ctx context.Context, ref string, data []byte) (bool, error)
	syncImmutable(ref string) error
}

// SyncImmutable makes a previously created object durable before it is indexed.
func SyncImmutable(store Store, ref string) error {
	switch s := store.(type) {
	case *multiStore:
		backend, err := s.storeFor(ref)
		if err != nil {
			return err
		}
		return SyncImmutable(backend, ref)
	case *encodedStore:
		return s.raw.syncImmutable(ref)
	default:
		return errors.New("docstore: immutable storage is unavailable")
	}
}

// ImmutableRef returns the reference at which an immutable object would be
// stored by the configured primary backend.
func ImmutableRef(store Store, key string) (string, error) {
	switch s := store.(type) {
	case *encodedStore:
		return s.raw.immutableRef(key + gzipSuffix)
	case *multiStore:
		return ImmutableRef(s.primary, key)
	default:
		return "", errors.New("docstore: immutable storage is unavailable")
	}
}

// PutIfAbsent atomically creates a compressed object at ref. Existing objects
// are never overwritten, including when a writer is retried after a timeout.
func PutIfAbsent(ctx context.Context, store Store, ref string, data []byte) (bool, error) {
	switch s := store.(type) {
	case *multiStore:
		backend, err := s.storeFor(ref)
		if err != nil {
			return false, err
		}
		return PutIfAbsent(ctx, backend, ref, data)
	case *encodedStore:
		if EncodingOf(ref) != EncodingGzip {
			return false, fmt.Errorf("docstore: immutable reference must use gzip: %q", ref)
		}
		compressed, err := compress(data)
		if err != nil {
			return false, err
		}
		return s.raw.putRawIfAbsent(ctx, ref, compressed)
	default:
		return false, errors.New("docstore: immutable storage is unavailable")
	}
}

// EncodingOf derives the content encoding from a stored reference.
func EncodingOf(ref string) string {
	if strings.HasSuffix(ref, gzipSuffix) {
		return EncodingGzip
	}
	return EncodingIdentity
}

// compress gzips data. The result is a fresh buffer; data is not retained.
func compress(data []byte) ([]byte, error) {
	// Pre-size to ~1/6 of the input: SBOM JSON typically shrinks 6–10x.
	buf := bytes.NewBuffer(make([]byte, 0, len(data)/6+512))
	zw, err := gzip.NewWriterLevel(buf, gzipLevel)
	if err != nil {
		return nil, fmt.Errorf("docstore: gzip writer: %w", err)
	}
	if _, err := zw.Write(data); err != nil {
		return nil, fmt.Errorf("docstore: gzip write: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("docstore: gzip close: %w", err)
	}
	return buf.Bytes(), nil
}

// decodeReader wraps rc according to encoding. Closing the returned reader
// closes rc.
func decodeReader(rc io.ReadCloser, encoding string) (io.ReadCloser, error) {
	switch encoding {
	case EncodingIdentity:
		return rc, nil
	case EncodingGzip:
		zr, err := gzip.NewReader(rc)
		if err != nil {
			_ = rc.Close()
			return nil, fmt.Errorf("docstore: gzip reader: %w", err)
		}
		return &gzipReadCloser{Reader: zr, underlying: rc}, nil
	default:
		_ = rc.Close()
		return nil, fmt.Errorf("docstore: unsupported content encoding %q", encoding)
	}
}

type gzipReadCloser struct {
	*gzip.Reader
	underlying io.ReadCloser
}

func (g *gzipReadCloser) Close() error {
	zerr := g.Reader.Close()
	uerr := g.underlying.Close()
	if zerr != nil {
		return zerr
	}
	return uerr
}

// encodedStore implements Store on top of a rawStore.
type encodedStore struct {
	raw rawStore
}

func newEncodedStore(raw rawStore) Store { return &encodedStore{raw: raw} }

func (e *encodedStore) Backend() string { return e.raw.Backend() }

func (e *encodedStore) Put(ctx context.Context, key string, data []byte) (PutResult, error) {
	gz, err := compress(data)
	if err != nil {
		return PutResult{}, err
	}
	ref, err := e.raw.putRaw(ctx, key+gzipSuffix, gz)
	if err != nil {
		return PutResult{}, err
	}
	return PutResult{Ref: ref, Encoding: EncodingGzip, StoredBytes: uint64(len(gz))}, nil
}

func (e *encodedStore) GetEncoded(ctx context.Context, ref string) (io.ReadCloser, string, error) {
	rc, err := e.raw.getRaw(ctx, ref)
	if err != nil {
		return nil, "", err
	}
	return rc, EncodingOf(ref), nil
}

func (e *encodedStore) Get(ctx context.Context, ref string) (io.ReadCloser, error) {
	rc, enc, err := e.GetEncoded(ctx, ref)
	if err != nil {
		return nil, err
	}
	reader, err := decodeReader(rc, enc)
	if s3client.IsObjectNotFound(err) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, ref)
	}
	return reader, err
}

func (e *encodedStore) Delete(ctx context.Context, ref string) error {
	return e.raw.deleteRaw(ctx, ref)
}

// writableChecker is implemented by backends that can cheaply verify write
// access up front (currently FSStore). S3 credentials are validated lazily
// on the first Put.
type writableChecker interface {
	CheckWritable() error
}

// CheckWritable runs the backend's startup write probe, if it has one.
// Read-only consumers (the API gateway) must not call this.
func CheckWritable(s Store) error {
	if wc, ok := s.(writableChecker); ok {
		return wc.CheckWritable()
	}
	if es, ok := s.(*encodedStore); ok {
		if wc, ok := es.raw.(writableChecker); ok {
			return wc.CheckWritable()
		}
	}
	return nil
}

// SHA256Hex returns the lowercase hex sha256 digest of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Key builds the relative storage key for an SBOM: "<sbom_id>/<basename>".
//
// The sbom_id gives a stable, collision-free directory; the sanitized base
// name of the source file is kept so the object is recognisable in the bucket
// and so the download can offer the original filename.
func Key(sbomID, sourceFile string) string {
	base := path.Base(strings.ReplaceAll(sourceFile, "\\", "/"))
	if base == "" || base == "." || base == "/" {
		return sbomID + "/document.json"
	}
	base = sanitizeName(base)
	if base == "" {
		base = "document.json"
	}
	return sbomID + "/" + base
}

// sanitizeName keeps a conservative character set for object keys / file
// names: letters, digits, '.', '-', '_' and '@' (for image references such as
// "app@sha256-…"). Everything else becomes '_'. Leading dots are stripped so a
// key can never start a hidden file or a path traversal segment.
func sanitizeName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_', r == '@':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.TrimLeft(b.String(), ".")
	if len(out) > 200 {
		out = out[len(out)-200:]
	}
	return out
}

// splitRef separates "scheme://rest" and validates the scheme.
func splitRef(ref, wantScheme string) (string, error) {
	prefix := wantScheme + "://"
	if !strings.HasPrefix(ref, prefix) {
		return "", fmt.Errorf("%w: %q", ErrBackendMismatch, ref)
	}
	rest := strings.TrimPrefix(ref, prefix)
	if rest == "" {
		return "", fmt.Errorf("docstore: empty reference %q", ref)
	}
	return rest, nil
}
