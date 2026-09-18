package docstore

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
)

// The bug this guards against (#358): the parsing worker resolved
// ORIGINAL_STORE_BACKEND=auto to fs (no S3_BUCKETS in its environment) and
// wrote "fs://…" references, while the API gateway resolved the same "auto" to
// s3 (it does get S3_BUCKETS, for the upload endpoint). Every download then
// failed with ErrBackendMismatch although the file was present in the volume
// mounted into both containers.
//
// A reference records where the bytes are; resolving it must not depend on the
// reading process's own backend choice.

func TestMultiStoreResolvesForeignScheme(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}

	ctx := context.Background()
	want := []byte(`{"spdxVersion":"SPDX-2.3"}`)
	res, err := fs.Put(ctx, "sbom-1/doc.json", want)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Primary is a stand-in for "the gateway resolved s3"; the fs store is
	// only the read fallback. The fs:// reference must still resolve.
	store := newMultiStore(stubStore{backend: BackendS3}, fs)

	rc, err := store.Get(ctx, res.Ref)
	if err != nil {
		t.Fatalf("Get(%q) through non-matching primary: %v", res.Ref, err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("Get returned %q, want %q", got, want)
	}

	if store.Backend() != BackendS3 {
		t.Errorf("Backend() = %q, want the primary %q", store.Backend(), BackendS3)
	}
}

func TestMultiStoreUnknownSchemeStillMismatches(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	store := newMultiStore(stubStore{backend: BackendS3}, fs)

	for _, ref := range []string{"gcs://bucket/key", "no-scheme", ""} {
		if _, err := store.Get(context.Background(), ref); !errors.Is(err, ErrBackendMismatch) {
			t.Errorf("Get(%q) error = %v, want ErrBackendMismatch", ref, err)
		}
	}
}

// A single configured backend must keep the exact previous behaviour, including
// the ErrBackendMismatch contract for a foreign reference.
func TestMultiStoreSingleBackendUnchanged(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}

	store := newMultiStore(fs, nil)
	if _, ok := store.(*multiStore); ok {
		t.Error("newMultiStore wrapped a single backend; it should return it unchanged")
	}
	if _, err := store.Get(context.Background(), "s3://bucket/key"); !errors.Is(err, ErrBackendMismatch) {
		t.Errorf("Get(s3://…) on fs-only store error = %v, want ErrBackendMismatch", err)
	}
}

// The gateway mounts the originals volume read-only, so the write probe must
// only ever touch the primary.
func TestMultiStoreCheckWritableProbesPrimaryOnly(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("cannot make dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	store := newMultiStore(stubStore{backend: BackendS3}, fs)
	if err := CheckWritable(store); err != nil {
		t.Errorf("CheckWritable probed the read-only fallback: %v", err)
	}
}

// stubStore is a minimal Store used as a primary that is never read from.
type stubStore struct{ backend string }

func (s stubStore) Backend() string { return s.backend }
func (s stubStore) Put(context.Context, string, []byte) (PutResult, error) {
	return PutResult{}, errors.New("stub: not implemented")
}
func (s stubStore) Get(context.Context, string) (io.ReadCloser, error) {
	return nil, errors.New("stub: not implemented")
}
func (s stubStore) GetEncoded(context.Context, string) (io.ReadCloser, string, error) {
	return nil, "", errors.New("stub: not implemented")
}
func (s stubStore) Delete(context.Context, string) error { return nil }
