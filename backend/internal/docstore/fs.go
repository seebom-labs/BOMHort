package docstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FSStore persists originals below a root directory (typically a PVC mounted
// into both the parsing-worker and the api-gateway). It is the raw backend;
// NewFSStore wraps it in the shared compression layer.
type FSStore struct {
	root string
}

// NewFSStore returns a Store rooted at dir, creating it if necessary.
func NewFSStore(dir string) (Store, error) {
	raw, err := newFSStore(dir)
	if err != nil {
		return nil, err
	}
	return newEncodedStore(raw), nil
}

func newFSStore(dir string) (*FSStore, error) {
	if dir == "" {
		return nil, errors.New("docstore: filesystem root is required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("docstore: resolve %q: %w", dir, err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("docstore: create %q: %w", abs, err)
	}
	return &FSStore{root: abs}, nil
}

// Backend implements rawStore.
func (f *FSStore) Backend() string { return BackendFS }

func (f *FSStore) immutableRef(key string) (string, error) {
	rel, err := f.safeRel(key)
	if err != nil {
		return "", err
	}
	return "fs://" + filepath.ToSlash(rel), nil
}

func (f *FSStore) putRawIfAbsent(ctx context.Context, ref string, data []byte) (bool, error) {
	key, err := splitRef(ref, BackendFS)
	if err != nil {
		return false, err
	}
	rel, err := f.safeRel(key)
	if err != nil {
		return false, err
	}
	filename := filepath.Join(f.root, rel)
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, fmt.Errorf("docstore: create immutable directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".immutable-*")
	if err != nil {
		return false, fmt.Errorf("docstore: create immutable temporary file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("docstore: write immutable object: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("docstore: sync immutable object: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("docstore: close immutable object: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := os.Link(tmp.Name(), filename); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("docstore: publish immutable object: %w", err)
	}
	if err := f.syncImmutable(ref); err != nil {
		return false, err
	}
	return true, nil
}

func (f *FSStore) syncImmutable(ref string) error {
	key, err := splitRef(ref, BackendFS)
	if err != nil {
		return err
	}
	rel, err := f.safeRel(key)
	if err != nil {
		return err
	}
	dir := filepath.Dir(filepath.Join(f.root, rel))
	for {
		directory, err := os.Open(dir)
		if err != nil {
			return fmt.Errorf("docstore: open immutable directory: %w", err)
		}
		err = directory.Sync()
		closeErr := directory.Close()
		if err != nil {
			return fmt.Errorf("docstore: sync immutable directory: %w", err)
		}
		if closeErr != nil {
			return fmt.Errorf("docstore: close immutable directory: %w", closeErr)
		}
		if dir == f.root {
			return nil
		}
		dir = filepath.Dir(dir)
	}
}

// CheckWritable verifies that the process can create files below the root.
// Writers (the parsing worker) call this at startup so a volume that is
// mounted read-only or owned by another uid (typical for a fresh PVC or
// Docker volume without fsGroup/chown) fails fast with an actionable error
// instead of failing every single ingestion job.
func (f *FSStore) CheckWritable() error {
	probe, err := os.CreateTemp(f.root, ".write-probe-*")
	if err != nil {
		return fmt.Errorf("docstore: %s is not writable by uid %d (%w) — mount the volume read-write and set fsGroup / chown it to the container user", f.root, os.Getuid(), err)
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return nil
}

// putRaw implements rawStore. Writes are atomic (temp file + rename) so a
// crashed worker never leaves a truncated original behind.
func (f *FSStore) putRaw(ctx context.Context, key string, data []byte) (string, error) {
	rel, err := f.safeRel(key)
	if err != nil {
		return "", err
	}
	abs := filepath.Join(f.root, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return "", fmt.Errorf("docstore: mkdir for %s: %w", rel, err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(abs), ".tmp-*")
	if err != nil {
		return "", fmt.Errorf("docstore: temp file for %s: %w", rel, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return "", fmt.Errorf("docstore: write %s: %w", rel, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", fmt.Errorf("docstore: close %s: %w", rel, err)
	}
	if err := os.Rename(tmpName, abs); err != nil {
		cleanup()
		return "", fmt.Errorf("docstore: rename %s: %w", rel, err)
	}
	return "fs://" + filepath.ToSlash(rel), nil
}

// getRaw implements rawStore.
func (f *FSStore) getRaw(ctx context.Context, ref string) (io.ReadCloser, error) {
	rest, err := splitRef(ref, "fs")
	if err != nil {
		return nil, err
	}
	rel, err := f.safeRel(rest)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(filepath.Join(f.root, rel))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, ref)
		}
		return nil, fmt.Errorf("docstore: open %s: %w", ref, err)
	}
	return file, nil
}

// deleteRaw implements rawStore. The per-SBOM directory is removed too once
// it is empty so re-ingests don't leave thousands of empty directories behind.
func (f *FSStore) deleteRaw(ctx context.Context, ref string) error {
	rest, err := splitRef(ref, "fs")
	if err != nil {
		return err
	}
	rel, err := f.safeRel(rest)
	if err != nil {
		return err
	}
	abs := filepath.Join(f.root, rel)
	if err := os.Remove(abs); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("docstore: remove %s: %w", ref, err)
	}
	if dir := filepath.Dir(abs); dir != f.root {
		_ = os.Remove(dir) // fails harmlessly when not empty
	}
	return nil
}

// safeRel normalises key into a relative path that cannot escape the root.
func (f *FSStore) safeRel(key string) (string, error) {
	key = strings.ReplaceAll(key, "\\", "/")
	rel := filepath.Clean("/" + key) // anchor, then Clean collapses any ".."
	rel = strings.TrimPrefix(rel, string(filepath.Separator))
	if rel == "" || rel == "." {
		return "", fmt.Errorf("docstore: invalid key %q", key)
	}
	return rel, nil
}
