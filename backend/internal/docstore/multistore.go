package docstore

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// multiStore routes reads by the scheme of the stored reference instead of by
// the locally configured backend.
//
// Why this exists (#358): a reference records where the bytes actually are.
// Resolving it against whatever backend the *reading* process happens to have
// configured breaks as soon as the two differ, which is the normal case rather
// than the exotic one:
//
//   - In docker-compose the parsing worker gets no S3_BUCKETS (the ingestion
//     watcher does the S3 scanning), so ORIGINAL_STORE_BACKEND=auto resolves to
//     fs and it writes "fs://…" refs. The API gateway *does* get S3_BUCKETS for
//     the upload endpoint, so the same "auto" resolves to s3 there — and every
//     single download failed with ErrBackendMismatch even though the file was
//     sitting in the shared volume the compose file mounts into both.
//   - Migrating a deployment from fs to s3 (or back) would orphan every
//     previously captured original, for the same reason.
//
// The package contract was always "opaque references … so that the API gateway
// can resolve a stored reference without knowing how it was produced"; this
// type makes the implementation match it. Writes still go to the single
// configured primary backend — only resolution is reference-driven.
type multiStore struct {
	// primary receives Put and defines Backend(); it is also used for reads
	// of its own scheme.
	primary Store
	// byScheme maps a reference scheme ("fs", "s3") to the store able to read
	// it. Contains primary plus every other backend that is configured well
	// enough to read.
	byScheme map[string]Store
}

// newMultiStore wraps primary so that references belonging to any of the
// additional stores resolve too. Additional stores that are nil, or whose
// backend the primary already covers, are ignored. With nothing to add it
// returns primary unchanged, so the common single-backend setup keeps exactly
// the previous behaviour and cost.
func newMultiStore(primary Store, additional ...Store) Store {
	if primary == nil {
		return nil
	}
	byScheme := map[string]Store{primary.Backend(): primary}
	for _, s := range additional {
		if s == nil {
			continue
		}
		if _, exists := byScheme[s.Backend()]; exists {
			continue
		}
		byScheme[s.Backend()] = s
	}
	if len(byScheme) == 1 {
		return primary
	}
	return &multiStore{primary: primary, byScheme: byScheme}
}

// storeFor picks the store matching the reference scheme. A reference with an
// unknown or unconfigured scheme yields ErrBackendMismatch, which keeps the
// error contract for the genuinely misconfigured case.
func (m *multiStore) storeFor(ref string) (Store, error) {
	scheme, _, ok := strings.Cut(ref, "://")
	if !ok || scheme == "" {
		return nil, fmt.Errorf("%w: %q", ErrBackendMismatch, ref)
	}
	s, ok := m.byScheme[scheme]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrBackendMismatch, ref)
	}
	return s, nil
}

func (m *multiStore) Backend() string { return m.primary.Backend() }

func (m *multiStore) Put(ctx context.Context, key string, data []byte) (PutResult, error) {
	return m.primary.Put(ctx, key, data)
}

func (m *multiStore) Get(ctx context.Context, ref string) (io.ReadCloser, error) {
	s, err := m.storeFor(ref)
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, ref)
}

func (m *multiStore) GetEncoded(ctx context.Context, ref string) (io.ReadCloser, string, error) {
	s, err := m.storeFor(ref)
	if err != nil {
		return nil, "", err
	}
	return s.GetEncoded(ctx, ref)
}

func (m *multiStore) Delete(ctx context.Context, ref string) error {
	s, err := m.storeFor(ref)
	if err != nil {
		return err
	}
	return s.Delete(ctx, ref)
}

// CheckWritable probes only the primary: the read-only fallbacks are never
// written to, and requiring them to be writable would reintroduce the failure
// this type exists to remove (the gateway mounts the originals volume :ro).
func (m *multiStore) CheckWritable() error { return CheckWritable(m.primary) }
