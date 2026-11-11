package advisory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/internal/osv"
)

const (
	// maxIndexSize bounds an index document. A 12k-record feed is ~1 MB.
	maxIndexSize = 64 << 20
	// maxRecordSize bounds a single OSV record.
	maxRecordSize = 4 << 20
	// fetchConcurrency is how many records are fetched at once per feed.
	fetchConcurrency = 8
	// insertBatch is how many records are written per ClickHouse insert.
	insertBatch = 500
)

// IndexEntry is one entry of a feed's index document.
type IndexEntry struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// Row is a feed record as it is stored in advisory_records.
type Row struct {
	Source      string
	ID          string
	Modified    time.Time
	PackageKeys []string
	RecordJSON  string
}

// SyncStore persists feed records.
type SyncStore interface {
	// AdvisoryRecordVersions returns the stored modified time per live
	// (not tombstoned) record id.
	AdvisoryRecordVersions(ctx context.Context, source string) (map[string]time.Time, error)
	InsertAdvisoryRecords(ctx context.Context, rows []Row) error
}

// ObjectGetter is the part of the S3 client an s3:// feed needs.
type ObjectGetter interface {
	GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, error)
}

// Fetcher reads feed documents from https://, s3:// and file:// locations.
type Fetcher struct {
	HTTP *http.Client
	S3   ObjectGetter
}

// NewFetcher returns a fetcher; s3c may be nil when no feed lives in S3.
func NewFetcher(s3c ObjectGetter) *Fetcher {
	return &Fetcher{HTTP: &http.Client{Timeout: 60 * time.Second}, S3: s3c}
}

// errNotFound marks a record the feed lists but does not serve.
var errNotFound = errors.New("not found")

// Get returns the document at loc, at most limit bytes.
func (f *Fetcher) Get(ctx context.Context, loc string, limit int64) ([]byte, error) {
	var body io.ReadCloser
	switch {
	case strings.HasPrefix(loc, "https://"):
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := f.HTTP.Do(req)
		if err != nil {
			return nil, fmt.Errorf("GET %s: %w", redact(loc), err)
		}
		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			return nil, errNotFound
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("GET %s: status %d", redact(loc), resp.StatusCode)
		}
		body = resp.Body
	case strings.HasPrefix(loc, "s3://"):
		if f.S3 == nil {
			return nil, fmt.Errorf("%s: no S3 bucket is configured (S3_BUCKETS)", loc)
		}
		rest := strings.TrimPrefix(loc, "s3://")
		bucket, key, ok := strings.Cut(rest, "/")
		if !ok || bucket == "" || key == "" {
			return nil, fmt.Errorf("%s: want s3://bucket/key", loc)
		}
		rc, err := f.S3.GetObject(ctx, bucket, key)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", loc, err)
		}
		body = rc
	case strings.HasPrefix(loc, "file://"):
		u, err := url.Parse(loc)
		if err != nil {
			return nil, err
		}
		fh, err := os.Open(u.Path)
		if errors.Is(err, os.ErrNotExist) {
			return nil, errNotFound
		}
		if err != nil {
			return nil, err
		}
		body = fh
	default:
		return nil, fmt.Errorf("unsupported location %q", redact(loc))
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", redact(loc), err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", redact(loc), limit)
	}
	return data, nil
}

// redact drops query string and user info, which may carry credentials.
func redact(loc string) string {
	u, err := url.Parse(loc)
	if err != nil {
		return "<invalid location>"
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return u.String()
}

// SyncResult reports one feed's sync.
type SyncResult struct {
	Source  string
	Indexed int // entries in the index
	Fetched int // records fetched and stored
	Failed  int // records that could not be fetched or parsed
	Removed int // stored records the index no longer lists, tombstoned
}

// tombstone is the row that retires a record the feed stopped publishing.
// It wins over the live row in advisory_records (newer synced_at), matches
// no package (empty package_keys) and is not reported as a stored version,
// so a record the feed publishes again is fetched again.
func tombstone(source, id string) Row {
	return Row{Source: source, ID: id, Modified: time.Unix(0, 0).UTC(), PackageKeys: []string{}}
}

// Sync brings the stored records of every source up to date with its
// index: only records that are new or whose modified time moved are
// fetched. A feed that fails keeps its stored records; the error is
// reported and the other feeds still sync.
func Sync(ctx context.Context, sources []Source, f *Fetcher, store SyncStore) ([]SyncResult, error) {
	var results []SyncResult
	var errs []error
	for _, s := range sources {
		r, err := syncOne(ctx, s, f, store)
		results = append(results, r)
		if err != nil {
			errs = append(errs, fmt.Errorf("advisory source %s: %w", s.Name, err))
		}
	}
	return results, errors.Join(errs...)
}

func parseTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func syncOne(ctx context.Context, s Source, f *Fetcher, store SyncStore) (SyncResult, error) {
	res := SyncResult{Source: s.Name}
	raw, err := f.Get(ctx, s.Index, maxIndexSize)
	if errors.Is(err, errNotFound) {
		return res, fmt.Errorf("index %s not found", redact(s.Index))
	}
	if err != nil {
		return res, err
	}
	var index []IndexEntry
	if err := json.Unmarshal(raw, &index); err != nil {
		return res, fmt.Errorf("index %s is not a JSON array of {id, modified}: %w", redact(s.Index), err)
	}
	res.Indexed = len(index)

	stored, err := store.AdvisoryRecordVersions(ctx, s.Name)
	if err != nil {
		return res, err
	}
	listed := make(map[string]struct{}, len(index))
	var todo []IndexEntry
	for _, e := range index {
		if e.ID == "" {
			continue
		}
		listed[e.ID] = struct{}{}
		mod, ok := parseTime(e.Modified)
		if have, known := stored[e.ID]; known && ok && !mod.After(have) {
			continue
		}
		todo = append(todo, e)
	}

	// Records the index no longer lists are retired, or the matcher would
	// keep applying an advisory the feed has taken back. An index that lists
	// nothing at all while records are stored is treated as a broken feed,
	// not as "every advisory was withdrawn": the records are kept.
	var gone []Row
	for id := range stored {
		if _, ok := listed[id]; !ok {
			gone = append(gone, tombstone(s.Name, id))
		}
	}
	if len(gone) > 0 && len(listed) == 0 {
		return res, fmt.Errorf("index %s lists no records while %d are stored; keeping them", redact(s.Index), len(stored))
	}
	for i := 0; i < len(gone); i += insertBatch {
		batch := gone[i:min(i+insertBatch, len(gone))]
		if err := store.InsertAdvisoryRecords(ctx, batch); err != nil {
			return res, err
		}
		res.Removed += len(batch)
	}
	if res.Removed > 0 {
		log.Printf("  advisory source %s: %d records no longer published, retired", s.Name, res.Removed)
	}

	if len(todo) == 0 {
		return res, nil
	}
	log.Printf("  advisory source %s: %d of %d records new or modified", s.Name, len(todo), len(index))

	var (
		mu    sync.Mutex
		rows  []Row
		wg    sync.WaitGroup
		sem   = make(chan struct{}, fetchConcurrency)
		flush = func(batch []Row) error { return store.InsertAdvisoryRecords(ctx, batch) }
		ferr  error
	)
	for _, e := range todo {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(e IndexEntry) {
			defer wg.Done()
			defer func() { <-sem }()
			row, err := fetchRecord(ctx, s, f, e)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Failed++
				if res.Failed <= 5 {
					log.Printf("  WARNING: advisory source %s: record %s: %v", s.Name, e.ID, err)
				}
				return
			}
			rows = append(rows, row)
			if len(rows) >= insertBatch && ferr == nil {
				batch := rows
				rows = nil
				if err := flush(batch); err != nil {
					ferr = err
					return
				}
				res.Fetched += len(batch)
			}
		}(e)
	}
	wg.Wait()
	if ferr != nil {
		return res, ferr
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if len(rows) > 0 {
		if err := flush(rows); err != nil {
			return res, err
		}
		res.Fetched += len(rows)
	}
	return res, nil
}

func fetchRecord(ctx context.Context, s Source, f *Fetcher, e IndexEntry) (Row, error) {
	loc, err := recordLocation(s.Index, e.ID)
	if err != nil {
		return Row{}, err
	}
	raw, err := f.Get(ctx, loc, maxRecordSize)
	if err != nil {
		return Row{}, err
	}
	var rec osv.VulnEntry
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Row{}, fmt.Errorf("not an OSV record: %w", err)
	}
	if rec.ID != e.ID {
		return Row{}, fmt.Errorf("record id %q does not match index id", rec.ID)
	}
	// The index's modified time is what the next sync compares against, so
	// it is the one stored; the record's own is the fallback.
	mod, ok := parseTime(e.Modified)
	if !ok {
		if mod, ok = parseTime(rec.Modified); !ok {
			mod = time.Now().UTC()
		}
	}
	return Row{
		Source:      s.Name,
		ID:          rec.ID,
		Modified:    mod,
		PackageKeys: PackageKeys(rec),
		RecordJSON:  string(raw),
	}, nil
}
