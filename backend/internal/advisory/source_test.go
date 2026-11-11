package advisory

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseSources(t *testing.T) {
	got, err := ParseSources(" Wolfi|https://feed.example/osv/all.json|pkg:apk/wolfi|pkg:APK/chainguard , private|s3://advisories/all.json ,")
	if err != nil {
		t.Fatal(err)
	}
	want := []Source{
		{Name: "wolfi", Index: "https://feed.example/osv/all.json", Prefixes: []string{"pkg:apk/wolfi", "pkg:apk/chainguard"}},
		{Name: "private", Index: "s3://advisories/all.json"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if got, err := ParseSources(""); err != nil || got != nil {
		t.Fatalf("empty: %v %v", got, err)
	}
}

func TestParseSourcesRejects(t *testing.T) {
	for _, raw := range []string{
		"https://feed.example/all.json",             // no name
		"osv|https://feed.example/all.json",         // reserved
		"a b|https://feed.example/all.json",         // bad name
		"x|http://feed.example/all.json",            // plain http
		"x|ftp://feed.example/all.json",             // scheme
		"x|https://feed.example/all.json|apk/wolfi", // not a purl prefix
		"x|file:///a/all.json,x|file:///b/all.json", // duplicate
	} {
		if _, err := ParseSources(raw); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
}

func TestAuthorityRespectsPathBoundary(t *testing.T) {
	s := Source{Prefixes: []string{"pkg:apk/wolfi", "pkg:apk/wolfi/openssl"}}
	if got := s.authority("pkg:apk/wolfi/openssl@3-r0"); got != len("pkg:apk/wolfi/openssl") {
		t.Errorf("longest prefix not chosen: %d", got)
	}
	if s.authority("pkg:apk/wolfish/x@1") != 0 {
		t.Error("prefix matched across a path boundary")
	}
	if s.authority("PKG:APK/WOLFI/curl@1") == 0 {
		t.Error("prefix match is case-sensitive")
	}
}

func TestRecordLocation(t *testing.T) {
	cases := map[string]string{
		"https://feed.example/osv/all.json":       "https://feed.example/osv/CGA-1.json",
		"https://feed.example/osv/all.json?sig=1": "https://feed.example/osv/CGA-1.json",
		"s3://bucket/feeds/vendor/all.json":       "s3://bucket/feeds/vendor/CGA-1.json",
		"file:///var/lib/feeds/all.json":          "file:///var/lib/feeds/CGA-1.json",
	}
	for index, want := range cases {
		if got, err := recordLocation(index, "CGA-1"); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", index, got, err, want)
		}
	}
	for _, id := range []string{"../etc/passwd", "a/b", "..", ""} {
		if _, err := recordLocation("file:///feeds/all.json", id); err == nil {
			t.Errorf("record id %q accepted", id)
		}
	}
}

func TestParsePURLAndKeys(t *testing.T) {
	p, ok := parsePURL("pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12")
	if !ok || p.key != "deb/debian/openssl" || p.version != "3.0.11-1~deb12u2" || p.qualifiers["distro"] != "debian-12" {
		t.Fatalf("parsed %+v", p)
	}
	if p, ok := parsePURL("pkg:npm/%40scope/name@1.0.0"); !ok || p.key != "npm/@scope/name" {
		t.Errorf("scoped npm: %+v", p)
	}
	if _, ok := parsePURL("not-a-purl"); ok {
		t.Error("garbage parsed")
	}
	for _, c := range []struct{ purl, eco, name, key, rel string }{
		{"pkg:apk/wolfi/curl", "Wolfi", "curl", "apk/wolfi/curl", ""},
		{"", "Alpine:v3.18", "zlib", "apk/alpine/zlib", "3.18"},
		{"", "Debian:12", "openssl", "deb/debian/openssl", "12"},
		{"", "Maven", "org.apache:commons", "maven/org.apache/commons", ""},
		{"", "SomethingNew", "x", "", ""},
	} {
		k, rel := affectedKey(c.purl, c.eco, c.name)
		if k != c.key || rel != c.rel {
			t.Errorf("%s/%s: %q %q, want %q %q", c.eco, c.name, k, rel, c.key, c.rel)
		}
	}
}

func TestNormalizeStatus(t *testing.T) {
	for in, want := range map[string]string{
		"Under Investigation":  StatusUnderInvestigation,
		"pending-upstream-fix": StatusPendingUpstreamFix,
		"fix_not_planned":      StatusFixNotPlanned,
		"NOT AFFECTED":         StatusNotAffected,
		"fixed":                StatusFixed,
		"affected":             StatusAffected,
		"":                     "",
		"maybe":                "",
	} {
		if got := normalizeStatus(in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}

// ------------------------------------------------------------------ sync

type memSyncStore struct {
	mu       sync.Mutex
	versions map[string]map[string]time.Time
	inserted []Row
}

func (m *memSyncStore) AdvisoryRecordVersions(_ context.Context, source string) (map[string]time.Time, error) {
	return m.versions[source], nil
}

func (m *memSyncStore) InsertAdvisoryRecords(_ context.Context, rows []Row) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inserted = append(m.inserted, rows...)
	return nil
}

func record(id, modified string) string {
	return fmt.Sprintf(`{"id":%q,"modified":%q,"related":["CVE-2026-1"],"affected":[{"package":{"ecosystem":"Wolfi","name":"curl","purl":"pkg:apk/wolfi/curl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"8.0.0-r1"}]}]}]}`, id, modified)
}

// Only records new or modified since the stored version are fetched; a
// record the feed lists but does not serve is counted as failed.
func TestSyncFetchesOnlyChangedRecords(t *testing.T) {
	var mu sync.Mutex
	var served []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served = append(served, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/osv/all.json":
			io.WriteString(w, `[{"id":"A","modified":"2026-01-01T00:00:00Z"},{"id":"B","modified":"2026-03-01T00:00:00Z"},{"id":"C","modified":"2026-03-01T00:00:00Z"},{"id":"D","modified":"2026-03-01T00:00:00Z"}]`)
		case "/osv/B.json":
			io.WriteString(w, record("B", "2026-03-01T00:00:00Z"))
		case "/osv/C.json":
			io.WriteString(w, record("C", "2026-03-01T00:00:00Z"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store := &memSyncStore{versions: map[string]map[string]time.Time{"wolfi": {
		"A": time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), // unchanged
		"B": time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), // modified since
	}}}
	f := &Fetcher{HTTP: srv.Client()}
	src := []Source{{Name: "wolfi", Index: srv.URL + "/osv/all.json"}}

	res, err := Sync(context.Background(), src, f, store)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Indexed != 4 || res[0].Fetched != 2 || res[0].Failed != 1 {
		t.Errorf("result = %+v", res[0])
	}
	for _, p := range served {
		if p == "/osv/A.json" {
			t.Error("unchanged record A was fetched")
		}
	}
	if len(store.inserted) != 2 {
		t.Fatalf("inserted %d rows", len(store.inserted))
	}
	for _, r := range store.inserted {
		if r.Source != "wolfi" || !reflect.DeepEqual(r.PackageKeys, []string{"apk/wolfi/curl"}) || !strings.Contains(r.RecordJSON, `"id":"`+r.ID+`"`) {
			t.Errorf("row = %+v", r)
		}
	}
}

func TestSyncFromFileAndBadIndex(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "all.json"), []byte(`[{"id":"P-1","modified":"2026-02-02T00:00:00Z"}]`), 0o600)
	os.WriteFile(filepath.Join(dir, "P-1.json"), []byte(record("P-1", "2026-02-02T00:00:00Z")), 0o600)
	store := &memSyncStore{}
	res, err := Sync(context.Background(), []Source{{Name: "private", Index: "file://" + filepath.Join(dir, "all.json")}}, NewFetcher(nil), store)
	if err != nil || res[0].Fetched != 1 {
		t.Fatalf("file feed: %+v %v", res, err)
	}
	if !store.inserted[0].Modified.Equal(time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("modified = %v", store.inserted[0].Modified)
	}

	os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"not":"an array"}`), 0o600)
	if _, err := Sync(context.Background(), []Source{{Name: "bad", Index: "file://" + filepath.Join(dir, "bad.json")}}, NewFetcher(nil), &memSyncStore{}); err == nil {
		t.Error("malformed index accepted")
	}
	if _, err := Sync(context.Background(), []Source{{Name: "gone", Index: "file://" + filepath.Join(dir, "missing.json")}}, NewFetcher(nil), &memSyncStore{}); err == nil {
		t.Error("missing index is not an error")
	}
}

// A record whose id differs from the index entry is rejected: the file name
// and its content must agree.
func TestSyncRejectsMismatchedRecordID(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "all.json"), []byte(`[{"id":"P-1","modified":"2026-02-02T00:00:00Z"}]`), 0o600)
	os.WriteFile(filepath.Join(dir, "P-1.json"), []byte(record("OTHER", "2026-02-02T00:00:00Z")), 0o600)
	store := &memSyncStore{}
	res, err := Sync(context.Background(), []Source{{Name: "private", Index: "file://" + filepath.Join(dir, "all.json")}}, NewFetcher(nil), store)
	if err != nil || res[0].Failed != 1 || len(store.inserted) != 0 {
		t.Fatalf("res %+v err %v inserted %d", res, err, len(store.inserted))
	}
}

func TestFetcherSizeLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.json")
	os.WriteFile(path, []byte(strings.Repeat("x", 100)), 0o600)
	if _, err := NewFetcher(nil).Get(context.Background(), "file://"+path, 10); err == nil {
		t.Error("oversized document accepted")
	}
	if _, err := NewFetcher(nil).Get(context.Background(), "s3://b/k", 10); err == nil {
		t.Error("s3 without a client accepted")
	}
}

// A record the index stops listing is retired with a tombstone, so the
// matcher no longer applies an advisory the feed has taken back.
func TestSyncTombstonesRecordsDroppedFromIndex(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "all.json"), []byte(`[{"id":"KEEP","modified":"2026-02-02T00:00:00Z"}]`), 0o600)
	when := time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)
	store := &memSyncStore{versions: map[string]map[string]time.Time{"private": {"KEEP": when, "GONE": when}}}

	res, err := Sync(context.Background(), []Source{{Name: "private", Index: "file://" + filepath.Join(dir, "all.json")}}, NewFetcher(nil), store)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Removed != 1 || res[0].Fetched != 0 {
		t.Fatalf("result = %+v", res[0])
	}
	if len(store.inserted) != 1 {
		t.Fatalf("inserted = %+v", store.inserted)
	}
	got := store.inserted[0]
	if got.ID != "GONE" || got.RecordJSON != "" || len(got.PackageKeys) != 0 || !got.Modified.Equal(time.Unix(0, 0)) {
		t.Errorf("tombstone = %+v", got)
	}
}

// An index that suddenly lists nothing is a broken feed, not a withdrawal of
// every advisory: the stored records are kept and the sync reports an error.
func TestSyncKeepsRecordsWhenIndexComesBackEmpty(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "all.json"), []byte(`[]`), 0o600)
	store := &memSyncStore{versions: map[string]map[string]time.Time{"private": {"A": time.Now()}}}
	_, err := Sync(context.Background(), []Source{{Name: "private", Index: "file://" + filepath.Join(dir, "all.json")}}, NewFetcher(nil), store)
	if err == nil {
		t.Fatal("empty index wiped stored records without an error")
	}
	if len(store.inserted) != 0 {
		t.Fatalf("records were tombstoned: %+v", store.inserted)
	}
}
