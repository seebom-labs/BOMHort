package tea

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func TestVEXVersionsRemainImmutable(t *testing.T) {
	handler, store, id, _ := setupTestHandler()
	ctx := context.Background()
	store.vexStmts = []models.VEXStatement{{
		VulnID: "CVE-2026-1234", ProductPURL: "pkg:golang/example/a@1", Status: "affected",
	}}
	sbomID := id.String()
	artifactID := ArtifactVEXUUID(sbomID)
	readData := func(version int, latest bool) []byte {
		t.Helper()
		data, err := handler.svc.GetArtifactData(ctx, artifactID, version, latest)
		if err != nil {
			t.Fatal(err)
		}
		defer data.Body.Close()
		raw, err := io.ReadAll(data.Body)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	col, err := handler.svc.GetCollection(ctx, sbomID, 1, true)
	if err != nil || col.Version != 1 || col.Artifacts[len(col.Artifacts)-1].Version != 1 {
		t.Fatalf("initial collection = %+v, err %v", col, err)
	}
	old := readData(1, false)
	if got := readData(1, true); !bytes.Equal(got, old) {
		t.Fatal("unchanged statements produced different bytes")
	}

	store.vexStmts[0].Status = "fixed"
	col, err = handler.svc.GetCollection(ctx, sbomID, 1, true)
	if err != nil || col.Version != 2 || col.Artifacts[len(col.Artifacts)-1].Version != 2 {
		t.Fatalf("updated collection = %+v, err %v", col, err)
	}
	current := readData(2, false)
	if bytes.Equal(old, current) {
		t.Fatal("changed statements produced identical VEX")
	}
	if got := readData(1, false); !bytes.Equal(got, old) {
		t.Fatal("published VEX version 1 changed")
	}
	oldCol, err := handler.svc.GetCollection(ctx, sbomID, 1, false)
	if err != nil || oldCol.Version != 1 || oldCol.Artifacts[len(oldCol.Artifacts)-1].Version != 1 {
		t.Fatalf("historical collection = %+v, err %v", oldCol, err)
	}

	restarted := NewHandler(NewService(store), "https://api.example.com/api/v1/tea")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tea/artifact/"+artifactID+"/latest/download", nil)
	rec := httptest.NewRecorder()
	restarted.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), current) ||
		!strings.HasSuffix(rec.Header().Get("Content-Location"), "/2/download") {
		t.Fatalf("latest after restart: status %d, location %q, body %s", rec.Code, rec.Header().Get("Content-Location"), rec.Body.String())
	}
	etag := rec.Header().Get("ETag")
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tea/artifact/"+artifactID+"/latest/download", nil)
	req.Header.Set("If-None-Match", etag)
	rec = httptest.NewRecorder()
	restarted.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified || !strings.HasSuffix(rec.Header().Get("Content-Location"), "/2/download") {
		t.Fatalf("conditional latest: status %d, location %q", rec.Code, rec.Header().Get("Content-Location"))
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tea/componentRelease/"+ComponentReleaseUUID(sbomID)+"/collection/1", nil)
	rec = httptest.NewRecorder()
	restarted.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"version":1`) {
		t.Fatalf("historical component collection: %d %s", rec.Code, rec.Body.String())
	}

	store.vexStmts = nil
	col, err = handler.svc.GetCollection(ctx, sbomID, 1, true)
	if err != nil || col.Version != 3 {
		t.Fatalf("collection after VEX removal = %+v, err %v", col, err)
	}
	if got := readData(1, false); !bytes.Equal(got, old) {
		t.Fatal("removing VEX changed historical bytes")
	}
	store.vexStmts = []models.VEXStatement{{VulnID: "CVE-2026-1234", ProductPURL: "pkg:golang/example/a@1", Status: "fixed"}}
	col, err = handler.svc.GetCollection(ctx, sbomID, 1, true)
	if err != nil || col.Version != 4 || col.Artifacts[len(col.Artifacts)-1].Version != 2 {
		t.Fatalf("collection after VEX reappears = %+v, err %v", col, err)
	}
}

func TestConcurrentSnapshotsPublishOnce(t *testing.T) {
	_, store, id, _ := setupTestHandler()
	store.vexStmts = []models.VEXStatement{{VulnID: "CVE-2026-1234", Status: "affected"}}
	const callers = 32
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			service := NewService(store)
			col, err := service.GetCollection(context.Background(), id.String(), 1, true)
			if err == nil && col.Version != 1 {
				err = fmt.Errorf("got collection version %d", col.Version)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := len(store.snapshots[id.String()]); got != 1 {
		t.Fatalf("published %d identical snapshots", got)
	}
}

func TestHistoricalVersionsDoNotQueryLiveVEX(t *testing.T) {
	_, store, id, _ := setupTestHandler()
	store.vexStmts = []models.VEXStatement{{VulnID: "CVE-2026-1234", Status: "affected"}}
	ctx := context.Background()
	if _, err := NewService(store).GetCollection(ctx, id.String(), 1, true); err != nil {
		t.Fatal(err)
	}
	service := NewService(&errorVEXStore{mockStore: store})
	if _, err := service.GetCollection(ctx, id.String(), 1, false); err != nil {
		t.Fatalf("historical collection: %v", err)
	}
	data, err := service.GetArtifactData(ctx, ArtifactVEXUUID(id.String()), 1, false)
	if err != nil {
		t.Fatalf("historical VEX: %v", err)
	}
	_ = data.Body.Close()
	if _, err := service.GetCollection(ctx, id.String(), 1, true); err == nil {
		t.Fatal("latest collection hid the live VEX query failure")
	}
}

func TestCollectionHistoryPagination(t *testing.T) {
	handler, store, id, _ := setupTestHandler()
	ctx := context.Background()
	store.vexStmts = []models.VEXStatement{{VulnID: "CVE-2026-1234", Status: "affected"}}
	if _, err := handler.svc.GetCollection(ctx, id.String(), 1, true); err != nil {
		t.Fatal(err)
	}
	store.vexStmts[0].Status = "fixed"
	if _, err := handler.svc.GetCollection(ctx, id.String(), 1, true); err != nil {
		t.Fatal(err)
	}
	for _, component := range []bool{false, true} {
		release, kind := id.String(), "productRelease"
		if component {
			release, kind = ComponentReleaseUUID(release), "componentRelease"
		}
		for page, want := range []int{2, 1} {
			url := fmt.Sprintf("/api/v1/tea/%s/%s/collections?pageSize=1&pageToken=%d", kind, release, page+1)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, url, nil))
			var result PaginatedResponse[Collection]
			if err := json.Unmarshal(rec.Body.Bytes(), &result); rec.Code != http.StatusOK || err != nil {
				t.Fatalf("%s: status %d, decode %v", url, rec.Code, err)
			}
			if len(result.Results) != 1 || result.Results[0].Version != want || result.Results[0].UUID != release ||
				result.HasNext != (page == 0) || (page == 0 && result.NextPageToken != "2") {
				t.Fatalf("%s: %+v", url, result)
			}
		}
	}
}

type unavailableSnapshots struct{ *mockStore }

func (u *unavailableSnapshots) LatestSnapshot(context.Context, *models.SBOM) (*Snapshot, error) {
	return nil, ErrSnapshotUnavailable
}

func TestUnavailableSnapshotStorageReturns503(t *testing.T) {
	_, store, id, _ := setupTestHandler()
	handler := NewHandler(NewService(&unavailableSnapshots{store}), "")
	for _, path := range []string{
		"/api/v1/tea/productRelease/" + id.String() + "/collection/latest",
		"/api/v1/tea/componentRelease/" + ComponentReleaseUUID(id.String()) + "/collection/latest",
		"/api/v1/tea/artifact/" + ArtifactVEXUUID(id.String()) + "/latest/download",
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: got %d, want 503: %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestOpenVEXOrderIsStableForTiedKeys(t *testing.T) {
	a := models.VEXStatement{VulnID: "CVE-1", ProductPURL: "pkg:x/a", Status: "affected", ImpactStatement: "a"}
	b := a
	b.ImpactStatement = "b"
	first, err := buildOpenVEXArtifactData("id", []models.VEXStatement{a, b}, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildOpenVEXArtifactData("id", []models.VEXStatement{b, a}, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	defer second.Body.Close()
	if first.SHA256Hash != second.SHA256Hash {
		t.Fatal("equal statement sets produced different bytes")
	}
}
