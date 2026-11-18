package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/projectgroup"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

var noParents = newVulnFilter(func(context.Context) (map[string]projectgroup.Assignment, error) {
	return nil, errors.New("parents must not be resolved without ?parent=")
})

func TestVulnFilterParsing(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x?cluster=a,%20b,,&namespace=ns&project=p&tag=Sandbox,cncf", nil)
	f, status, _ := noParents(r)
	if status != 0 {
		t.Fatalf("status = %d", status)
	}
	want := clickhouse.VulnFilter{Clusters: []string{"a", "b"}, Namespaces: []string{"ns"}, Projects: []string{"p"}, Tags: []string{"cncf", "sandbox"}}
	if !reflect.DeepEqual(f, want) {
		t.Fatalf("got %+v, want %+v", f, want)
	}

	long := strings.Repeat("x", maxOwnerNameLen+1)
	for _, p := range []string{"cluster", "namespace", "project", "parent"} {
		if _, status, _ := noParents(httptest.NewRequest(http.MethodGet, "/x?"+p+"=ok,"+long, nil)); status != http.StatusBadRequest {
			t.Errorf("%s too long: status = %d, want 400", p, status)
		}
	}
}

func TestVulnFilterParent(t *testing.T) {
	assignments := map[string]projectgroup.Assignment{
		"child-a": {Parent: "kubernetes"},
		"child-b": {Parent: "kubernetes"},
		"other":   {Parent: "helm"},
		// sub heads its own group, so it is not listed under kubernetes.
		"sub":     {Parent: "kubernetes"},
		"sub-kid": {Parent: "sub"},
	}
	filter := newVulnFilter(func(context.Context) (map[string]projectgroup.Assignment, error) { return assignments, nil })
	f, status, _ := filter(httptest.NewRequest(http.MethodGet, "/x?parent=kubernetes", nil))
	if status != 0 {
		t.Fatalf("status = %d", status)
	}
	slices.Sort(f.ParentMembers)
	if want := []string{"child-a", "child-b", "kubernetes"}; !reflect.DeepEqual(f.ParentMembers, want) {
		t.Fatalf("members = %v, want %v", f.ParentMembers, want)
	}

	failing := newVulnFilter(func(context.Context) (map[string]projectgroup.Assignment, error) { return nil, errors.New("down") })
	if _, status, _ := failing(httptest.NewRequest(http.MethodGet, "/x?parent=kubernetes", nil)); status != http.StatusInternalServerError {
		t.Fatalf("resolver error: status = %d, want 500", status)
	}
}

func TestVulnListHandlerRejects(t *testing.T) {
	for _, tc := range []struct{ pattern, url string }{
		{"GET /x", "/x?scope=indirect"},
		{"GET /x", "/x?cluster=" + strings.Repeat("c", maxOwnerNameLen+1)},
		{"GET /c/{name}", "/c/" + strings.Repeat("c", maxOwnerNameLen+1)},
		{"GET /c/{name}", "/c/a?cluster=b"},
		{"GET /x", "/x?exploit=true"},
		{"GET /x", "/x?exploit=Available"},
	} {
		mux := http.NewServeMux()
		// nil client: a request that reaches the query would panic.
		mux.HandleFunc(tc.pattern, vulnListHandler(nil, noParents,
			pathOwner("cluster", func(f *clickhouse.VulnFilter) *[]string { return &f.Clusters })))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.url, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", tc.url, rec.Code)
		}
	}
}

func TestParseExploit(t *testing.T) {
	for raw, want := range map[string][2]bool{
		"":          {false, true},
		"available": {true, true},
		"none":      {false, false},
		"1":         {false, false},
	} {
		on, ok := parseExploit(raw)
		if on != want[0] || ok != want[1] {
			t.Errorf("parseExploit(%q) = %v, %v; want %v, %v", raw, on, ok, want[0], want[1])
		}
	}
}

func TestOnlyExploitable(t *testing.T) {
	items := []dto.VulnerabilityListItem{
		{VulnID: "CVE-1", ExploitAvailable: true},
		{VulnID: "CVE-2"},
		{VulnID: "CVE-3", ExploitAvailable: true},
	}
	got := onlyExploitable(items)
	if len(got) != 2 || got[0].VulnID != "CVE-1" || got[1].VulnID != "CVE-3" {
		t.Fatalf("got %+v", got)
	}
	if empty := onlyExploitable(nil); empty == nil || len(empty) != 0 {
		t.Errorf("no findings must encode as [], got %#v", empty)
	}
}
