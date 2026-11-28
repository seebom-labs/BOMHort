package main

import (
	"context"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/advisory"
	"github.com/seebom-labs/bomhort/backend/internal/osv"
)

type fakeOSV struct {
	byPURL map[string][]string
	full   map[string]*osv.VulnEntry
}

func (f fakeOSV) QueryBatch(_ context.Context, purls []string) (*osv.BatchResponse, error) {
	resp := &osv.BatchResponse{Results: make([]osv.QueryResult, len(purls))}
	for i, p := range purls {
		for _, id := range f.byPURL[p] {
			resp.Results[i].Vulns = append(resp.Results[i].Vulns, osv.VulnEntry{ID: id})
		}
	}
	return resp, nil
}

func (f fakeOSV) HydrateVulns(_ context.Context, ids []string) (map[string]*osv.VulnEntry, error) {
	out := map[string]*osv.VulnEntry{}
	for _, id := range ids {
		if e, ok := f.full[id]; ok {
			out[id] = e
		}
	}
	return out, nil
}

type feedStore struct{ recs []advisory.StoredRecord }

func (s feedStore) LookupAdvisoryRecords(context.Context, []string, []string) ([]advisory.StoredRecord, error) {
	return s.recs, nil
}

func TestScanVulnerabilitiesWithoutFeeds(t *testing.T) {
	src := fakeOSV{
		byPURL: map[string][]string{"pkg:npm/a@1": {"GHSA-1", "GHSA-lost"}},
		full:   map[string]*osv.VulnEntry{"GHSA-1": {ID: "GHSA-1"}},
	}
	got, err := scanVulnerabilities(context.Background(), src, nil, []string{"pkg:npm/a@1", "pkg:npm/b@1"})
	if err != nil {
		t.Fatal(err)
	}
	// The un-hydrated id is skipped, not stubbed.
	if len(got) != 1 || got[0].Entry.ID != "GHSA-1" || got[0].Source != advisory.OSVSource {
		t.Fatalf("findings = %+v", got)
	}
}

// End to end through the worker's scan: an apk package whose distro feed
// has the backported fix produces no finding, although osv.dev matches the
// upstream range; a package one revision older keeps it.
func TestScanVulnerabilitiesBackport(t *testing.T) {
	fixed, old := "pkg:apk/wolfi/openssl@3.1.4-r2", "pkg:apk/wolfi/openssl@3.1.4-r1"
	src := fakeOSV{
		byPURL: map[string][]string{fixed: {"GHSA-up"}, old: {"GHSA-up"}},
		full:   map[string]*osv.VulnEntry{"GHSA-up": {ID: "GHSA-up", Aliases: []string{"CVE-2026-0001"}}},
	}
	rec := osv.VulnEntry{ID: "CGA-1", Related: []string{"CVE-2026-0001"}, Affected: []osv.Affected{{
		Package: osv.AffectedPackage{Ecosystem: "Wolfi", Name: "openssl", PURL: "pkg:apk/wolfi/openssl"},
		Ranges:  []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "3.1.4-r2"}}}},
	}}}
	m := advisory.NewMatcher(
		[]advisory.Source{{Name: "wolfi", Index: "https://feed.example/all.json", Prefixes: []string{"pkg:apk/wolfi"}}},
		feedStore{recs: []advisory.StoredRecord{{Source: "wolfi", Record: rec}}},
	)
	got, err := scanVulnerabilities(context.Background(), src, m, []string{fixed, old})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].PURL != old || got[0].Source != "wolfi" || got[0].Status != advisory.StatusAffected {
		t.Fatalf("findings = %+v", got)
	}
}

func TestScanVulnerabilities_OSPackagesReleaseFiltering(t *testing.T) {
	rhel9PURL := "pkg:rpm/redhat/openssl-libs@3.5.9-1.el9_9?distro=rhel-9.9&epoch=1"
	rhsa8 := &osv.VulnEntry{
		ID: "RHSA-2020:5588",
		Affected: []osv.Affected{{
			Package: osv.AffectedPackage{Ecosystem: "Red Hat:rhel_e4s:8.0::baseos", Name: "openssl-libs"},
			Ranges:  []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "1:1.1.1-9.el8_0"}}}},
		}},
	}
	rhsa9 := &osv.VulnEntry{
		ID: "RHSA-2026:9999",
		Affected: []osv.Affected{{
			Package: osv.AffectedPackage{Ecosystem: "Red Hat:enterprise_linux:9::baseos", Name: "openssl-libs"},
			Ranges:  []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "1:3.5.10-1.el9_9"}}}},
		}},
	}

	src := fakeOSV{
		byPURL: map[string][]string{rhel9PURL: {"RHSA-2020:5588", "RHSA-2026:9999"}},
		full:   map[string]*osv.VulnEntry{"RHSA-2020:5588": rhsa8, "RHSA-2026:9999": rhsa9},
	}

	// Without feeds: OSV hits for other releases should be filtered out.
	got, err := scanVulnerabilities(context.Background(), src, nil, []string{rhel9PURL})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Entry.ID != "RHSA-2026:9999" {
		t.Fatalf("got findings = %+v, want only RHSA-2026:9999", got)
	}
}
