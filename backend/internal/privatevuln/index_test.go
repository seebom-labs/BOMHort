package privatevuln

import (
	"strings"
	"testing"
	"time"
)

func TestParse_RejectsPublicPrefixes(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr string
	}{
		{
			name:    "CVE prefix rejected",
			json:    `[{"id": "CVE-2024-1234", "summary": "test"}]`,
			wantErr: `cannot use public OSV prefix CVE-`,
		},
		{
			name:    "Lowercase cve prefix rejected",
			json:    `[{"id": "cve-2024-1234", "summary": "test"}]`,
			wantErr: `cannot use public OSV prefix CVE-`,
		},
		{
			name:    "GHSA prefix rejected",
			json:    `[{"id": "GHSA-xxxx-yyyy-zzzz", "summary": "test"}]`,
			wantErr: `cannot use public OSV prefix GHSA-`,
		},
		{
			name:    "PYSEC prefix rejected",
			json:    `[{"id": "PYSEC-2023-192", "summary": "test"}]`,
			wantErr: `cannot use public OSV prefix PYSEC-`,
		},
		{
			name:    "GO prefix rejected",
			json:    `[{"id": "GO-2024-0001", "summary": "test"}]`,
			wantErr: `cannot use public OSV prefix GO-`,
		},
		{
			name:    "RUSTSEC prefix rejected",
			json:    `[{"id": "RUSTSEC-2024-0001", "summary": "test"}]`,
			wantErr: `cannot use public OSV prefix RUSTSEC-`,
		},
		{
			name:    "MAL prefix rejected",
			json:    `[{"id": "MAL-2024-0001", "summary": "test"}]`,
			wantErr: `cannot use public OSV prefix MAL-`,
		},
		{
			name:    "DSA prefix rejected",
			json:    `[{"id": "DSA-5000-1", "summary": "test"}]`,
			wantErr: `cannot use public OSV prefix DSA-`,
		},
		{
			name:    "Spaces rejected",
			json:    `[{"id": "Security Bulletin 12", "summary": "test"}]`,
			wantErr: `invalid id`,
		},
		{
			name:    "Too long id rejected",
			json:    `[{"id": "` + strings.Repeat("A", 101) + `", "summary": "test"}]`,
			wantErr: `invalid id`,
		},
		{
			name:    "Empty id rejected",
			json:    `[{"id": "", "summary": "test"}]`,
			wantErr: `missing id`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.json), "test.json")
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestParse_ValidFormats(t *testing.T) {
	arrayJSON := `[
		{
			"id": "BOMHORT-2024-001",
			"summary": "Internal flaw in auth module",
			"affected": [
				{
					"package": {
						"name": "internal-auth",
						"ecosystem": "npm",
						"purl": "pkg:npm/internal-auth"
					},
					"ranges": [
						{
							"type": "SEMVER",
							"events": [
								{"introduced": "0"},
								{"fixed": "2.1.0"}
							]
						}
					]
				}
			]
		}
	]`

	idx, err := Parse([]byte(arrayJSON), "array.json")
	if err != nil {
		t.Fatalf("Parse array: %v", err)
	}
	if len(idx.Entries) != 1 || idx.Entries[0].ID != "BOMHORT-2024-001" {
		t.Fatalf("Entries = %+v", idx.Entries)
	}

	objectJSON := `{
		"version": "1.0",
		"vulnerabilities": [
			{
				"id": "ORG-SEC-2024-042",
				"summary": "Wrapper object test",
				"affected": [
					{
						"package": {
							"name": "core-lib",
							"ecosystem": "npm",
							"purl": "pkg:npm/core-lib"
						},
						"versions": ["1.0.0", "1.0.1"]
					}
				]
			}
		]
	}`

	idx2, err := Parse([]byte(objectJSON), "object.json")
	if err != nil {
		t.Fatalf("Parse object: %v", err)
	}
	if len(idx2.Entries) != 1 || idx2.Entries[0].ID != "ORG-SEC-2024-042" {
		t.Fatalf("Entries = %+v", idx2.Entries)
	}
}

func TestMatch_SemverAndVersions(t *testing.T) {
	doc := `[
		{
			"id": "BOMHORT-2024-001",
			"summary": "Flaw in lodash fork",
			"affected": [
				{
					"package": {
						"name": "lodash",
						"ecosystem": "npm",
						"purl": "pkg:npm/lodash"
					},
					"ranges": [
						{
							"type": "SEMVER",
							"events": [
								{"introduced": "0"},
								{"fixed": "4.17.21"}
							]
						}
					]
				}
			]
		},
		{
			"id": "BOMHORT-2024-002",
			"summary": "Targeted version flaw",
			"affected": [
				{
					"package": {
						"name": "custom-pkg",
						"ecosystem": "npm",
						"purl": "pkg:npm/custom-pkg"
					},
					"versions": ["1.5.0", "1.5.1"]
				}
			]
		}
	]`

	idx, err := Parse([]byte(doc), "test.json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	purls := []string{
		"pkg:npm/lodash@4.17.15",     // should match BOMHORT-2024-001
		"pkg:npm/lodash@4.17.21",     // fixed version, should not match
		"pkg:npm/custom-pkg@1.5.0",   // should match BOMHORT-2024-002
		"pkg:npm/custom-pkg@1.5.2",   // not in versions list, should not match
		"pkg:npm/other-pkg@1.0.0",    // different package
	}

	findings := idx.Match(purls)
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}

	f1 := findings[0]
	if f1.PURL != "pkg:npm/lodash@4.17.15" || f1.Entry.ID != "BOMHORT-2024-001" {
		t.Errorf("f1 = %+v", f1)
	}
	if f1.Source != "private" {
		t.Errorf("f1.Source = %q, want 'private'", f1.Source)
	}
	if f1.FixedVersion != "4.17.21" {
		t.Errorf("f1.FixedVersion = %q, want '4.17.21'", f1.FixedVersion)
	}

	f2 := findings[1]
	if f2.PURL != "pkg:npm/custom-pkg@1.5.0" || f2.Entry.ID != "BOMHORT-2024-002" {
		t.Errorf("f2 = %+v", f2)
	}
	if f2.Source != "private" {
		t.Errorf("f2.Source = %q, want 'private'", f2.Source)
	}
}

func TestMatch_WithdrawnIgnored(t *testing.T) {
	doc := `[
		{
			"id": "BOMHORT-2024-999",
			"summary": "Withdrawn advisory",
			"withdrawn": "` + time.Now().UTC().Format(time.RFC3339) + `",
			"affected": [
				{
					"package": {
						"name": "pkg-a",
						"ecosystem": "npm",
						"purl": "pkg:npm/pkg-a"
					},
					"versions": ["1.0.0"]
				}
			]
		}
	]`

	idx, err := Parse([]byte(doc), "test.json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	findings := idx.Match([]string{"pkg:npm/pkg-a@1.0.0"})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for withdrawn advisory, got %d", len(findings))
	}
	if len(idx.Entries) != 1 {
		t.Errorf("Entries = %d, want 1", len(idx.Entries))
	}
	if len(idx.ActiveEntries) != 0 {
		t.Errorf("ActiveEntries = %d, want 0 (withdrawn excluded)", len(idx.ActiveEntries))
	}
}

func TestMatch_EcosystemAndLenientSemverAndVersionless(t *testing.T) {
	doc := `[
		{
			"id": "ACME-2026-002",
			"summary": "npm ecosystem range",
			"affected": [{
				"package": {"ecosystem": "npm", "name": "express"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.19.0"}]}]
			}]
		},
		{
			"id": "ACME-2026-003",
			"summary": "PyPI ecosystem range",
			"affected": [{
				"package": {"ecosystem": "PyPI", "name": "urllib3"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "2.32.0"}]}]
			}]
		},
		{
			"id": "ACME-2026-004",
			"summary": "Maven Final qualifier",
			"affected": [{
				"package": {"purl": "pkg:maven/org.example/core"},
				"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.5.1.Final"}]}]
			}]
		},
		{
			"id": "ACME-2026-005",
			"summary": "Four-part version range",
			"affected": [{
				"package": {"purl": "pkg:nuget/Foo.Bar"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.5.0.0"}, {"fixed": "1.5.0.2"}]}]
			}]
		},
		{
			"id": "ACME-2026-006",
			"summary": "All versions via introduced 0 matches versionless PURL",
			"affected": [{
				"package": {"purl": "pkg:golang/example.com/internal"},
				"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
			}]
		}
	]`

	idx, err := Parse([]byte(doc), "test.json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	purls := []string{
		"pkg:npm/express@4.18.2",                 // matches ACME-2026-002
		"pkg:npm/express@4.19.0",                 // fixed
		"pkg:pypi/urllib3@2.32.0rc1",             // pre-release < 2.32.0 -> matches ACME-2026-003
		"pkg:pypi/urllib3@2.32.0",                // fixed
		"pkg:maven/org.example/core@1.5.0.Final", // < 1.5.1.Final -> matches ACME-2026-004
		"pkg:nuget/Foo.Bar@1.5.0.1",              // between 1.5.0.0 and 1.5.0.2 -> matches ACME-2026-005
		"pkg:golang/example.com/internal",        // versionless with introduced:0 -> matches ACME-2026-006
		"pkg:npm/express",                        // versionless with bounded range -> must not match
	}

	findings := idx.Match(purls)
	got := make(map[string]string, len(findings))
	for _, f := range findings {
		got[f.Entry.ID] = f.PURL
	}

	want := map[string]string{
		"ACME-2026-002": "pkg:npm/express@4.18.2",
		"ACME-2026-003": "pkg:pypi/urllib3@2.32.0rc1",
		"ACME-2026-004": "pkg:maven/org.example/core@1.5.0.Final",
		"ACME-2026-005": "pkg:nuget/Foo.Bar@1.5.0.1",
		"ACME-2026-006": "pkg:golang/example.com/internal",
	}
	if len(got) != len(want) {
		t.Fatalf("matched %v, want %v", got, want)
	}
	for id, purl := range want {
		if got[id] != purl {
			t.Errorf("finding %s PURL = %q, want %q", id, got[id], purl)
		}
	}
}
