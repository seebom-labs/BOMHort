package license

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCategorize(t *testing.T) {
	tests := []struct {
		input    string
		expected Category
	}{
		{"MIT", CategoryPermissive},
		{"Apache-2.0", CategoryPermissive},
		{"BSD-3-Clause", CategoryPermissive}, // CNCF allowlist
		{"ISC", CategoryPermissive},          // CNCF allowlist
		{"0BSD", CategoryPermissive},         // CNCF allowlist
		{"GPL-3.0-only", CategoryCopyleft},
		{"AGPL-3.0-or-later", CategoryCopyleft},
		{"MPL-2.0", CategoryCopyleft},
		{"MPL-2.0-no-copyleft-exception", CategoryCopyleft},
		{"Apache-2.0-with-LLVM-exception", CategoryPermissive},
		{"NOASSERTION", CategoryUnknown},
		{"NONE", CategoryUnknown},
		{"", CategoryUnknown},
		{"none", CategoryUnknown},
		{"SomeWeirdLicense", CategoryUnapproved},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := Categorize(tt.input)
			if got != tt.expected {
				t.Errorf("Categorize(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	names := []string{"pkg-a", "pkg-b", "pkg-c", "pkg-d"}
	licenses := []string{"MIT", "GPL-3.0-only", "MIT", "NOASSERTION"}

	results := Check(names, licenses)

	if len(results) == 0 {
		t.Fatal("expected non-empty results")
	}

	// Build a map for easier assertion.
	byLicense := make(map[string]Result)
	for _, r := range results {
		byLicense[r.LicenseID] = r
	}

	mitResult, ok := byLicense["MIT"]
	if !ok {
		t.Fatal("expected MIT result")
	}
	if mitResult.PackageCount != 2 {
		t.Errorf("expected 2 MIT packages, got %d", mitResult.PackageCount)
	}
	if mitResult.Category != CategoryPermissive {
		t.Errorf("expected permissive, got %s", mitResult.Category)
	}
	// Permissive licenses should never have non-compliant packages.
	if len(mitResult.NonCompliantPackages) != 0 {
		t.Errorf("expected 0 non-compliant packages for permissive MIT, got %v", mitResult.NonCompliantPackages)
	}

	gplResult, ok := byLicense["GPL-3.0-only"]
	if !ok {
		t.Fatal("expected GPL result")
	}
	if gplResult.PackageCount != 1 {
		t.Errorf("expected 1 GPL package, got %d", gplResult.PackageCount)
	}
	if len(gplResult.NonCompliantPackages) != 1 || gplResult.NonCompliantPackages[0] != "pkg-b" {
		t.Errorf("expected [pkg-b] non-compliant, got %v", gplResult.NonCompliantPackages)
	}
}

func TestCheckWithExceptions_BlanketExempt(t *testing.T) {
	names := []string{"pkg-a", "pkg-b", "pkg-c"}
	licenses := []string{"MIT", "MPL-2.0", "MPL-2.0"}

	ef := &ExceptionsFile{
		BlanketExceptions: []BlanketException{
			{ID: "blanket-mpl", License: "MPL-2.0", Status: "approved", Comment: "MPL ok"},
		},
	}
	idx := BuildIndex(ef)

	results := CheckWithExceptions(names, licenses, idx)
	byLicense := make(map[string]Result)
	for _, r := range results {
		byLicense[r.LicenseID] = r
	}

	mpl := byLicense["MPL-2.0"]
	if mpl.ExemptionReason == "" {
		t.Error("expected blanket exemption reason for MPL-2.0")
	}
	if mpl.PackageCount != 2 {
		t.Errorf("expected 2 MPL packages, got %d", mpl.PackageCount)
	}
	// Blanket exempt: all packages should be in ExemptedPackages, NOT NonCompliantPackages.
	if len(mpl.ExemptedPackages) != 2 {
		t.Errorf("expected 2 exempted packages, got %v", mpl.ExemptedPackages)
	}
	if len(mpl.NonCompliantPackages) != 0 {
		t.Errorf("expected 0 non-compliant packages for blanket-exempted license, got %v", mpl.NonCompliantPackages)
	}
}

func TestCheckWithExceptions_BlanketPrefixMatch(t *testing.T) {
	// MPL-2.0-no-copyleft-exception should be covered by a blanket exception for MPL-2.0.
	names := []string{"pkg-slug"}
	licenses := []string{"MPL-2.0-no-copyleft-exception"}

	ef := &ExceptionsFile{
		BlanketExceptions: []BlanketException{
			{ID: "blanket-mpl", License: "MPL-2.0", Status: "approved", Comment: "MPL ok"},
		},
	}
	idx := BuildIndex(ef)

	results := CheckWithExceptions(names, licenses, idx)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.ExemptionReason == "" {
		t.Error("expected blanket exemption reason for MPL-2.0-no-copyleft-exception via prefix match")
	}
	if len(r.ExemptedPackages) != 1 || r.ExemptedPackages[0] != "pkg-slug" {
		t.Errorf("expected pkg-slug exempted, got %v", r.ExemptedPackages)
	}
	if len(r.NonCompliantPackages) != 0 {
		t.Errorf("expected 0 non-compliant, got %v", r.NonCompliantPackages)
	}
}

func TestCheckWithExceptions_PackageExempt(t *testing.T) {
	names := []string{"pkg-a", "pkg-b"}
	licenses := []string{"GPL-3.0-only", "GPL-3.0-only"}

	ef := &ExceptionsFile{
		Exceptions: []Exception{
			{ID: "exc-1", Package: "pkg-a", License: "GPL-3.0-only", Status: "approved"},
		},
	}
	idx := BuildIndex(ef)

	results := CheckWithExceptions(names, licenses, idx)
	byLicense := make(map[string]Result)
	for _, r := range results {
		byLicense[r.LicenseID] = r
	}

	gpl := byLicense["GPL-3.0-only"]
	if len(gpl.ExemptedPackages) != 1 || gpl.ExemptedPackages[0] != "pkg-a" {
		t.Errorf("expected pkg-a exempted, got %v", gpl.ExemptedPackages)
	}
	if len(gpl.NonCompliantPackages) != 1 || gpl.NonCompliantPackages[0] != "pkg-b" {
		t.Errorf("expected only pkg-b non-compliant, got %v", gpl.NonCompliantPackages)
	}
}

func TestLoadPolicy(t *testing.T) {
	previous := activePolicy
	t.Cleanup(func() {
		policyMu.Lock()
		activePolicy = previous
		policyMu.Unlock()
	})
	policyJSON := `{
		"permissive": ["MIT", "Apache-2.0", "BSD-3-Clause"],
		"copyleft": ["GPL-3.0-only", "AGPL-3.0-only"]
	}`

	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "license-policy.json")
	if err := os.WriteFile(policyPath, []byte(policyJSON), 0644); err != nil {
		t.Fatal(err)
	}

	permCount, copyleftCount, err := LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("LoadPolicy() error: %v", err)
	}
	if permCount != 3 {
		t.Errorf("expected 3 permissive, got %d", permCount)
	}
	if copyleftCount != 2 {
		t.Errorf("expected 2 copyleft, got %d", copyleftCount)
	}

	// After loading, Categorize should reflect the new policy.
	if got := Categorize("MIT"); got != CategoryPermissive {
		t.Errorf("expected MIT=permissive, got %s", got)
	}
	if got := Categorize("GPL-3.0-only"); got != CategoryCopyleft {
		t.Errorf("expected GPL-3.0-only=copyleft, got %s", got)
	}
	// Declared but not listed = unapproved
	if got := Categorize("WTFPL"); got != CategoryUnapproved {
		t.Errorf("expected WTFPL=unapproved, got %s", got)
	}
}

func TestLoadPolicy_MissingFile(t *testing.T) {
	_, _, err := LoadPolicy("/nonexistent/policy.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestGetPolicy(t *testing.T) {
	p := GetPolicy()
	if p == nil {
		t.Fatal("GetPolicy() returned nil")
	}
	// Should have at least some default entries.
	if len(p.Permissive) == 0 && len(p.Copyleft) == 0 {
		t.Error("expected non-empty policy")
	}
}

func TestLoadExceptions(t *testing.T) {
	exceptionsJSON := `{
		"version": "1.0.0",
		"blanketExceptions": [
			{"id": "b1", "license": "MPL-2.0", "status": "approved", "comment": "ok"}
		],
		"exceptions": [
			{"id": "e1", "package": "github.com/foo/bar", "license": "GPL-3.0-only", "status": "approved"}
		]
	}`

	tmpDir := t.TempDir()
	excPath := filepath.Join(tmpDir, "exceptions.json")
	if err := os.WriteFile(excPath, []byte(exceptionsJSON), 0644); err != nil {
		t.Fatal(err)
	}

	idx, err := LoadExceptions(excPath)
	if err != nil {
		t.Fatalf("LoadExceptions() error: %v", err)
	}
	if idx == nil {
		t.Fatal("expected non-nil index")
	}
	if idx.Raw == nil {
		t.Fatal("expected non-nil Raw exceptions file")
	}
	if len(idx.Raw.BlanketExceptions) != 1 {
		t.Errorf("expected 1 blanket exception, got %d", len(idx.Raw.BlanketExceptions))
	}

	// Verify the blanket exception works via CheckWithExceptions.
	results := CheckWithExceptions(
		[]string{"test-pkg"}, []string{"MPL-2.0"}, idx,
	)
	if len(results) == 0 {
		t.Fatal("expected results")
	}
	if results[0].ExemptionReason == "" {
		t.Error("expected blanket exemption to apply for MPL-2.0")
	}
}

func TestLoadExceptions_MissingFile(t *testing.T) {
	_, err := LoadExceptions("/nonexistent/exceptions.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadExceptionsWithFallback_PrimaryPath(t *testing.T) {
	exceptionsJSON := `{
		"version": "1.0.0",
		"blanketExceptions": [
			{"id": "b1", "license": "MPL-2.0", "status": "approved", "comment": "ok"}
		],
		"exceptions": []
	}`
	tmpDir := t.TempDir()
	primary := filepath.Join(tmpDir, "primary.json")
	if err := os.WriteFile(primary, []byte(exceptionsJSON), 0644); err != nil {
		t.Fatal(err)
	}

	idx, err := LoadExceptionsWithFallback(primary, "/nonexistent/fallback.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(idx.Raw.BlanketExceptions) != 1 {
		t.Errorf("expected 1 blanket exception, got %d", len(idx.Raw.BlanketExceptions))
	}
}

func TestLoadExceptionsWithFallback_FallbackPath(t *testing.T) {
	// Only a missing primary permits using the fallback.
	fullJSON := `{
		"version": "1.0.0",
		"blanketExceptions": [
			{"id": "b1", "license": "BSD-3-Clause", "status": "approved", "comment": "ok"}
		],
		"exceptions": []
	}`
	tmpDir := t.TempDir()
	primary := filepath.Join(tmpDir, "primary.json")
	fallback := filepath.Join(tmpDir, "fallback.json")
	if err := os.WriteFile(fallback, []byte(fullJSON), 0644); err != nil {
		t.Fatal(err)
	}

	idx, err := LoadExceptionsWithFallback(primary, fallback)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(idx.Raw.BlanketExceptions) != 1 {
		t.Errorf("expected 1 blanket exception from fallback, got %d", len(idx.Raw.BlanketExceptions))
	}
	if idx.Raw.BlanketExceptions[0].License != "BSD-3-Clause" {
		t.Errorf("expected BSD-3-Clause from fallback, got %s", idx.Raw.BlanketExceptions[0].License)
	}
}

func TestLoadExceptionsWithFallback_AllMissing(t *testing.T) {
	_, err := LoadExceptionsWithFallback("/nonexistent/a.json", "/nonexistent/b.json")
	if err == nil {
		t.Error("expected error when all paths are missing")
	}
}

func TestLoadExceptionsWithFallback_EmptyPaths(t *testing.T) {
	_, err := LoadExceptionsWithFallback("", "")
	if err == nil {
		t.Error("expected error for empty paths")
	}
}

func TestBuildIndex_Empty(t *testing.T) {
	idx := BuildIndex(&ExceptionsFile{})
	if idx == nil {
		t.Fatal("expected non-nil index for empty file")
	}
	// Verify no exemptions apply.
	results := CheckWithExceptions(
		[]string{"pkg"}, []string{"GPL-3.0-only"}, idx,
	)
	for _, r := range results {
		if r.ExemptionReason != "" {
			t.Errorf("expected no exemption, got %q", r.ExemptionReason)
		}
	}
}

func TestCheck_EmptyInput(t *testing.T) {
	results := Check(nil, nil)
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty input, got %d", len(results))
	}
}

func TestCheck_MismatchedLengths(t *testing.T) {
	// If names and licenses have different lengths, should not panic.
	results := Check([]string{"pkg-a"}, []string{})
	// Should handle gracefully (empty or partial results).
	_ = results
}

func TestBuildIndex_AllCNCFProjectsNeverPromotedToBlanket(t *testing.T) {
	// A project label must never remove the package restriction.
	ef := &ExceptionsFile{
		Exceptions: []Exception{
			{
				ID:      "blanket-ebpf-gpl",
				Package: "In-kernel eBPF programs",
				License: "GPL-2.0-only, GPL-2.0-or-later",
				Project: "All CNCF Projects",
				Status:  "approved",
				Comment: "GPL-2.0 permitted for in-kernel eBPF programs",
			},
		},
	}
	idx := BuildIndex(ef)

	// Neither license is exempt for unrelated packages or projects.
	exempt, reason := idx.IsExempt("any-package", "GPL-2.0-only")
	if exempt {
		t.Error("unrelated package must not be exempt")
	}
	if reason != "" {
		t.Error("expected no exemption reason")
	}

	exempt2, _ := idx.IsExempt("another-package", "GPL-2.0-or-later")
	if exempt2 {
		t.Error("unrelated package must not be exempt")
	}

	// Non-listed license should NOT be exempt.
	exempt3, _ := idx.IsExempt("pkg", "GPL-3.0-only")
	if exempt3 {
		t.Error("expected GPL-3.0-only to NOT be exempted")
	}
}

func TestBuildIndex_CompoundLicenseOR(t *testing.T) {
	ef := &ExceptionsFile{
		Exceptions: []Exception{
			{
				ID:      "exc-libpathrs",
				Package: "libpathrs",
				License: "MPL-2.0 OR LGPL-3.0-or-later",
				Project: "*",
				Status:  "approved",
				Comment: "libpathrs blanket exception",
			},
		},
	}
	idx := BuildIndex(ef)

	// Both licenses are exempt only for the named package.
	exempt, _ := idx.IsExempt("libpathrs", "MPL-2.0")
	if !exempt {
		t.Error("expected MPL-2.0 package exception")
	}
	exempt2, _ := idx.IsExempt("libpathrs", "LGPL-3.0-or-later")
	if !exempt2 {
		t.Error("expected LGPL-3.0-or-later package exception")
	}
}

func TestBuildIndex_CompoundLicenseAND(t *testing.T) {
	ef := &ExceptionsFile{
		Exceptions: []Exception{
			{
				ID:      "exc-securejoin",
				Package: "cyphar/filepath-securejoin",
				License: "MPL-2.0 AND BSD-3-Clause",
				Project: "*",
				Status:  "approved",
				Comment: "filepath-securejoin blanket exception",
			},
		},
	}
	idx := BuildIndex(ef)

	// Both licenses are exempt only for the named package.
	exempt, _ := idx.IsExempt("cyphar/filepath-securejoin", "MPL-2.0")
	if !exempt {
		t.Error("expected MPL-2.0 package exception via AND split")
	}
	exempt2, _ := idx.IsExempt("cyphar/filepath-securejoin", "BSD-3-Clause")
	if !exempt2 {
		t.Error("expected BSD-3-Clause package exception via AND split")
	}
}

func TestIsExempt_PathSuffixPackageMatch(t *testing.T) {
	// CNCF exception uses short name, SBOM has full qualified name.
	ef := &ExceptionsFile{
		Exceptions: []Exception{
			{
				ID:      "exc-foo",
				Package: "cyphar/filepath-securejoin",
				License: "MPL-2.0",
				Project: "containerd",
				Status:  "approved",
				Comment: "securejoin exception",
			},
		},
	}
	idx := BuildIndex(ef)

	// Full Go module path matches a complete suffix within the project.
	exempt, reason := idx.IsExempt("github.com/cyphar/filepath-securejoin", "MPL-2.0", "containerd")
	if !exempt {
		t.Error("expected substring match for github.com/cyphar/filepath-securejoin")
	}
	if !strings.Contains(reason, "exc-foo") {
		t.Errorf("expected reason to contain exc-foo, got %s", reason)
	}

	// Exact match should also work.
	exempt2, _ := idx.IsExempt("cyphar/filepath-securejoin", "MPL-2.0", "containerd")
	if !exempt2 {
		t.Error("expected exact match for cyphar/filepath-securejoin")
	}

	// Non-matching package should NOT be exempt.
	exempt3, _ := idx.IsExempt("github.com/other/package", "MPL-2.0", "containerd")
	if exempt3 {
		t.Error("expected non-matching package to NOT be exempt")
	}
}

func TestIsExempt_SubstringPackageAnyLicense(t *testing.T) {
	ef := &ExceptionsFile{
		Exceptions: []Exception{
			{
				ID:      "exc-any",
				Package: "eclipse-ee4j/expressly",
				Status:  "approved",
				Comment: "expressly exception",
			},
		},
	}
	idx := BuildIndex(ef)

	// Substring match on package-only exception (any license).
	exempt, _ := idx.IsExempt("org.eclipse.expressly/eclipse-ee4j/expressly", "EPL-2.0")
	if !exempt {
		t.Error("expected substring match for package-only exception")
	}
}

func TestSplitLicenses(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"MIT", []string{"MIT"}},
		{"GPL-2.0-only, GPL-2.0-or-later", []string{"GPL-2.0-only", "GPL-2.0-or-later"}},
		{"MPL-2.0 OR LGPL-3.0-or-later", []string{"MPL-2.0", "LGPL-3.0-or-later"}},
		{"MPL-2.0 AND BSD-3-Clause", []string{"MPL-2.0", "BSD-3-Clause"}},
		{"", nil},
		{"  Apache-2.0  ", []string{"Apache-2.0"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := splitLicenses(tt.input)
			if len(got) != len(tt.expected) {
				t.Errorf("splitLicenses(%q) = %v, want %v", tt.input, got, tt.expected)
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("splitLicenses(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestCheck_GoTempNamesFiltered(t *testing.T) {
	// Go temp directory names like "tmp.ej9m9OiO2V" should be silently skipped
	// and never appear in non-compliant package lists.
	names := []string{"tmp.ej9m9OiO2V", "real-pkg", "tmp.AbCdEfGhIj"}
	licenses := []string{"GPL-3.0-only", "GPL-3.0-only", "NOASSERTION"}

	results := Check(names, licenses)

	byLicense := make(map[string]Result)
	for _, r := range results {
		byLicense[r.LicenseID] = r
	}

	gpl, ok := byLicense["GPL-3.0-only"]
	if !ok {
		t.Fatal("expected GPL-3.0-only result")
	}
	// Only "real-pkg" should appear; the tmp.* names should be filtered out.
	if gpl.PackageCount != 1 {
		t.Errorf("expected 1 GPL package (tmp names skipped), got %d", gpl.PackageCount)
	}
	if len(gpl.NonCompliantPackages) != 1 || gpl.NonCompliantPackages[0] != "real-pkg" {
		t.Errorf("expected [real-pkg] non-compliant, got %v", gpl.NonCompliantPackages)
	}

	// The NOASSERTION tmp package should be entirely skipped.
	noassert, ok := byLicense["NOASSERTION"]
	if ok && noassert.PackageCount > 0 {
		t.Errorf("expected NOASSERTION tmp package to be filtered, got count=%d", noassert.PackageCount)
	}
}
