package repo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanner_Scan(t *testing.T) {
	// Create a temporary directory with test SPDX, CycloneDX, and VEX files.
	tmpDir := t.TempDir()

	testFiles := map[string]string{
		"test1.spdx.json":   `{"spdxVersion": "SPDX-2.3"}`,
		"test2.spdx.json":   `{"spdxVersion": "SPDX-2.3"}`,
		"test3.cdx.json":    `{"bomFormat": "CycloneDX", "specVersion": "1.5"}`,
		"cve.openvex.json":  `{"@context": "https://openvex.dev/ns/v0.2.0"}`,
		"advisory.vex.json": `{"statements": []}`,
		"not-spdx.txt":      `this should be ignored`,
	}

	for name, content := range testFiles {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0644); err != nil {
			t.Fatalf("failed to write test file %s: %v", name, err)
		}
	}

	scanner := NewScanner(tmpDir)
	files, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() returned error: %v", err)
	}

	// Should find 2 SPDX + 1 CycloneDX + 2 VEX files, not the .txt file.
	if len(files) != 5 {
		t.Errorf("expected 5 files, got %d", len(files))
	}

	sbomCount := 0
	vexCount := 0
	for _, f := range files {
		if f.SHA256Hash == "" {
			t.Errorf("expected non-empty hash for %s", f.RelPath)
		}
		if f.RelPath == "" {
			t.Error("expected non-empty relative path")
		}
		switch f.FileType {
		case "sbom":
			sbomCount++
		case "vex":
			vexCount++
		default:
			t.Errorf("unexpected file type %q for %s", f.FileType, f.RelPath)
		}
	}

	if sbomCount != 3 {
		t.Errorf("expected 3 SBOM files (2 SPDX + 1 CycloneDX), got %d", sbomCount)
	}
	if vexCount != 2 {
		t.Errorf("expected 2 VEX files, got %d", vexCount)
	}
}

func TestScanner_Scan_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	scanner := NewScanner(tmpDir)
	files, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() returned error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

func TestScanner_Scan_NestedDirectories(t *testing.T) {
	tmpDir := t.TempDir()

	// Create nested structure: project/subdir/file.spdx.json
	nestedDir := filepath.Join(tmpDir, "project", "subdir")
	if err := os.MkdirAll(nestedDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nestedDir, "deep.spdx.json"), []byte(`{"spdxVersion":"SPDX-2.3"}`), 0644); err != nil {
		t.Fatal(err)
	}
	// Also a VEX file at the root
	if err := os.WriteFile(filepath.Join(tmpDir, "root.openvex.json"), []byte(`{"@context":"openvex"}`), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(tmpDir)
	files, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(files) != 2 {
		t.Errorf("expected 2 files (nested SBOM + root VEX), got %d", len(files))
	}

	// Verify relative paths include directory structure.
	for _, f := range files {
		if f.RelPath == "" {
			t.Error("expected non-empty relative path")
		}
	}
}

func TestScanner_Scan_SHA256Consistency(t *testing.T) {
	tmpDir := t.TempDir()
	content := `{"spdxVersion": "SPDX-2.3", "name": "hash-test"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "a.spdx.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(tmpDir)
	files1, _ := scanner.Scan()
	files2, _ := scanner.Scan()

	if len(files1) != 1 || len(files2) != 1 {
		t.Fatal("expected 1 file each scan")
	}
	if files1[0].SHA256Hash != files2[0].SHA256Hash {
		t.Error("expected identical hash for same file content")
	}
	if files1[0].SHA256Hash == "" {
		t.Error("expected non-empty hash")
	}
}

func TestScanner_Scan_NonexistentDir(t *testing.T) {
	scanner := NewScanner("/nonexistent/dir/that/does/not/exist")
	_, err := scanner.Scan()
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

func TestScanner_IgnorePrefix(t *testing.T) {
	tmpDir := t.TempDir()

	testFiles := map[string]string{
		"_demo.spdx.json":     `{"spdxVersion": "SPDX-2.3"}`,
		"_example.cdx.json":   `{"bomFormat": "CycloneDX"}`,
		"real-sbom.spdx.json": `{"spdxVersion": "SPDX-2.3"}`,
		"other.json":          `{"spdxVersion": "SPDX-2.3"}`,
	}

	for name, content := range testFiles {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0644); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
	}

	// With ignore prefix "_" — should skip 2 files.
	scanner := NewScannerWithIgnorePrefix(tmpDir, "_")
	files, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("expected 2 files (ignore prefix='_'), got %d", len(files))
		for _, f := range files {
			t.Logf("  found: %s", f.RelPath)
		}
	}

	// Without ignore prefix — should find all 4.
	scanner2 := NewScanner(tmpDir)
	files2, err := scanner2.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(files2) != 4 {
		t.Errorf("expected 4 files (no ignore prefix), got %d", len(files2))
	}

	// Empty string prefix — should find all 4.
	scanner3 := NewScannerWithIgnorePrefix(tmpDir, "")
	files3, err := scanner3.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(files3) != 4 {
		t.Errorf("expected 4 files (empty ignore prefix), got %d", len(files3))
	}
}

func TestScanner_GenericJSON(t *testing.T) {
	tmpDir := t.TempDir()

	// Generic .json files should be classified as "sbom" (format detected at parse time).
	testFiles := map[string]string{
		"unknown-format.json":      `{"some": "json"}`,
		"my-bom.json":             `{"bomFormat": "CycloneDX"}`,
		"project.spdx.json":       `{"spdxVersion": "SPDX-2.3"}`,
		"advisory.openvex.json":   `{"@context": "openvex"}`,
		"not-json.txt":            `plain text`,
		"license-policy.json":     `{"permissive":["MIT"]}`,
		"license-exceptions.json": `{"exceptions":[]}`,
	}

	for name, content := range testFiles {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0644); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
	}

	scanner := NewScanner(tmpDir)
	files, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	// Expected: unknown-format.json (sbom), my-bom.json (sbom), project.spdx.json (sbom), advisory.openvex.json (vex)
	// Excluded: not-json.txt (not .json), license-policy.json, license-exceptions.json (config files)
	if len(files) != 4 {
		t.Errorf("expected 4 files, got %d", len(files))
		for _, f := range files {
			t.Logf("  found: %s (type=%s)", f.RelPath, f.FileType)
		}
	}

	sbomCount := 0
	vexCount := 0
	for _, f := range files {
		switch f.FileType {
		case "sbom":
			sbomCount++
		case "vex":
			vexCount++
		}
	}
	if sbomCount != 3 {
		t.Errorf("expected 3 sbom files, got %d", sbomCount)
	}
	if vexCount != 1 {
		t.Errorf("expected 1 vex file, got %d", vexCount)
	}
}


