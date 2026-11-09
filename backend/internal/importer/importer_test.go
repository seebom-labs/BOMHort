package importer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/vex"
)

// fakeGateway dedups by content hash like POST /api/v1/sboms/upload.
type fakeGateway struct {
	mu      sync.Mutex
	seen    map[[32]byte]bool
	uploads []Upload
	fail    func(Upload) error
}

func (g *fakeGateway) Upload(_ context.Context, u Upload) (UploadResult, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fail != nil {
		if err := g.fail(u); err != nil {
			return UploadResult{}, err
		}
	}
	if g.seen == nil {
		g.seen = map[[32]byte]bool{}
	}
	h := sha256.Sum256(u.Data)
	if g.seen[h] {
		return UploadResult{Status: "duplicate"}, nil
	}
	g.seen[h] = true
	g.uploads = append(g.uploads, u)
	return UploadResult{Status: "pending", JobID: fmt.Sprintf("job-%d", len(g.uploads))}, nil
}

// exportDoc is one SBOM of a source export with one suppressed finding.
func exportDoc(i int) string {
	return fmt.Sprintf(`{
  "bomFormat": "CycloneDX", "specVersion": "1.5",
  "serialNumber": "urn:uuid:00000000-0000-4000-8000-%012d",
  "metadata": {"component": {"name": "service-%d", "version": "1.0.0"}},
  "components": [{"bom-ref": "lib", "name": "lib", "purl": "pkg:npm/lib-%d@1.0.0"}],
  "vulnerabilities": [{"id": "CVE-2024-%04d",
    "analysis": {"state": "not_affected", "justification": "code_not_present", "detail": "Reviewed by the security team."},
    "affects": [{"ref": "lib"}]}]
}`, i, i, i, i)
}

// The acceptance case of #536: a directory export of 50 SBOMs with analyses
// lands as 50 SBOMs and 50 VEX documents, suppressed with the original
// justification, and a second run imports nothing.
func TestRun_ImportsDirectoryExportOnce(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 50; i++ {
		writeFile(t, dir, fmt.Sprintf("export/service-%02d.cdx.json", i), exportDoc(i))
	}
	writeFile(t, dir, "mapping.json", `{"tags": ["imported"], "projects": {"service-7": {"project": "seven"}}}`)
	mapping, err := LoadMapping(dir + "/mapping.json")
	if err != nil {
		t.Fatal(err)
	}
	src, err := NewDirSource(dir + "/export")
	if err != nil {
		t.Fatal(err)
	}
	gw := &fakeGateway{}

	sum, err := Run(context.Background(), Options{Source: src, Mapping: mapping, Uploader: gw})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Projects != 50 || sum.VEX != 50 || sum.Uploaded != 100 || sum.Duplicates != 0 || sum.Failed != 0 {
		t.Fatalf("first run: %+v", sum)
	}

	var sboms, vexDocs int
	for _, u := range gw.uploads {
		switch {
		case strings.HasSuffix(u.FileName, ".openvex.json"):
			vexDocs++
			if u.Project != "" || u.Tags != nil {
				t.Errorf("VEX %s carries ownership %q %v", u.FileName, u.Project, u.Tags)
			}
			res, err := vex.Parse(bytes.NewReader(u.Data), u.FileName)
			if err != nil || len(res.Statements) != 1 {
				t.Fatalf("VEX %s: %v", u.FileName, err)
			}
			s := res.Statements[0]
			if s.Status != "not_affected" || s.Justification != "vulnerable_code_not_present" ||
				s.ImpactStatement != "Reviewed by the security team." ||
				!strings.Contains(s.StatusNotes, "justification=code_not_present") {
				t.Errorf("VEX %s statement = %+v", u.FileName, s)
			}
		default:
			sboms++
			if !reflectTags(u.Tags, "imported") {
				t.Errorf("SBOM %s tags = %v", u.FileName, u.Tags)
			}
			if (u.FileName == "service-07.cdx.json") != (u.Project == "seven") {
				t.Errorf("SBOM %s project = %q", u.FileName, u.Project)
			}
		}
	}
	if sboms != 50 || vexDocs != 50 {
		t.Fatalf("uploaded %d SBOMs and %d VEX documents, want 50 and 50", sboms, vexDocs)
	}

	again, err := Run(context.Background(), Options{Source: src, Mapping: mapping, Uploader: gw})
	if err != nil {
		t.Fatal(err)
	}
	if again.Uploaded != 0 || again.Duplicates != 100 {
		t.Errorf("rerun imported something: %+v", again)
	}
}

func TestRun_DryRunUploadsNothing(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.cdx.json", exportDoc(1))
	writeFile(t, dir, "b.cdx.json", `{"bomFormat":"CycloneDX","metadata":{"component":{"name":"b"}},
	  "components":[{"bom-ref":"x","purl":"pkg:npm/x@1"}],
	  "vulnerabilities":[{"id":"CVE-1","analysis":{"state":"resolved"},"affects":[{"ref":"x"}]}]}`)
	src, err := NewDirSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	sum, err := Run(context.Background(), Options{Source: src, Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Projects != 2 || sum.VEX != 1 || sum.Statements != 1 || sum.Uploaded != 0 {
		t.Errorf("dry run: %+v", sum)
	}
	plan := out.String()
	for _, want := range []string{
		"a.openvex.json, 1 statements (not_affected 1)",
		"VEX:  not generated: the SBOM has no serialNumber",
		"project: from the document, tags: none",
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("plan lacks %q:\n%s", want, plan)
		}
	}
}

// A VEX document is only sent once its SBOM was accepted.
func TestRun_FailedSBOMSkipsItsVEX(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.cdx.json", exportDoc(1))
	writeFile(t, dir, "b.cdx.json", exportDoc(2))
	src, err := NewDirSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	gw := &fakeGateway{fail: func(u Upload) error {
		if u.FileName == "a.cdx.json" {
			return errors.New("413 Request Entity Too Large")
		}
		return nil
	}}
	sum, err := Run(context.Background(), Options{Source: src, Uploader: gw})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Failed != 1 || sum.Uploaded != 2 {
		t.Errorf("summary %+v", sum)
	}
	for _, u := range gw.uploads {
		if u.FileName == "a.openvex.json" {
			t.Error("uploaded the VEX of an SBOM that failed")
		}
	}
}

func TestVEXFileName(t *testing.T) {
	for in, want := range map[string]string{
		"app.cdx.json": "app.openvex.json",
		"App.CDX.JSON": "App.openvex.json",
		"bom.json":     "bom.openvex.json",
	} {
		if got := vexFileName(in); got != want {
			t.Errorf("vexFileName(%q) = %q, want %q", in, got, want)
		}
	}
}

func reflectTags(got []string, want ...string) bool {
	return strings.Join(got, ",") == strings.Join(want, ",")
}
