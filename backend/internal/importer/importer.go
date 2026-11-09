package importer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Options configures a Run.
type Options struct {
	Source  Source
	Mapping *Mapping
	// Uploader is nil for a dry run: the plan is printed, nothing is sent.
	Uploader Uploader
	// Out receives the plan and the upload results.
	Out io.Writer
}

// Summary counts what a Run did. In a dry run only Projects, VEX and
// Statements are filled: they are what would be uploaded.
type Summary struct {
	Projects   int // SBOMs read from the source
	VEX        int // OpenVEX documents generated
	Statements int // statements in them
	Uploaded   int // documents the instance accepted as new
	Duplicates int // documents it already had
	Failed     int // SBOMs that could not be read or uploaded
}

// Run imports every SBOM of the source. A failure on one SBOM is reported and
// counted, and the run continues; only failing to list the source is fatal.
func Run(ctx context.Context, opts Options) (Summary, error) {
	var sum Summary
	projects, err := opts.Source.ListProjects(ctx)
	if err != nil {
		return sum, fmt.Errorf("list source: %w", err)
	}
	out := opts.Out
	if out == nil {
		out = io.Discard
	}

	for _, p := range projects {
		if err := ctx.Err(); err != nil {
			return sum, err
		}
		sum.Projects++
		project, tags := opts.Mapping.Resolve(p.Name)
		fmt.Fprintf(out, "%s (%s)\n  project: %s, tags: %s\n", p.Name, p.ID, orDefault(project, "from the document"), orDefault(strings.Join(tags, ","), "none"))

		sbom, err := opts.Source.GetSBOM(ctx, p)
		if err != nil {
			sum.Failed++
			fmt.Fprintf(out, "  FAILED: read SBOM: %v\n", err)
			continue
		}
		doc, err := parseCycloneDX(sbom)
		if err != nil {
			sum.Failed++
			fmt.Fprintf(out, "  FAILED: %v\n", err)
			continue
		}
		analyses, notes, err := opts.Source.ListAnalyses(ctx, p)
		if err != nil {
			sum.Failed++
			fmt.Fprintf(out, "  FAILED: read analyses: %v\n", err)
			continue
		}
		vex, vexErr := BuildVEX(doc.SerialNumber, analyses)
		if vexErr != nil && !errors.Is(vexErr, errNoSerial) {
			sum.Failed++
			fmt.Fprintf(out, "  FAILED: build VEX: %v\n", vexErr)
			continue
		}
		notes = append(notes, vex.Notes...)

		fmt.Fprintf(out, "  SBOM: %s\n", p.FileName)
		vexName := vexFileName(p.FileName)
		switch {
		case vexErr != nil:
			fmt.Fprintf(out, "  VEX:  not generated: %v (%d statements)\n", vexErr, vex.Statements())
		case vex.Data == nil:
			fmt.Fprintf(out, "  VEX:  none (no analyses to import)\n")
		default:
			sum.VEX++
			sum.Statements += vex.Statements()
			fmt.Fprintf(out, "  VEX:  %s, %d statements (%s)\n", vexName, vex.Statements(), formatCounts(vex.ByStatus))
		}
		for _, n := range notes {
			fmt.Fprintf(out, "  note: %s\n", n)
		}

		if opts.Uploader == nil {
			continue
		}
		res, err := opts.Uploader.Upload(ctx, Upload{FileName: p.FileName, Data: sbom, Project: project, Tags: tags})
		if err != nil {
			sum.Failed++
			fmt.Fprintf(out, "  FAILED: upload SBOM: %v\n", err)
			continue
		}
		report(out, "SBOM", res, &sum)
		if vex.Data == nil || vexErr != nil {
			continue
		}
		res, err = opts.Uploader.Upload(ctx, Upload{FileName: vexName, Data: vex.Data})
		if err != nil {
			sum.Failed++
			fmt.Fprintf(out, "  FAILED: upload VEX: %v\n", err)
			continue
		}
		report(out, "VEX", res, &sum)
	}
	return sum, nil
}

func report(out io.Writer, kind string, res UploadResult, sum *Summary) {
	if res.Duplicate() {
		sum.Duplicates++
		fmt.Fprintf(out, "  %s already imported\n", kind)
		return
	}
	sum.Uploaded++
	fmt.Fprintf(out, "  %s uploaded (job %s)\n", kind, res.JobID)
}

// vexFileName derives the VEX upload name from the SBOM's, keeping the
// .openvex.json suffix the gateway classifies as VEX.
func vexFileName(sbomName string) string {
	base := sbomName
	lower := strings.ToLower(base)
	for _, suffix := range []string{".cdx.json", ".json"} {
		if strings.HasSuffix(lower, suffix) {
			base = base[:len(base)-len(suffix)]
			break
		}
	}
	return base + ".openvex.json"
}

func formatCounts(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s %d", k, counts[k])
	}
	return strings.Join(parts, ", ")
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
