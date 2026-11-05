package main

import (
	"context"
	"encoding/csv"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// CSV export of the vulnerability listing (#266, carve-out of #62).
//
// GET /api/v1/reports/vulnerabilities?format=csv[&scope=…]
//
// The rows are exactly those of GET /api/v1/vulnerabilities (same query,
// same scope filter, every finding with its VEX status — there is no
// "effective only" filter there either, so the export and the UI cannot
// disagree). They are streamed from a single ClickHouse cursor straight into
// the response; nothing is accumulated, so an export of hundreds of
// thousands of findings costs the gateway one row of memory.

// vulnerabilityRows is the cursor the handler reads from; satisfied by
// *clickhouse.VulnerabilityCursor.
type vulnerabilityRows interface {
	Next() bool
	Item() dto.VulnerabilityListItem
	Err() error
	Close() error
}

type vulnerabilityStreamFunc func(ctx context.Context, scope string, f clickhouse.VulnFilter) (vulnerabilityRows, error)

// reportFormats are the accepted ?format= values. A whitelist so a future
// "pdf" is an addition, not a rework, and anything else is a clear 400.
var reportFormats = map[string]bool{"csv": true}

// vulnerabilityCSVHeader: cve_id first — the id an auditor's questionnaire
// asks for (#412) — then OSV's id and every other alias.
var vulnerabilityCSVHeader = []string{
	"cve_id", "vuln_id", "aliases", "severity", "purl", "summary",
	"fixed_version", "source_file", "discovered_at",
	"dependency_scope", "dependency_depth", "vex_status",
}

func vulnerabilityCSVRecord(v dto.VulnerabilityListItem) []string {
	depth := ""
	if v.DependencyDepth != nil {
		depth = strconv.FormatUint(uint64(*v.DependencyDepth), 10)
	}
	rec := []string{
		v.CVEID, v.VulnID, strings.Join(v.Aliases, ";"), v.Severity, v.PURL, v.Summary,
		v.FixedVersion, v.SourceFile, v.DiscoveredAt,
		v.DependencyScope, depth, v.VEXStatus,
	}
	for i := range rec {
		rec[i] = csvSafe(rec[i])
	}
	return rec
}

// csvSafe neutralises spreadsheet formula injection (CWE-1236): summaries
// come from OSV and PURLs and file names from uploaded SBOMs, and a cell
// starting with = + - @ (or a tab/CR) is executed as a formula when the
// export is opened in Excel or LibreOffice. A leading apostrophe makes the
// spreadsheet show it as text.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// csvFlushEvery bounds how many rows sit in the csv.Writer buffer before
// they are pushed to the client.
const csvFlushEvery = 500

func vulnerabilityReportHandler(filter vulnFilterFunc, stream vulnerabilityStreamFunc, now func() time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		format := q.Get("format")
		if !reportFormats[format] {
			writeError(w, http.StatusBadRequest, "Invalid format (expected csv)")
			return
		}
		scope, ok := parseScope(q.Get("scope"))
		if !ok {
			writeError(w, http.StatusBadRequest, "Invalid scope (expected direct, transitive, root or unknown)")
			return
		}

		f, status, msg := filter(r)
		if status != 0 {
			writeError(w, status, msg)
			return
		}

		rows, err := stream(r.Context(), scope, f)
		if err != nil {
			log.Printf("ERROR: vulnerability report: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to export vulnerabilities")
			return
		}
		defer rows.Close()

		filename := "bomhort-vulnerabilities-" + now().UTC().Format("2006-01-02") + ".csv"
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)

		cw := csv.NewWriter(w)
		flusher, _ := w.(http.Flusher)
		flush := func() bool {
			cw.Flush()
			if err := cw.Error(); err != nil {
				log.Printf("WARNING: vulnerability report aborted by client: %v", err)
				return false
			}
			if flusher != nil {
				flusher.Flush()
			}
			return true
		}

		if err := cw.Write(vulnerabilityCSVHeader); err != nil {
			log.Printf("WARNING: vulnerability report: %v", err)
			return
		}
		n := 0
		for rows.Next() {
			if err := cw.Write(vulnerabilityCSVRecord(rows.Item())); err != nil {
				log.Printf("WARNING: vulnerability report: %v", err)
				return
			}
			n++
			if n%csvFlushEvery == 0 && !flush() {
				return
			}
		}
		if !flush() {
			return
		}
		// The status line is already sent; a failure now can only truncate
		// the file. Log it — the client sees a short CSV, and a half-written
		// report must not pass silently on the server side either.
		if err := rows.Err(); err != nil {
			log.Printf("ERROR: vulnerability report truncated after %d rows: %v", n, err)
		}
	}
}
