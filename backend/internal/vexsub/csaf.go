package vexsub

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

const maxCSAFDocsPerSync = 500

// CSAFDocument represents the CSAF 2.0 VEX schema subset needed for statement extraction.
type CSAFDocument struct {
	Document struct {
		CSAFVersion string `json:"csaf_version"`
		Category    string `json:"category"`
		Title       string `json:"title"`
		Publisher   struct {
			Name string `json:"name"`
		} `json:"publisher"`
		Tracking struct {
			ID                 string `json:"id"`
			Status             string `json:"status"`
			InitialReleaseDate string `json:"initial_release_date"`
			CurrentReleaseDate string `json:"current_release_date"`
		} `json:"tracking"`
	} `json:"document"`
	ProductTree struct {
		FullProductNames []CSAFProduct      `json:"full_product_names"`
		Branches         []CSAFBranch       `json:"branches"`
		Relationships    []CSAFRelationship `json:"relationships"`
		ProductGroups    []CSAFProductGroup `json:"product_groups"`
	} `json:"product_tree"`
	Vulnerabilities []CSAFVulnerability `json:"vulnerabilities"`
}

// CSAFProduct maps a CSAF product ID to its identification helpers.
type CSAFProduct struct {
	Name                        string                   `json:"name"`
	ProductID                   string                   `json:"product_id"`
	ProductIdentificationHelper CSAFIdentificationHelper `json:"product_identification_helper"`
}

// CSAFIdentificationHelper carries PURL and CPE identifiers on a CSAF product.
type CSAFIdentificationHelper struct {
	PURL string `json:"purl"`
	CPE  string `json:"cpe"`
}

// CSAFBranch models nested category/name branches inside product_tree.
type CSAFBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Product  *CSAFProduct `json:"product,omitempty"`
	Branches []CSAFBranch `json:"branches,omitempty"`
}

// CSAFRelationship models relationships between product entries in product_tree.
type CSAFRelationship struct {
	Category                  string      `json:"category"`
	ProductReference          string      `json:"product_reference"`
	RelatesToProductReference string      `json:"relates_to_product_reference"`
	FullProductName           CSAFProduct `json:"full_product_name"`
}

// CSAFProductGroup groups product IDs so flags/threats/remediations can target group_ids.
type CSAFProductGroup struct {
	GroupID    string   `json:"group_id"`
	Summary    string   `json:"summary"`
	ProductIDs []string `json:"product_ids"`
}

// CSAFVulnerability models a single vulnerability section in CSAF 2.0.
type CSAFVulnerability struct {
	CVE           string            `json:"cve"`
	IDs           []CSAFVulnID      `json:"ids"`
	ProductStatus CSAFProductStatus `json:"product_status"`
	Flags         []CSAFFlag        `json:"flags"`
	Threats       []CSAFThreat      `json:"threats"`
	Remediations  []CSAFRemediation `json:"remediations"`
}

// CSAFVulnID models non-CVE advisory identifiers under vulnerabilities[].ids[].
type CSAFVulnID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

// CSAFProductStatus holds affected/fixed/not-affected product ID lists.
type CSAFProductStatus struct {
	KnownAffected      []string `json:"known_affected"`
	KnownNotAffected   []string `json:"known_not_affected"`
	Fixed              []string `json:"fixed"`
	UnderInvestigation []string `json:"under_investigation"`
}

// CSAFFlag carries machine-readable justifications on non-affected products.
type CSAFFlag struct {
	Label      string   `json:"label"`
	ProductIDs []string `json:"product_ids"`
	GroupIDs   []string `json:"group_ids"`
}

// CSAFThreat carries CSAF impact statements and threat metadata.
type CSAFThreat struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
	GroupIDs   []string `json:"group_ids"`
}

// CSAFRemediation carries CSAF action statements for remediations.
type CSAFRemediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
	GroupIDs   []string `json:"group_ids"`
}

// CSAFProviderMetadata represents an OASIS CSAF 2.0 provider-metadata.json document.
type CSAFProviderMetadata struct {
	Distributions []struct {
		DirectoryURL string `json:"directory_url"`
		ROLIE        struct {
			Feeds []struct {
				Summary string `json:"summary"`
				URL     string `json:"url"`
				FeedURL string `json:"feed_url"` // non-standard alias kept for compatibility
			} `json:"feeds"`
		} `json:"rolie"`
	} `json:"distributions"`
}

// ROLIEFeed represents the RFC 8322 JSON feed document.
type ROLIEFeed struct {
	Feed struct {
		Entry []ROLIEEntry `json:"entry"`
	} `json:"feed"`
}

// ROLIELink holds a single RFC 8322 entry link.
type ROLIELink struct {
	Rel  string `json:"rel"`
	Type string `json:"type"`
	Href string `json:"href"`
}

// ROLIEEntry holds a single advisory entry inside a ROLIE feed.
type ROLIEEntry struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Updated   string `json:"updated"`
	Published string `json:"published"`
	Content   struct {
		Type string `json:"type"`
		Src  string `json:"src"`
	} `json:"content"`
	Link []ROLIELink `json:"link"`
}

// ParseCSAF parses a CSAF 2.0 JSON document into OpenVEX VEXStatement records.
func ParseCSAF(r io.Reader, sourceURL string) ([]models.VEXStatement, error) {
	data, err := readBounded(r, maxVEXDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf("reading CSAF input: %w", err)
	}

	var doc CSAFDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decoding CSAF 2.0: %w", err)
	}

	if doc.Document.CSAFVersion == "" && len(doc.Vulnerabilities) == 0 && len(doc.ProductTree.FullProductNames) == 0 {
		return nil, fmt.Errorf("not a valid CSAF document")
	}

	productPURLs := collectCSAFProductPURLs(doc)
	productGroups := make(map[string][]string, len(doc.ProductTree.ProductGroups))
	for _, g := range doc.ProductTree.ProductGroups {
		if g.GroupID != "" && len(g.ProductIDs) > 0 {
			productGroups[g.GroupID] = g.ProductIDs
		}
	}

	now := time.Now().UTC()
	ts := parseCSAFTimestamp(doc.Document.Tracking.CurrentReleaseDate, doc.Document.Tracking.InitialReleaseDate, now)

	docID := strings.TrimSpace(doc.Document.Tracking.ID)
	if docID == "" {
		docID = sourceURL
	}
	author := strings.TrimSpace(doc.Document.Publisher.Name)
	if author == "" {
		author = "upstream-csaf"
	}

	var stmts []models.VEXStatement
	for _, v := range doc.Vulnerabilities {
		vulnID := extractCSAFVulnID(v)
		if vulnID == "" {
			continue
		}

		justByPID := make(map[string]string)
		for _, flag := range v.Flags {
			just := mapCSAFFlagToJustification(flag.Label)
			if just == "" {
				continue
			}
			for _, pid := range expandCSAFTargets(flag.ProductIDs, flag.GroupIDs, productGroups) {
				if justByPID[pid] == "" {
					justByPID[pid] = just
				}
			}
		}

		impactByPID := make(map[string]string)
		for _, threat := range v.Threats {
			if threat.Category != "impact" || strings.TrimSpace(threat.Details) == "" {
				continue
			}
			for _, pid := range expandCSAFTargets(threat.ProductIDs, threat.GroupIDs, productGroups) {
				if impactByPID[pid] == "" {
					impactByPID[pid] = strings.TrimSpace(threat.Details)
				}
			}
		}

		actionByPID := make(map[string]string)
		for _, rem := range v.Remediations {
			if strings.TrimSpace(rem.Details) == "" {
				continue
			}
			for _, pid := range expandCSAFTargets(rem.ProductIDs, rem.GroupIDs, productGroups) {
				if actionByPID[pid] == "" {
					actionByPID[pid] = strings.TrimSpace(rem.Details)
				}
			}
		}

		emit := func(pids []string, status string) {
			seenPID := make(map[string]struct{}, len(pids))
			for _, pid := range pids {
				if _, dup := seenPID[pid]; dup {
					continue
				}
				seenPID[pid] = struct{}{}

				purl := productPURLs[pid]
				if purl == "" {
					continue
				}
				stmt := models.VEXStatement{
					IngestedAt:      now,
					VEXID:           uuid.New(),
					DocumentID:      docID,
					SourceFile:      sourceURL,
					ProductPURL:     purl,
					VulnID:          vulnID,
					Status:          status,
					VEXTimestamp:    ts,
					Author:          author,
					Role:            models.VEXRoleUpstream,
					Tooling:         sourceURL,
					ImpactStatement: impactByPID[pid],
					ActionStatement: actionByPID[pid],
				}
				if status == models.VEXStatusNotAffected {
					stmt.Justification = justByPID[pid]
				}
				stmts = append(stmts, stmt)
			}
		}

		emit(v.ProductStatus.KnownNotAffected, models.VEXStatusNotAffected)
		emit(v.ProductStatus.KnownAffected, models.VEXStatusAffected)
		emit(v.ProductStatus.Fixed, models.VEXStatusFixed)
		emit(v.ProductStatus.UnderInvestigation, models.VEXStatusUnderInvestigation)
	}

	return stmts, nil
}

func collectCSAFProductPURLs(doc CSAFDocument) map[string]string {
	productPURLs := make(map[string]string)
	for _, p := range doc.ProductTree.FullProductNames {
		if p.ProductID != "" && p.ProductIdentificationHelper.PURL != "" {
			productPURLs[p.ProductID] = p.ProductIdentificationHelper.PURL
		}
	}
	walkBranches(doc.ProductTree.Branches, productPURLs)
	for _, rel := range doc.ProductTree.Relationships {
		pid := rel.FullProductName.ProductID
		if pid == "" {
			continue
		}
		if purl := rel.FullProductName.ProductIdentificationHelper.PURL; purl != "" {
			productPURLs[pid] = purl
		} else if purl := productPURLs[rel.ProductReference]; purl != "" && productPURLs[pid] == "" {
			productPURLs[pid] = purl
		}
	}
	return productPURLs
}

func expandCSAFTargets(productIDs, groupIDs []string, groups map[string][]string) []string {
	out := make([]string, 0, len(productIDs))
	out = append(out, productIDs...)
	for _, gid := range groupIDs {
		out = append(out, groups[gid]...)
	}
	return out
}

func extractCSAFVulnID(v CSAFVulnerability) string {
	if cve := strings.TrimSpace(v.CVE); cve != "" {
		return normalizeVulnID(cve)
	}
	fallback := ""
	for _, id := range v.IDs {
		norm := normalizeVulnID(id.Text)
		if norm == "" {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(norm), "CVE-") {
			return norm
		}
		if fallback == "" {
			fallback = norm
		}
	}
	return fallback
}

func parseCSAFTimestamp(primary, secondary string, fallback time.Time) time.Time {
	for _, raw := range []string{primary, secondary} {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
			if parsed, err := time.Parse(layout, raw); err == nil {
				return parsed.UTC()
			}
		}
	}
	return fallback
}

func walkBranches(branches []CSAFBranch, result map[string]string) {
	for _, b := range branches {
		if b.Product != nil && b.Product.ProductID != "" && b.Product.ProductIdentificationHelper.PURL != "" {
			result[b.Product.ProductID] = b.Product.ProductIdentificationHelper.PURL
		}
		if len(b.Branches) > 0 {
			walkBranches(b.Branches, result)
		}
	}
}

// mapCSAFFlagToJustification maps CSAF 2.0 flag labels to OpenVEX justification codes.
func mapCSAFFlagToJustification(label string) string {
	switch strings.TrimSpace(label) {
	case "component_not_present":
		return models.VEXJustificationComponentNotPresent
	case "vulnerable_code_not_present":
		return models.VEXJustificationVulnerableCodeNotPresent
	case "vulnerable_code_not_in_execute_path":
		return models.VEXJustificationVulnerableCodeNotInExecutePath
	case "vulnerable_code_cannot_be_controlled_by_adversary":
		return models.VEXJustificationVulnerableCodeCannotBeControlled
	case "inline_mitigations_already_exist":
		return models.VEXJustificationInlineMitigationsExist
	default:
		return ""
	}
}

// FetchCSAFProvider fetches and parses CSAF documents from a provider URL or local path.
func FetchCSAFProvider(ctx context.Context, client *http.Client, sourceURL string, _ []string) (SourceResult, error) {
	if !strings.HasPrefix(sourceURL, "http://") && !strings.HasPrefix(sourceURL, "https://") {
		localPath, _ := resolveLocalPath(sourceURL)
		return readLocalCSAF(localPath, sourceURL)
	}

	client = ensureHTTPClient(client)
	body, _, err := fetchBytes(ctx, client, sourceURL, map[string]string{"Accept": "application/json"})
	if err != nil {
		return SourceResult{}, fmt.Errorf("fetching CSAF source %s: %w", sourceURL, err)
	}

	var doc CSAFDocument
	if err := json.Unmarshal(body, &doc); err == nil && (doc.Document.CSAFVersion != "" || len(doc.Vulnerabilities) > 0) {
		stmts, err := ParseCSAF(bytes.NewReader(body), sourceURL)
		if err != nil {
			return SourceResult{}, err
		}
		return SourceResult{Statements: stmts, Complete: true}, nil
	}

	var meta CSAFProviderMetadata
	if err := json.Unmarshal(body, &meta); err == nil && len(meta.Distributions) > 0 {
		return fetchFromProviderMetadata(ctx, client, sourceURL, meta)
	}

	var rolie ROLIEFeed
	if err := json.Unmarshal(body, &rolie); err == nil && len(rolie.Feed.Entry) > 0 {
		return fetchFromROLIE(ctx, client, sourceURL, rolie)
	}

	return SourceResult{Complete: true}, nil
}

func readLocalCSAF(path, sourceURL string) (SourceResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return SourceResult{}, fmt.Errorf("stat local CSAF %s: %w", path, err)
	}
	if !info.IsDir() {
		f, err := os.Open(path)
		if err != nil {
			return SourceResult{}, fmt.Errorf("opening CSAF file %s: %w", path, err)
		}
		defer f.Close()
		stmts, err := ParseCSAF(f, sourceURL)
		if err != nil {
			return SourceResult{}, err
		}
		return SourceResult{Statements: stmts, Complete: true}, nil
	}

	var all []models.VEXStatement
	hasErrors := false
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			hasErrors = true
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			hasErrors = true
			return err
		}
		defer f.Close()
		stmts, err := ParseCSAF(f, sourceURL)
		if err == nil {
			all = append(all, stmts...)
		} else {
			hasErrors = true
		}
		return nil
	})
	if err != nil {
		return SourceResult{}, err
	}
	return SourceResult{Statements: all, Complete: !hasErrors}, nil
}

func fetchFromProviderMetadata(ctx context.Context, client *http.Client, base string, meta CSAFProviderMetadata) (SourceResult, error) {
	var all []models.VEXStatement
	var errs []error
	succeeded := 0
	allComplete := true

	for _, dist := range meta.Distributions {
		if len(dist.ROLIE.Feeds) > 0 {
			for _, feed := range dist.ROLIE.Feeds {
				feedRef := strings.TrimSpace(feed.URL)
				if feedRef == "" {
					feedRef = strings.TrimSpace(feed.FeedURL)
				}
				if feedRef == "" {
					continue
				}
				feedURL := resolveURL(base, feedRef)
				body, _, err := fetchBytes(ctx, client, feedURL, map[string]string{"Accept": "application/json"})
				if err != nil {
					errs = append(errs, err)
					allComplete = false
					continue
				}
				var rolie ROLIEFeed
				if err := json.Unmarshal(body, &rolie); err != nil {
					errs = append(errs, fmt.Errorf("decoding ROLIE feed %s: %w", feedURL, err))
					allComplete = false
					continue
				}
				res, err := fetchFromROLIE(ctx, client, feedURL, rolie)
				if err != nil {
					errs = append(errs, err)
					allComplete = false
					continue
				}
				if !res.Complete {
					allComplete = false
				}
				succeeded++
				all = append(all, res.Statements...)
			}
			continue
		}

		if dirRef := strings.TrimSpace(dist.DirectoryURL); dirRef != "" {
			dirURL := resolveURL(base, dirRef)
			res, err := fetchFromCSAFDirectory(ctx, client, dirURL)
			if err != nil {
				errs = append(errs, err)
				allComplete = false
				continue
			}
			if !res.Complete {
				allComplete = false
			}
			succeeded++
			all = append(all, res.Statements...)
		}
	}

	if succeeded == 0 && len(errs) > 0 {
		return SourceResult{}, errors.Join(errs...)
	}
	return SourceResult{
		Statements: all,
		Complete:   allComplete && len(errs) == 0 && succeeded > 0,
	}, nil
}

func fetchFromCSAFDirectory(ctx context.Context, client *http.Client, dirURL string) (SourceResult, error) {
	changesURL := joinBaseURL(dirURL, "changes.csv")
	body, _, err := fetchBytes(ctx, client, changesURL, nil)
	if err != nil {
		return SourceResult{}, err
	}

	r := csv.NewReader(bytes.NewReader(body))
	var docURLs []string
	seen := make(map[string]struct{})
	capped := false
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return SourceResult{}, fmt.Errorf("reading %s: %w", changesURL, err)
		}
		if len(rec) == 0 {
			continue
		}
		rel := strings.TrimSpace(rec[0])
		if !strings.HasSuffix(strings.ToLower(rel), ".json") {
			continue
		}
		u := joinBaseURL(dirURL, rel)
		if _, dup := seen[u]; dup {
			continue
		}
		seen[u] = struct{}{}
		docURLs = append(docURLs, u)
		if len(docURLs) >= maxCSAFDocsPerSync {
			capped = true
			break
		}
	}

	stmts, hasErrors, err := fetchCSAFDocumentsConcurrently(ctx, client, dirURL, docURLs)
	if err != nil {
		return SourceResult{}, err
	}
	return SourceResult{
		Statements: stmts,
		Complete:   !capped && !hasErrors,
	}, nil
}

func fetchFromROLIE(ctx context.Context, client *http.Client, base string, rolie ROLIEFeed) (SourceResult, error) {
	var docURLs []string
	seen := make(map[string]struct{})
	capped := false

	for _, entry := range rolie.Feed.Entry {
		entryURL := pickROLIEEntryURL(base, entry)
		if entryURL == "" {
			continue
		}
		if _, dup := seen[entryURL]; dup {
			continue
		}
		seen[entryURL] = struct{}{}
		docURLs = append(docURLs, entryURL)
		if len(docURLs) >= maxCSAFDocsPerSync {
			capped = true
			break
		}
	}

	stmts, hasErrors, err := fetchCSAFDocumentsConcurrently(ctx, client, base, docURLs)
	if err != nil {
		return SourceResult{}, err
	}
	return SourceResult{
		Statements: stmts,
		Complete:   !capped && !hasErrors,
	}, nil
}

func pickROLIEEntryURL(base string, entry ROLIEEntry) string {
	if src := strings.TrimSpace(entry.Content.Src); src != "" && !isNonAdvisoryArtifact(src) {
		return resolveURL(base, src)
	}
	fallback := ""
	for _, l := range entry.Link {
		href := strings.TrimSpace(l.Href)
		if href == "" || isNonAdvisoryArtifact(href) {
			continue
		}
		resolved := resolveURL(base, href)
		if strings.EqualFold(l.Rel, "self") || strings.Contains(strings.ToLower(l.Type), "json") || strings.HasSuffix(strings.ToLower(href), ".json") {
			return resolved
		}
		if fallback == "" {
			fallback = resolved
		}
	}
	return fallback
}

func isNonAdvisoryArtifact(href string) bool {
	lower := strings.ToLower(strings.TrimSpace(href))
	for _, ext := range []string{".sha256", ".sha512", ".asc", ".minisig", ".sig", ".csv"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func fetchCSAFDocumentsConcurrently(ctx context.Context, client *http.Client, sourceURL string, docURLs []string) ([]models.VEXStatement, bool, error) {
	if len(docURLs) == 0 {
		return nil, false, nil
	}

	workers := maxConcurrentFetches
	if len(docURLs) < workers {
		workers = len(docURLs)
	}

	jobs := make(chan string, len(docURLs))
	for _, u := range docURLs {
		jobs <- u
	}
	close(jobs)

	type result struct {
		stmts []models.VEXStatement
		err   error
	}
	results := make([]result, 0, len(docURLs))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for docURL := range jobs {
				if ctx.Err() != nil {
					return
				}
				body, _, err := fetchBytes(ctx, client, docURL, map[string]string{"Accept": "application/json"})
				if err != nil {
					mu.Lock()
					results = append(results, result{err: err})
					mu.Unlock()
					continue
				}
				stmts, err := ParseCSAF(bytes.NewReader(body), sourceURL)
				mu.Lock()
				results = append(results, result{stmts: stmts, err: err})
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}

	var all []models.VEXStatement
	var firstErr error
	succeeded := 0
	hasErrors := false
	for _, r := range results {
		if r.err != nil {
			hasErrors = true
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		succeeded++
		all = append(all, r.stmts...)
	}
	if succeeded == 0 && firstErr != nil {
		return nil, false, firstErr
	}
	return all, hasErrors, nil
}

func normalizeVulnID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	if idx := strings.LastIndex(id, "/"); idx >= 0 {
		id = id[idx+1:]
	}
	return id
}
