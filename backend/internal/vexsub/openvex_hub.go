package vexsub

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/goccy/go-json"
	"github.com/seebom-labs/bomhort/backend/internal/vex"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

const maxHubDocsPerSync = 500

type vexHubIndex struct {
	Packages []struct {
		ID       string `json:"id"`
		PURL     string `json:"purl"`
		Location string `json:"location"`
	} `json:"packages"`
}

// FetchOpenVEXHub fetches and parses OpenVEX documents from a local directory,
// an HTTP OpenVEX hub with index.json (aquasecurity/vexhub spec), or legacy
// PURL-layout HTTP paths.
func FetchOpenVEXHub(ctx context.Context, client *http.Client, sourceURL string, knownPURLs []string) (SourceResult, error) {
	if !strings.HasPrefix(sourceURL, "http://") && !strings.HasPrefix(sourceURL, "https://") {
		localPath, _ := resolveLocalPath(sourceURL)
		return readLocalOpenVEX(localPath, sourceURL)
	}

	client = ensureHTTPClient(client)

	// Fast path: check index.json at the hub root first so large PURL sets do
	// not trigger tens of thousands of 404 probes.
	indexURL := joinBaseURL(sourceURL, "index.json")
	if docURLs, ok, capped, err := fetchHubIndexURLs(ctx, client, sourceURL, indexURL, knownPURLs); err != nil {
		return SourceResult{}, err
	} else if ok {
		stmts, hasErrors, err := fetchOpenVEXDocumentsConcurrently(ctx, client, sourceURL, docURLs)
		if err != nil {
			return SourceResult{}, err
		}
		return SourceResult{
			Statements: stmts,
			Complete:   !capped && !hasErrors,
		}, nil
	}

	if len(knownPURLs) == 0 {
		return SourceResult{Complete: true}, nil
	}

	candidateSet := make(map[string]struct{})
	var candidateURLs []string
	seenPURLKeys := make(map[string]struct{})

	for _, rawPURL := range knownPURLs {
		key := dedupeHubLookupKey(rawPURL)
		if key == "" {
			continue
		}
		if _, seen := seenPURLKeys[key]; seen {
			continue
		}
		seenPURLKeys[key] = struct{}{}

		for _, u := range candidatePURLPaths(sourceURL, rawPURL) {
			if _, exists := candidateSet[u]; !exists {
				candidateSet[u] = struct{}{}
				candidateURLs = append(candidateURLs, u)
			}
		}
	}

	stmts, hasErrors, err := fetchOpenVEXDocumentsConcurrently(ctx, client, sourceURL, candidateURLs)
	if err != nil {
		return SourceResult{}, err
	}
	return SourceResult{
		Statements: stmts,
		Complete:   !hasErrors,
	}, nil
}

func fetchHubIndexURLs(ctx context.Context, client *http.Client, baseURL, indexURL string, knownPURLs []string) ([]string, bool, bool, error) {
	body, _, err := fetchBytes(ctx, client, indexURL, map[string]string{"Accept": "application/json"})
	if err != nil {
		var he *httpError
		if errors.As(err, &he) && (he.StatusCode == http.StatusNotFound || he.StatusCode == http.StatusMethodNotAllowed) {
			return nil, false, false, nil
		}
		// Some test/legacy servers serve a generic 404/400/3xx or non-index on unknown paths;
		// only surface 5xx or transport errors when probing fails completely.
		return nil, false, false, nil
	}

	var idx vexHubIndex
	if err := json.Unmarshal(body, &idx); err != nil || len(idx.Packages) == 0 {
		return nil, false, false, nil
	}

	knownByCore := make(map[string][]ParsedPURL, len(knownPURLs))
	knownExact := make(map[string]struct{}, len(knownPURLs))
	for _, raw := range knownPURLs {
		knownExact[raw] = struct{}{}
		if p, ok := ParsePURL(raw); ok {
			core := p.Core()
			knownByCore[core] = append(knownByCore[core], p)
		}
	}

	seen := make(map[string]struct{})
	var docURLs []string
	capped := false
	for _, entry := range idx.Packages {
		loc := strings.TrimSpace(entry.Location)
		if loc == "" {
			continue
		}
		pkgID := strings.TrimSpace(entry.ID)
		if pkgID == "" {
			pkgID = strings.TrimSpace(entry.PURL)
		}
		if len(knownPURLs) > 0 && pkgID != "" {
			parsedEntry, ok := ParsePURL(pkgID)
			if ok {
				candidates := knownByCore[parsedEntry.Core()]
				if len(candidates) == 0 || !matchesAnyCandidate(parsedEntry, candidates) {
					continue
				}
			} else {
				if _, exists := knownExact[pkgID]; !exists {
					continue
				}
			}
		}
		docURL := joinBaseURL(baseURL, loc)
		if _, dup := seen[docURL]; dup {
			continue
		}
		seen[docURL] = struct{}{}
		docURLs = append(docURLs, docURL)
		if len(docURLs) >= maxHubDocsPerSync {
			capped = true
			break
		}
	}
	return docURLs, true, capped, nil
}

func matchesAnyCandidate(stmt ParsedPURL, candidates []ParsedPURL) bool {
	for _, c := range candidates {
		if stmt.Matches(c) {
			return true
		}
	}
	return false
}

func dedupeHubLookupKey(rawPURL string) string {
	p, ok := ParsePURL(rawPURL)
	if !ok {
		return strings.TrimSpace(rawPURL)
	}
	if p.Version != "" {
		return p.Core() + "@" + p.Version
	}
	return p.Core()
}

func fetchOpenVEXDocumentsConcurrently(ctx context.Context, client *http.Client, sourceURL string, docURLs []string) ([]models.VEXStatement, bool, error) {
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

	type fetchResult struct {
		stmts     []models.VEXStatement
		reachable bool
		err       error
	}
	results := make([]fetchResult, 0, len(docURLs))
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
				stmts, err := fetchSingleOpenVEXURL(ctx, client, docURL, sourceURL)
				if err != nil {
					var he *httpError
					if errors.As(err, &he) && he.StatusCode == http.StatusNotFound {
						mu.Lock()
						results = append(results, fetchResult{reachable: true})
						mu.Unlock()
						continue
					}
					mu.Lock()
					results = append(results, fetchResult{err: err})
					mu.Unlock()
					continue
				}
				mu.Lock()
				results = append(results, fetchResult{stmts: stmts, reachable: true})
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
	anyReachable := false
	hasErrors := false
	for _, r := range results {
		if r.reachable {
			anyReachable = true
		}
		if r.err != nil {
			hasErrors = true
			if firstErr == nil {
				firstErr = r.err
			}
		}
		all = append(all, r.stmts...)
	}
	if !anyReachable && firstErr != nil {
		return nil, false, firstErr
	}
	return all, hasErrors, nil
}

func readLocalOpenVEX(path, sourceURL string) (SourceResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return SourceResult{}, fmt.Errorf("stat local OpenVEX %s: %w", path, err)
	}
	if !info.IsDir() {
		f, err := os.Open(path)
		if err != nil {
			return SourceResult{}, fmt.Errorf("opening OpenVEX file %s: %w", path, err)
		}
		defer f.Close()
		res, err := vex.Parse(f, sourceURL)
		if err != nil {
			return SourceResult{}, fmt.Errorf("parsing OpenVEX file %s: %w", path, err)
		}
		for i := range res.Statements {
			stampUpstream(&res.Statements[i], sourceURL)
		}
		return SourceResult{Statements: res.Statements, Complete: true}, nil
	}

	var all []models.VEXStatement
	hasErrors := false
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			hasErrors = true
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if name == "index.json" || !strings.HasSuffix(name, ".json") {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			hasErrors = true
			return nil
		}
		defer f.Close()

		res, err := vex.Parse(f, sourceURL)
		if err != nil {
			hasErrors = true
			return nil
		}
		for i := range res.Statements {
			stampUpstream(&res.Statements[i], sourceURL)
		}
		all = append(all, res.Statements...)
		return nil
	})
	if err != nil {
		return SourceResult{}, err
	}
	return SourceResult{Statements: all, Complete: !hasErrors}, nil
}

func fetchSingleOpenVEXURL(ctx context.Context, client *http.Client, docURL, sourceURL string) ([]models.VEXStatement, error) {
	body, _, err := fetchBytes(ctx, client, docURL, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, err
	}

	res, err := vex.Parse(bytes.NewReader(body), sourceURL)
	if err != nil {
		return nil, fmt.Errorf("parsing OpenVEX from %s: %w", docURL, err)
	}
	for i := range res.Statements {
		stampUpstream(&res.Statements[i], sourceURL)
	}
	return res.Statements, nil
}

func candidatePURLPaths(base, rawPURL string) []string {
	p, ok := ParsePURL(rawPURL)
	if !ok {
		return nil
	}

	coreRel := strings.TrimPrefix(p.Core(), "pkg:")
	var out []string
	out = append(out,
		joinBaseURL(base, "pkg/"+coreRel+"/vex.openvex.json"),
		joinBaseURL(base, "pkg/"+coreRel+"/vex.json"),
		joinBaseURL(base, "pkg/"+coreRel+".openvex.json"),
	)
	if p.Version != "" {
		verRel := coreRel + "@" + p.Version
		out = append(out,
			joinBaseURL(base, "pkg/"+verRel+"/vex.openvex.json"),
			joinBaseURL(base, "pkg/"+verRel+".openvex.json"),
		)
	}
	out = append(out,
		joinBaseURL(base, ".vex/"+p.Type+"/"+p.Name+".openvex.json"),
		joinBaseURL(base, ".vex/"+p.Name+".openvex.json"),
	)
	return out
}
