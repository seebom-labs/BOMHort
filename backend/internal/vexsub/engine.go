package vexsub

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// Engine coordinates fetching and normalizing VEX statements from all configured upstream sources.
type Engine struct {
	Client *http.Client
}

// NewEngine creates an Engine with a sensible default HTTP timeout.
func NewEngine() *Engine {
	return &Engine{
		Client: &http.Client{Timeout: defaultHTTPTimeout},
	}
}

type knownPURLIndex struct {
	exact  map[string]struct{}
	byCore map[string][]ParsedPURL
}

func buildKnownPURLIndex(knownPURLs []string) knownPURLIndex {
	idx := knownPURLIndex{
		exact:  make(map[string]struct{}, len(knownPURLs)),
		byCore: make(map[string][]ParsedPURL),
	}
	seenParsed := make(map[string]struct{}, len(knownPURLs))
	for _, raw := range knownPURLs {
		if raw == "" {
			continue
		}
		idx.exact[raw] = struct{}{}
		if parsed, ok := ParsePURL(raw); ok {
			if _, dup := seenParsed[raw]; !dup {
				seenParsed[raw] = struct{}{}
				core := parsed.Core()
				idx.byCore[core] = append(idx.byCore[core], parsed)
			}
		}
	}
	return idx
}

func (idx knownPURLIndex) expandMatches(stmtPURL string) []string {
	if stmtPURL == "" || stmtPURL == "*" {
		return nil
	}
	if _, exactHit := idx.exact[stmtPURL]; exactHit {
		// Exact match still preserves any additional SBOM PURLs with extra qualifiers
		// that match the parsed statement PURL.
		parsedStmt, ok := ParsePURL(stmtPURL)
		if !ok {
			return []string{stmtPURL}
		}
		out := []string{stmtPURL}
		seen := map[string]struct{}{stmtPURL: {}}
		for _, candidate := range idx.byCore[parsedStmt.Core()] {
			if _, dup := seen[candidate.Raw]; dup {
				continue
			}
			if parsedStmt.Matches(candidate) {
				seen[candidate.Raw] = struct{}{}
				out = append(out, candidate.Raw)
			}
		}
		return out
	}

	parsedStmt, ok := ParsePURL(stmtPURL)
	if !ok {
		return nil
	}
	var out []string
	for _, candidate := range idx.byCore[parsedStmt.Core()] {
		if parsedStmt.Matches(candidate) {
			out = append(out, candidate.Raw)
		}
	}
	return out
}

// Pull fetches upstream VEX statements from all configured sources and binds
// each matched statement onto the concrete known PURLs present in ClickHouse.
func (e *Engine) Pull(ctx context.Context, sources []config.VEXSourceConfig, knownPURLs []string) (PullResult, error) {
	if len(sources) == 0 || len(knownPURLs) == 0 {
		return PullResult{Complete: true}, nil
	}

	purlIdx := buildKnownPURLIndex(knownPURLs)

	var allMatched []models.VEXStatement
	var errs []error
	allComplete := true

	type dedupKey struct {
		docID       string
		vulnID      string
		productPURL string
		status      string
	}
	seen := make(map[dedupKey]struct{})

	for _, src := range sources {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			allComplete = false
			break
		}

		var res SourceResult
		var err error

		switch src.Type {
		case SourceTypeOpenVEXHub:
			res, err = FetchOpenVEXHub(ctx, e.Client, src.URL, knownPURLs)
		case SourceTypeCSAFProvider:
			res, err = FetchCSAFProvider(ctx, e.Client, src.URL, knownPURLs)
		case SourceTypeOCIReferrers:
			res, err = FetchOCIReferrers(ctx, e.Client, src.URL, knownPURLs)
		default:
			log.Printf("  WARNING: unknown VEX source type %q (skipping)", src.Type)
			continue
		}

		if err != nil {
			log.Printf("  WARNING: upstream VEX pull from %s (%s) failed: %v", src.Type, src.URL, err)
			errs = append(errs, err)
			allComplete = false
			continue
		}
		if !res.Complete {
			allComplete = false
		}

		for _, s := range res.Statements {
			stampUpstream(&s, src.URL)
			matchedPURLs := purlIdx.expandMatches(s.ProductPURL)
			for _, concretePURL := range matchedPURLs {
				bound := s
				bound.ProductPURL = concretePURL
				key := dedupKey{
					docID:       bound.DocumentID,
					vulnID:      bound.VulnID,
					productPURL: bound.ProductPURL,
					status:      bound.Status,
				}
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				allMatched = append(allMatched, bound)
			}
		}
	}

	if len(errs) > 0 && len(allMatched) == 0 {
		return PullResult{}, errors.Join(errs...)
	}
	return PullResult{
		Statements: allMatched,
		Complete:   allComplete && len(errs) == 0,
	}, nil
}
