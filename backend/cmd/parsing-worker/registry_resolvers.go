package main

import (
	"context"
	"log"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/internal/evaluate"
	gh "github.com/seebom-labs/bomhort/backend/internal/github"
)

type licenseResolver = evaluate.LicenseResolver
type batchLicenseResolver = evaluate.BatchLicenseResolver
type explainer = evaluate.Explainer
type cachePersister = evaluate.CachePersister

// discrepancyChecker is implemented by resolvers that compare discovered license
// expressions with a package's declared license (#530).
type discrepancyChecker interface {
	CheckDiscrepancy(ctx context.Context, purl, declaredLicense string) (discovered string, hasDiscrepancy bool)
}

// batchDiscrepancyChecker is implemented by resolvers that compare discovered license
// expressions with declared licenses in bulk batches (#530).
type batchDiscrepancyChecker interface {
	CheckDiscrepanciesBatch(ctx context.Context, purls, declaredLicenses []string) []string
}

// registryResolver couples a resolver with its cache namespace in registry_license_cache.
type registryResolver struct {
	name     string
	resolver licenseResolver
}

func toEvaluateResolvers(resolvers []registryResolver) []evaluate.RegistryResolver {
	if resolvers == nil {
		return nil
	}
	out := make([]evaluate.RegistryResolver, len(resolvers))
	for i, r := range resolvers {
		out[i] = evaluate.RegistryResolver{Name: r.name, Resolver: r.resolver}
	}
	return out
}

func fromEvaluateResolvers(resolvers []evaluate.RegistryResolver) []registryResolver {
	if resolvers == nil {
		return nil
	}
	out := make([]registryResolver, len(resolvers))
	for i, r := range resolvers {
		out[i] = registryResolver{name: r.Name, resolver: r.Resolver}
	}
	return out
}

func newRegistryResolvers(ctx context.Context, cfg *config.Config, chClient *clickhouse.Client, ghResolver *gh.Resolver) []registryResolver {
	return fromEvaluateResolvers(evaluate.NewRegistryResolvers(ctx, cfg, chClient, ghResolver))
}

func buildRegistryResolvers(cfg *config.Config, ghResolver *gh.Resolver) []registryResolver {
	return fromEvaluateResolvers(evaluate.BuildRegistryResolvers(cfg, ghResolver))
}

func persistRegistryCaches(ctx context.Context, store cachePersister, resolvers []registryResolver) {
	evaluate.PersistRegistryCaches(ctx, store, toEvaluateResolvers(resolvers))
}

type privateFilter interface {
	IsPrivate(purl string) bool
}

func applyRegistryResolvers(ctx context.Context, resolvers []registryResolver, purls, licenses, sources []string, privatePrefixes ...[]string) map[string]int {
	return evaluate.ApplyRegistryResolvers(ctx, toEvaluateResolvers(resolvers), purls, licenses, sources, privatePrefixes...)
}

func isUnknownLicense(lic string) bool {
	return evaluate.IsUnknownLicense(lic)
}

// detectLicenseDiscrepancies runs discrepancy checking across enabled resolvers (#530).
// Declared license wins and remains authoritative for compliance; discovered
// expressions are stored in LicenseDiscrepancy and surfaced in the license discrepancies view.
// First-party and private packages are excluded from external discrepancy lookups to avoid leaking identifiers.
func detectLicenseDiscrepancies(ctx context.Context, resolvers []registryResolver, purls, licenses []string) []string {
	var batchChecker batchDiscrepancyChecker
	var singleChecker discrepancyChecker
	for _, rr := range resolvers {
		if b, ok := rr.resolver.(batchDiscrepancyChecker); ok {
			batchChecker = b
			break
		}
		if s, ok := rr.resolver.(discrepancyChecker); ok {
			singleChecker = s
			break
		}
	}
	if batchChecker == nil && singleChecker == nil {
		return nil
	}

	var privFilters []privateFilter
	for _, rr := range resolvers {
		if pf, ok := rr.resolver.(privateFilter); ok {
			privFilters = append(privFilters, pf)
		}
	}
	isPrivate := func(purl string) bool {
		if isFirstPartyPURL(purl) {
			return true
		}
		for _, pf := range privFilters {
			if pf.IsPrivate(purl) {
				return true
			}
		}
		return false
	}

	// Filter out first-party/private packages so private identifiers are never sent to external services (#530).
	safePURLs := make([]string, len(purls))
	for i, purl := range purls {
		if isPrivate(purl) {
			safePURLs[i] = ""
		} else {
			safePURLs[i] = purl
		}
	}

	var discrepancies []string
	if batchChecker != nil {
		discrepancies = batchChecker.CheckDiscrepanciesBatch(ctx, safePURLs, licenses)
	} else {
		discrepancies = make([]string, len(licenses))
		for i, purl := range safePURLs {
			if purl == "" || i >= len(licenses) {
				continue
			}
			if disc, found := singleChecker.CheckDiscrepancy(ctx, purl, licenses[i]); found {
				discrepancies[i] = disc
			}
		}
	}

	count := 0
	for _, d := range discrepancies {
		if d != "" {
			count++
		}
	}
	if count > 0 {
		log.Printf("  Detected %d license discrepancies (discovered vs. declared)", count)
	}
	return discrepancies
}
