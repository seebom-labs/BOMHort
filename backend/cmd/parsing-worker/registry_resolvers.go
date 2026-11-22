package main

import (
	"context"
	"log"

	"github.com/seebom-labs/bomhort/backend/internal/clearlydefined"
	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/internal/depsdev"
	gh "github.com/seebom-labs/bomhort/backend/internal/github"
	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/npm"
	"github.com/seebom-labs/bomhort/backend/internal/nuget"
	"github.com/seebom-labs/bomhort/backend/internal/packagist"
	"github.com/seebom-labs/bomhort/backend/internal/pypi"
)

// licenseResolver is implemented by the package-registry resolvers.
type licenseResolver interface {
	Resolve(ctx context.Context, purl string) string
	PreloadCache(entries map[string]string)
	CacheEntries() map[string]string
}

type batchLicenseResolver interface {
	ResolveBatch(ctx context.Context, purls []string) map[string]string
}

// explainer is implemented by resolvers that record why a purl stayed
// unresolved (a license.Reason* value, "" when unknown) and whether a resolved
// license is the newest release's rather than the exact version's. handled is
// false for purls of ecosystems the resolver does not cover.
type explainer interface {
	Explain(purl string) (handled bool, reason string, latest bool)
}

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

// newRegistryResolvers builds the enabled registry resolvers and preloads their
// caches from ClickHouse. ghResolver may be nil; when present, the NuGet
// resolver uses it to derive licenses of legacy packages from their GitHub repo.
func newRegistryResolvers(ctx context.Context, cfg *config.Config, chClient *clickhouse.Client, ghResolver *gh.Resolver) []registryResolver {
	out := buildRegistryResolvers(cfg, ghResolver)
	for _, rr := range out {
		if cached, err := chClient.QueryRegistryLicenseCache(ctx, rr.name); err == nil && len(cached) > 0 {
			rr.resolver.PreloadCache(cached)
			log.Printf("Preloaded %d %s license cache entries", len(cached), rr.name)
		}
	}
	return out
}

// buildRegistryResolvers returns the enabled registry resolvers in chain
// order, without touching ClickHouse.
func buildRegistryResolvers(cfg *config.Config, ghResolver *gh.Resolver) []registryResolver {
	var out []registryResolver

	if !cfg.SkipNPMResolve {
		out = append(out, registryResolver{name: "npm", resolver: npm.NewResolver()})
		log.Println("npm license resolver enabled (registry.npmjs.org)")
	} else {
		log.Println("npm license resolver disabled (SKIP_NPM_RESOLVE=true)")
	}

	if !cfg.SkipNuGetResolve {
		var repo nuget.RepoResolver
		if ghResolver != nil {
			repo = ghResolver
		}
		out = append(out, registryResolver{name: "nuget", resolver: nuget.NewResolver(repo)})
		log.Println("NuGet license resolver enabled (api.nuget.org)")
	} else {
		log.Println("NuGet license resolver disabled (SKIP_NUGET_RESOLVE=true)")
	}

	if !cfg.SkipDepsDevResolve {
		out = append(out, registryResolver{name: "depsdev", resolver: depsdev.NewResolver()})
		log.Println("deps.dev license resolver enabled (api.deps.dev)")
	} else {
		log.Println("deps.dev license resolver disabled (SKIP_DEPSDEV_RESOLVE=true)")
	}

	if !cfg.SkipPackagistResolve {
		out = append(out, registryResolver{name: "packagist", resolver: packagist.NewResolver()})
		log.Println("Packagist license resolver enabled (repo.packagist.org)")
	} else {
		log.Println("Packagist license resolver disabled (SKIP_PACKAGIST_RESOLVE=true)")
	}

	// PyPI runs after deps.dev: it only sees what deps.dev could not map.
	if !cfg.SkipPyPIResolve {
		out = append(out, registryResolver{name: "pypi", resolver: pypi.NewResolver()})
		log.Println("PyPI license resolver enabled (pypi.org)")
	} else {
		log.Println("PyPI license resolver disabled (SKIP_PYPI_RESOLVE=true)")
	}

	// ClearlyDefined runs after the registry resolvers (#530).
	if !cfg.SkipClearlyDefinedResolve {
		cd := clearlydefined.NewResolver()
		cd.SetPrivatePrefixes(cfg.PrivatePackagePrefixes)
		out = append(out, registryResolver{name: "clearlydefined", resolver: cd})
		log.Println("ClearlyDefined license resolver enabled (api.clearlydefined.io)")
	} else {
		log.Println("ClearlyDefined license resolver disabled (SKIP_CLEARLYDEFINED_RESOLVE=true)")
	}
	return out
}

// cachePersister is the subset of *clickhouse.Client used to persist resolver caches.
type cachePersister interface {
	InsertRegistryLicenseCache(ctx context.Context, registry string, entries map[string]string) error
}

// persistRegistryCaches writes every resolver's cache (including negative
// results with their reasons) to registry_license_cache.
func persistRegistryCaches(ctx context.Context, store cachePersister, resolvers []registryResolver) {
	if store == nil {
		return
	}
	for _, rr := range resolvers {
		if entries := rr.resolver.CacheEntries(); len(entries) > 0 {
			_ = store.InsertRegistryLicenseCache(ctx, rr.name, entries)
		}
	}
}

type privateFilter interface {
	IsPrivate(purl string) bool
}

// applyRegistryResolvers offers every package with an unknown license to each
// resolver in order and writes resolved expressions back into licenses, and
// the resolver's name into sources (when sources is non-nil). Resolvers ignore
// purls of other ecosystems, so all packages can be offered to all resolvers.
// Private and first-party packages are never sent to external resolvers (#530).
// Returns the number of packages resolved per resolver name.
func applyRegistryResolvers(ctx context.Context, resolvers []registryResolver, purls, licenses, sources, privatePrefixes []string) map[string]int {
	counts := make(map[string]int, len(resolvers))
	for _, rr := range resolvers {
		if batch, ok := rr.resolver.(batchLicenseResolver); ok {
			unknownPURLs := make([]string, 0, len(licenses))
			for i, lic := range licenses {
				if !isUnknownLicense(lic) {
					continue
				}
				if i >= len(purls) || purls[i] == "" {
					continue
				}
				if clearlydefined.IsPrivatePackage(purls[i], privatePrefixes) {
					continue
				}
				unknownPURLs = append(unknownPURLs, purls[i])
			}
			if len(unknownPURLs) == 0 {
				continue
			}
			resolved := batch.ResolveBatch(ctx, unknownPURLs)
			for i, lic := range licenses {
				if !isUnknownLicense(lic) {
					continue
				}
				if i >= len(purls) || purls[i] == "" {
					continue
				}
				if clearlydefined.IsPrivatePackage(purls[i], privatePrefixes) {
					continue
				}
				if spdx := resolved[purls[i]]; spdx != "" {
					licenses[i] = spdx
					recordSource(sources, i, rr, purls[i])
					counts[rr.name]++
				}
			}
			continue
		}
		for i, lic := range licenses {
			if !isUnknownLicense(lic) {
				continue
			}
			if i >= len(purls) || purls[i] == "" {
				continue
			}
			if clearlydefined.IsPrivatePackage(purls[i], privatePrefixes) {
				continue
			}
			if spdx := rr.resolver.Resolve(ctx, purls[i]); spdx != "" {
				licenses[i] = spdx
				recordSource(sources, i, rr, purls[i])
				counts[rr.name]++
			}
		}
	}
	return counts
}

// recordSource notes that rr resolved package i, marking it "+latest" when the
// resolver used the newest release's license.
func recordSource(sources []string, i int, rr registryResolver, purl string) {
	if i >= len(sources) {
		return
	}
	src := rr.name
	if ex, ok := rr.resolver.(explainer); ok {
		if _, _, latest := ex.Explain(purl); latest {
			src = license.WithModifier(src, license.ModifierLatest)
		}
	}
	sources[i] = src
}

func isUnknownLicense(lic string) bool {
	return lic == "" || lic == "NOASSERTION" || lic == "NONE"
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
