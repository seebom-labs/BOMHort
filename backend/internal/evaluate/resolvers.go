package evaluate

import (
	"context"
	"log"

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

// LicenseResolver is implemented by the package-registry resolvers.
type LicenseResolver interface {
	Resolve(ctx context.Context, purl string) string
	PreloadCache(entries map[string]string)
	CacheEntries() map[string]string
}

// BatchLicenseResolver is implemented by resolvers supporting batch queries.
type BatchLicenseResolver interface {
	ResolveBatch(ctx context.Context, purls []string) map[string]string
}

// Explainer is implemented by resolvers that record why a purl stayed
// unresolved (a license.Reason* value, "" when unknown) and whether a resolved
// license is the newest release's rather than the exact version's. Handled is
// false for purls of ecosystems the resolver does not cover.
type Explainer interface {
	Explain(purl string) (handled bool, reason string, latest bool)
}

// RegistryResolver couples a resolver with its cache namespace in registry_license_cache.
type RegistryResolver struct {
	Name     string
	Resolver LicenseResolver
}

// NewRegistryResolvers builds the enabled registry resolvers and preloads their
// caches from ClickHouse. ghResolver may be nil; when present, the NuGet
// resolver uses it to derive licenses of legacy packages from their GitHub repo.
func NewRegistryResolvers(ctx context.Context, cfg *config.Config, chClient *clickhouse.Client, ghResolver *gh.Resolver) []RegistryResolver {
	out := BuildRegistryResolvers(cfg, ghResolver)
	if chClient == nil {
		return out
	}
	for _, rr := range out {
		if cached, err := chClient.QueryRegistryLicenseCache(ctx, rr.Name); err == nil && len(cached) > 0 {
			rr.Resolver.PreloadCache(cached)
			log.Printf("Preloaded %d %s license cache entries", len(cached), rr.Name)
		}
	}
	return out
}

// BuildRegistryResolvers returns the enabled registry resolvers in chain
// order, without touching ClickHouse.
func BuildRegistryResolvers(cfg *config.Config, ghResolver *gh.Resolver) []RegistryResolver {
	var out []RegistryResolver

	if !cfg.SkipNPMResolve {
		out = append(out, RegistryResolver{Name: "npm", Resolver: npm.NewResolver()})
		log.Println("npm license resolver enabled (registry.npmjs.org)")
	} else {
		log.Println("npm license resolver disabled (SKIP_NPM_RESOLVE=true)")
	}

	if !cfg.SkipNuGetResolve {
		var repo nuget.RepoResolver
		if ghResolver != nil {
			repo = ghResolver
		}
		out = append(out, RegistryResolver{Name: "nuget", Resolver: nuget.NewResolver(repo)})
		log.Println("NuGet license resolver enabled (api.nuget.org)")
	} else {
		log.Println("NuGet license resolver disabled (SKIP_NUGET_RESOLVE=true)")
	}

	if !cfg.SkipDepsDevResolve {
		out = append(out, RegistryResolver{Name: "depsdev", Resolver: depsdev.NewResolver()})
		log.Println("deps.dev license resolver enabled (api.deps.dev)")
	} else {
		log.Println("deps.dev license resolver disabled (SKIP_DEPSDEV_RESOLVE=true)")
	}

	if !cfg.SkipPackagistResolve {
		out = append(out, RegistryResolver{Name: "packagist", Resolver: packagist.NewResolver()})
		log.Println("Packagist license resolver enabled (repo.packagist.org)")
	} else {
		log.Println("Packagist license resolver disabled (SKIP_PACKAGIST_RESOLVE=true)")
	}

	// PyPI runs after deps.dev: it only sees what deps.dev could not map.
	if !cfg.SkipPyPIResolve {
		out = append(out, RegistryResolver{Name: "pypi", Resolver: pypi.NewResolver()})
		log.Println("PyPI license resolver enabled (pypi.org)")
	} else {
		log.Println("PyPI license resolver disabled (SKIP_PYPI_RESOLVE=true)")
	}
	return out
}

// CachePersister is the subset of *clickhouse.Client used to persist resolver caches.
type CachePersister interface {
	InsertRegistryLicenseCache(ctx context.Context, registry string, entries map[string]string) error
}

// PersistRegistryCaches writes every resolver's cache (including negative
// results with their reasons) to registry_license_cache.
func PersistRegistryCaches(ctx context.Context, store CachePersister, resolvers []RegistryResolver) {
	if store == nil {
		return
	}
	for _, rr := range resolvers {
		if entries := rr.Resolver.CacheEntries(); len(entries) > 0 {
			_ = store.InsertRegistryLicenseCache(ctx, rr.Name, entries)
		}
	}
}

// ApplyRegistryResolvers offers every package with an unknown license to each
// resolver in order and writes resolved expressions back into licenses, and
// the resolver's name into sources (when sources is non-nil). Resolvers ignore
// purls of other ecosystems, so all packages can be offered to all resolvers.
// Returns the number of packages resolved per resolver name.
func ApplyRegistryResolvers(ctx context.Context, resolvers []RegistryResolver, purls, licenses, sources []string) map[string]int {
	counts := make(map[string]int, len(resolvers))
	for _, rr := range resolvers {
		if batch, ok := rr.Resolver.(BatchLicenseResolver); ok {
			unknownPURLs := make([]string, 0, len(licenses))
			for i, lic := range licenses {
				if !IsUnknownLicense(lic) {
					continue
				}
				if i >= len(purls) || purls[i] == "" {
					continue
				}
				unknownPURLs = append(unknownPURLs, purls[i])
			}
			if len(unknownPURLs) == 0 {
				continue
			}
			resolved := batch.ResolveBatch(ctx, unknownPURLs)
			for i, lic := range licenses {
				if !IsUnknownLicense(lic) {
					continue
				}
				if i >= len(purls) || purls[i] == "" {
					continue
				}
				if spdx := resolved[purls[i]]; spdx != "" {
					licenses[i] = spdx
					recordSource(sources, i, rr, purls[i])
					counts[rr.Name]++
				}
			}
			continue
		}
		for i, lic := range licenses {
			if !IsUnknownLicense(lic) {
				continue
			}
			if i >= len(purls) || purls[i] == "" {
				continue
			}
			if spdx := rr.Resolver.Resolve(ctx, purls[i]); spdx != "" {
				licenses[i] = spdx
				recordSource(sources, i, rr, purls[i])
				counts[rr.Name]++
			}
		}
	}
	return counts
}

// recordSource notes that rr resolved package i, marking it "+latest" when the
// resolver used the newest release's license.
func recordSource(sources []string, i int, rr RegistryResolver, purl string) {
	if i >= len(sources) {
		return
	}
	src := rr.Name
	if ex, ok := rr.Resolver.(Explainer); ok {
		if _, _, latest := ex.Explain(purl); latest {
			src = license.WithModifier(src, license.ModifierLatest)
		}
	}
	sources[i] = src
}

// IsUnknownLicense reports whether lic is empty or an unasserted license marker.
func IsUnknownLicense(lic string) bool {
	return lic == "" || lic == "NOASSERTION" || lic == "NONE"
}
