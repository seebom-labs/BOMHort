package main

import (
	"context"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/internal/evaluate"
	gh "github.com/seebom-labs/bomhort/backend/internal/github"
)

type licenseResolver = evaluate.LicenseResolver
type batchLicenseResolver = evaluate.BatchLicenseResolver
type explainer = evaluate.Explainer
type cachePersister = evaluate.CachePersister

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

func applyRegistryResolvers(ctx context.Context, resolvers []registryResolver, purls, licenses, sources []string) map[string]int {
	return evaluate.ApplyRegistryResolvers(ctx, toEvaluateResolvers(resolvers), purls, licenses, sources)
}

func isUnknownLicense(lic string) bool {
	return evaluate.IsUnknownLicense(lic)
}
