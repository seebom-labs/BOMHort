package main

import (
	"context"

	"github.com/seebom-labs/bomhort/backend/internal/evaluate"
)

type githubLookup = evaluate.GitHubLookup

var coveredPURLTypes = evaluate.CoveredPURLTypes

func resolvePackageLicenses(ctx context.Context, github githubLookup, resolvers []registryResolver, purls, licenses []string, roots []uint32) (sources []string, counts map[string]int, err error) {
	return evaluate.ResolvePackageLicenses(ctx, github, toEvaluateResolvers(resolvers), purls, licenses, roots)
}

func explainUnresolved(resolvers []registryResolver, purls, licenses, sources []string, roots []uint32) {
	evaluate.ExplainUnresolved(toEvaluateResolvers(resolvers), purls, licenses, sources, roots)
}

func unresolvedReason(resolvers []registryResolver, purl string, isRoot bool) string {
	return evaluate.UnresolvedReason(toEvaluateResolvers(resolvers), purl, isRoot)
}

func purlType(purl string) string {
	return evaluate.PURLType(purl)
}
