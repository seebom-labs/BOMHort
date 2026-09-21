package main

import (
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/ingestpath"
)

func mustLayout(t *testing.T, spec string) ingestpath.Layout {
	t.Helper()
	l, err := ingestpath.ParseLayout(spec)
	if err != nil {
		t.Fatalf("ParseLayout(%q): %v", spec, err)
	}
	return l
}

func TestStripPrefix(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		prefix string
		want   string
	}{
		{"no prefix", "prod-eu/payments/f.json", "", "prod-eu/payments/f.json"},
		{"prefix with slash", "k3s-io/prod-eu/f.json", "k3s-io/", "prod-eu/f.json"},
		{"prefix without slash", "k3s-io/prod-eu/f.json", "k3s-io", "prod-eu/f.json"},
		{"nested prefix", "a/b/prod-eu/f.json", "a/b/", "prod-eu/f.json"},
		{"key equals prefix", "k3s-io/", "k3s-io/", ""},
		{"non-matching prefix is left alone", "other/f.json", "k3s-io/", "other/f.json"},
		{"empty key", "", "k3s-io/", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripPrefix(tt.key, tt.prefix); got != tt.want {
				t.Errorf("stripPrefix(%q, %q) = %q, want %q", tt.key, tt.prefix, got, tt.want)
			}
		})
	}
}

func TestOwnership_ResolveWithLayout(t *testing.T) {
	own := ownership{layout: mustLayout(t, "cluster/namespace/project")}

	cluster, namespace, project, _ := own.resolve("prod-eu/payments/payment-service/sbom.spdx.json")
	if cluster != "prod-eu" || namespace != "payments" || project != "payment-service" {
		t.Errorf("resolve() = (%q, %q, %q), want (prod-eu, payments, payment-service)", cluster, namespace, project)
	}
}

// The layout is defined relative to the ingestion root, so a bucket's
// configured key prefix must be stripped first. Without this, a bucket with
// prefix "k3s-io/" would label every SBOM with cluster="k3s-io".
func TestOwnership_ResolveStripsBucketPrefix(t *testing.T) {
	own := ownership{
		prefix: "k3s-io/",
		layout: mustLayout(t, "cluster/namespace"),
	}

	cluster, namespace, _, _ := own.resolve("k3s-io/prod-eu/payments/sbom.spdx.json")
	if cluster != "prod-eu" {
		t.Errorf("cluster = %q, want prod-eu (the prefix must not be read as a segment)", cluster)
	}
	if namespace != "payments" {
		t.Errorf("namespace = %q, want payments", namespace)
	}
}

// Explicit per-bucket configuration always wins over path derivation:
// an operator who names a dimension means it.
func TestOwnership_ExplicitConfigOutranksPath(t *testing.T) {
	own := ownership{
		cluster: "configured-cluster",
		layout:  mustLayout(t, "cluster/namespace/project"),
	}

	cluster, namespace, project, _ := own.resolve("prod-eu/payments/payment-service/sbom.spdx.json")
	if cluster != "configured-cluster" {
		t.Errorf("cluster = %q, want the configured value to win", cluster)
	}
	if namespace != "payments" || project != "payment-service" {
		t.Errorf("unset dimensions should still be derived, got (%q, %q)", namespace, project)
	}
}

func TestOwnership_ResolveWithoutLayout(t *testing.T) {
	own := ownership{
		cluster:   "c",
		namespace: "n",
		project:   "p",
	}

	cluster, namespace, project, _ := own.resolve("prod-eu/payments/payment-service/sbom.spdx.json")
	if cluster != "c" || namespace != "n" || project != "p" {
		t.Errorf("resolve() = (%q, %q, %q), want the configured values unchanged", cluster, namespace, project)
	}
}

func TestOwnership_ShallowPathLeavesRestEmpty(t *testing.T) {
	own := ownership{layout: mustLayout(t, "cluster/namespace/project")}

	cluster, namespace, project, _ := own.resolve("prod-eu/sbom.spdx.json")
	if cluster != "prod-eu" {
		t.Errorf("cluster = %q, want prod-eu", cluster)
	}
	if namespace != "" || project != "" {
		t.Errorf("missing levels must stay empty, got (%q, %q)", namespace, project)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	tests := []struct {
		name string
		vals []string
		want string
	}{
		{"first wins", []string{"a", "b"}, "a"},
		{"skips empty", []string{"", "b"}, "b"},
		{"all empty", []string{"", ""}, ""},
		{"no args", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstNonEmpty(tt.vals...); got != tt.want {
				t.Errorf("firstNonEmpty(%v) = %q, want %q", tt.vals, got, tt.want)
			}
		})
	}
}

// Tags are bucket configuration, not path-derived: every object in a bucket
// carries the same labels regardless of how deep its key is. A layout that
// consumes segments must not disturb them.
func TestOwnership_ResolveCarriesConfiguredTags(t *testing.T) {
	own := ownership{
		layout: mustLayout(t, "cluster/namespace/project"),
		tags:   []string{"sandbox-applications"},
	}
	_, _, project, tags := own.resolve("prod-eu/payments/payment-service/sbom.spdx.json")
	// The project must survive alongside the tag. Tags group projects, they do
	// not replace them -- if the tag ever started standing in for the project,
	// every project under one grouping would collapse into a single row.
	if project != "payment-service" {
		t.Errorf("project = %q, want payment-service to survive tagging", project)
	}
	if len(tags) != 1 || tags[0] != "sandbox-applications" {
		t.Errorf("tags = %v, want [sandbox-applications]", tags)
	}
}

// An untagged bucket must yield no tags rather than a one-element list holding
// the empty string, which would show up as a nameless grouping in the UI.
func TestOwnership_ResolveWithoutTags(t *testing.T) {
	own := ownership{cluster: "c"}
	if _, _, _, tags := own.resolve("a/b/sbom.spdx.json"); len(tags) != 0 {
		t.Errorf("tags = %v, want empty for an untagged bucket", tags)
	}
}
