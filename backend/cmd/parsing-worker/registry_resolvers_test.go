package main

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// fakeResolver resolves purls with a given prefix from a static map.
type fakeResolver struct {
	prefix string
	known  map[string]string
	calls  int
	cache  map[string]string
}

func (f *fakeResolver) Resolve(_ context.Context, purl string) string {
	if !strings.HasPrefix(purl, f.prefix) {
		return ""
	}
	f.calls++
	return f.known[purl]
}

func (f *fakeResolver) PreloadCache(entries map[string]string) {
	if f.cache == nil {
		f.cache = map[string]string{}
	}
	for k, v := range entries {
		f.cache[k] = v
	}
}

func (f *fakeResolver) CacheEntries() map[string]string { return f.cache }

type fakeBatchResolver struct {
	known map[string]string
	seen  []string
	cache map[string]string
}

func (f *fakeBatchResolver) Resolve(_ context.Context, purl string) string {
	return f.known[purl]
}

func (f *fakeBatchResolver) ResolveBatch(_ context.Context, purls []string) map[string]string {
	f.seen = append(f.seen, purls...)
	out := make(map[string]string, len(purls))
	for _, purl := range purls {
		out[purl] = f.known[purl]
	}
	return out
}

func (f *fakeBatchResolver) PreloadCache(entries map[string]string) {
	if f.cache == nil {
		f.cache = map[string]string{}
	}
	for k, v := range entries {
		f.cache[k] = v
	}
}

func (f *fakeBatchResolver) CacheEntries() map[string]string { return f.cache }

type fakeStore struct {
	inserted map[string]map[string]string
}

func (s *fakeStore) InsertRegistryLicenseCache(_ context.Context, registry string, entries map[string]string) error {
	if s.inserted == nil {
		s.inserted = map[string]map[string]string{}
	}
	s.inserted[registry] = entries
	return nil
}

func TestApplyRegistryResolvers(t *testing.T) {
	npm := &fakeResolver{prefix: "pkg:npm/", known: map[string]string{
		"pkg:npm/a@1": "MIT",
		"pkg:npm/b@1": "", // registry knows nothing
	}}
	nuget := &fakeResolver{prefix: "pkg:nuget/", known: map[string]string{
		"pkg:nuget/C@1": "Apache-2.0",
	}}
	resolvers := []registryResolver{{"npm", npm}, {"nuget", nuget}}

	purls := []string{"pkg:npm/a@1", "pkg:npm/b@1", "pkg:nuget/C@1", "pkg:golang/x@1", "", "pkg:nuget/D@1"}
	licenses := []string{"NOASSERTION", "", "NONE", "NOASSERTION", "NOASSERTION", "BSD-3-Clause"}

	sources := make([]string, len(licenses))
	counts := applyRegistryResolvers(context.Background(), resolvers, purls, licenses, sources)

	want := []string{"MIT", "", "Apache-2.0", "NOASSERTION", "NOASSERTION", "BSD-3-Clause"}
	if !reflect.DeepEqual(licenses, want) {
		t.Errorf("licenses = %v, want %v", licenses, want)
	}
	wantSources := []string{"npm", "", "nuget", "", "", ""}
	if !reflect.DeepEqual(sources, wantSources) {
		t.Errorf("sources = %v, want %v", sources, wantSources)
	}
	if counts["npm"] != 1 || counts["nuget"] != 1 {
		t.Errorf("counts = %v, want npm=1 nuget=1", counts)
	}
	// Known licenses (index 5) must never be offered to a resolver.
	if nuget.calls != 1 {
		t.Errorf("nuget resolver called %d times, want 1 (only the unknown nuget purl)", nuget.calls)
	}
}

func TestApplyRegistryResolvers_BatchResolverRunsAfterNPMForStillUnknownLicenses(t *testing.T) {
	npm := &fakeResolver{prefix: "pkg:npm/", known: map[string]string{
		"pkg:npm/a@1": "MIT",
		"pkg:npm/b@1": "",
	}}
	depsdev := &fakeBatchResolver{known: map[string]string{
		"pkg:npm/b@1":      "ISC",
		"pkg:maven/g/a@1":  "Apache-2.0",
		"pkg:cargo/skip@1": "BSD-3-Clause",
	}}
	resolvers := []registryResolver{{"npm", npm}, {"depsdev", depsdev}}

	purls := []string{"pkg:npm/a@1", "pkg:npm/b@1", "pkg:maven/g/a@1", "pkg:cargo/skip@1"}
	licenses := []string{"NOASSERTION", "", "NONE", "MIT"}

	counts := applyRegistryResolvers(context.Background(), resolvers, purls, licenses, nil)

	wantLicenses := []string{"MIT", "ISC", "Apache-2.0", "MIT"}
	if !reflect.DeepEqual(licenses, wantLicenses) {
		t.Errorf("licenses = %v, want %v", licenses, wantLicenses)
	}
	wantSeen := []string{"pkg:npm/b@1", "pkg:maven/g/a@1"}
	if !reflect.DeepEqual(depsdev.seen, wantSeen) {
		t.Errorf("deps.dev saw %v, want only still-unknown purls %v", depsdev.seen, wantSeen)
	}
	if counts["npm"] != 1 || counts["depsdev"] != 2 {
		t.Errorf("counts = %v, want npm=1 depsdev=2", counts)
	}
}

func TestApplyRegistryResolvers_LicensesShorterThanPURLs(t *testing.T) {
	r := &fakeResolver{prefix: "pkg:npm/", known: map[string]string{"pkg:npm/a@1": "MIT"}}
	purls := []string{"pkg:npm/a@1", "pkg:npm/b@1"}
	licenses := []string{"NOASSERTION"}
	applyRegistryResolvers(context.Background(), []registryResolver{{"npm", r}}, purls, licenses, []string{""})
	if licenses[0] != "MIT" || len(licenses) != 1 {
		t.Errorf("got %v", licenses)
	}
}

func TestPersistRegistryCaches(t *testing.T) {
	r := &fakeResolver{prefix: "pkg:npm/"}
	r.PreloadCache(map[string]string{"a@1": "MIT", "b@1": "!not-published"})
	empty := &fakeResolver{prefix: "pkg:nuget/"}
	store := &fakeStore{}

	persistRegistryCaches(context.Background(), store, []registryResolver{{"npm", r}, {"nuget", empty}})

	if got := store.inserted["npm"]; !reflect.DeepEqual(got, map[string]string{"a@1": "MIT", "b@1": "!not-published"}) {
		t.Errorf("npm cache (with negative reasons) not persisted: %v", store.inserted)
	}
	if _, ok := store.inserted["nuget"]; ok {
		t.Errorf("empty cache must not be persisted: %v", store.inserted)
	}
	// Must not panic without a persistence backend.
	persistRegistryCaches(context.Background(), nil, []registryResolver{{"npm", r}})
}
