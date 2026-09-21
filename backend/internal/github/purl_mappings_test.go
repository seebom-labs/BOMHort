package github

import (
	"sort"
	"testing"
)

// The archived-repo views rebuild ExtractGitHubRepo's mapping in SQL from
// WellKnownModuleMappings. That only stays correct while the exported table
// and the function agree, so the agreement is asserted here rather than left
// to whoever next adds a module to the map.

// TestWellKnownMappingsRoundTrip is the drift guard: every exported prefix must
// resolve, through ExtractGitHubRepo, to exactly the repo key exported with it.
func TestWellKnownMappingsRoundTrip(t *testing.T) {
	prefixes, repoKeys := WellKnownModuleMappings()

	if len(prefixes) != len(repoKeys) {
		t.Fatalf("parallel slices disagree: %d prefixes, %d repo keys", len(prefixes), len(repoKeys))
	}
	if len(prefixes) == 0 {
		t.Fatal("no mappings exported — the SQL side would silently match nothing")
	}

	for i, prefix := range prefixes {
		owner, repo, ok := ExtractGitHubRepo("pkg:golang/" + prefix)
		if !ok {
			t.Errorf("prefix %q does not resolve through ExtractGitHubRepo", prefix)
			continue
		}
		if got := RepoKey(owner, repo); got != repoKeys[i] {
			t.Errorf("prefix %q: exported repo key %q, ExtractGitHubRepo says %q",
				prefix, repoKeys[i], got)
		}
	}
}

// TestWellKnownMappingsCoverEveryEntry stops an entry from being dropped from
// the export while staying in the map: the SQL side would then quietly stop
// reporting that module.
func TestWellKnownMappingsCoverEveryEntry(t *testing.T) {
	prefixes, _ := WellKnownModuleMappings()

	exported := make(map[string]bool, len(prefixes))
	for _, p := range prefixes {
		exported[p] = true
	}
	for prefix := range wellKnownGoModules {
		if !exported[prefix] {
			t.Errorf("module prefix %q is in the map but not exported", prefix)
		}
	}
	if len(prefixes) != len(wellKnownGoModules) {
		t.Errorf("exported %d prefixes, map holds %d", len(prefixes), len(wellKnownGoModules))
	}
}

// TestWellKnownMappingsLongestPrefixFirst pins the ordering the SQL lookup
// relies on. It walks the prefix list in order and takes the first match, so
// with "k8s.io/api" ahead of a hypothetical "k8s.io" every k8s.io/* module
// would resolve to the shorter entry.
func TestWellKnownMappingsLongestPrefixFirst(t *testing.T) {
	prefixes, _ := WellKnownModuleMappings()

	if !sort.SliceIsSorted(prefixes, func(i, j int) bool {
		if len(prefixes[i]) != len(prefixes[j]) {
			return len(prefixes[i]) > len(prefixes[j])
		}
		return prefixes[i] < prefixes[j]
	}) {
		t.Error("prefixes are not sorted longest-first; SQL first-match lookup becomes order-dependent")
	}
}

// TestExtractGitHubRepoImportPathDiffersFromRepo is the regression guard for
// the empty archived-packages page: these purls share no substring with their
// repository, so the previous `purl LIKE '%' || repo || '%'` join could never
// match them and the view rendered empty while the dashboard counted them.
func TestExtractGitHubRepoImportPathDiffersFromRepo(t *testing.T) {
	cases := []struct {
		purl string
		want string
	}{
		{"pkg:golang/gopkg.in/yaml.v3@v3.0.1", "go-yaml/yaml"},
		{"pkg:golang/gopkg.in/yaml.v2@v2.4.0", "go-yaml/yaml"},
		{"pkg:golang/k8s.io/client-go@v0.29.0", "kubernetes/client-go"},
		{"pkg:golang/google.golang.org/grpc@v1.58.3", "grpc/grpc-go"},
		{"pkg:golang/go.uber.org/zap@v1.27.0", "uber-go/zap"},
		{"pkg:golang/sigs.k8s.io/yaml@v1.4.0", "kubernetes-sigs/yaml"},
		{"pkg:golang/golang.org/x/net@v0.23.0", "golang/net"},
		{"pkg:golang/oras.land/oras-go/v2@v2.5.0", "oras-project/oras-go"},
		{"pkg:golang/dario.cat/mergo@v1.0.0", "darccio/mergo"},
		// Direct forms, which the substring match did handle.
		{"pkg:golang/github.com/spf13/cobra@v1.8.0", "spf13/cobra"},
		{"pkg:github/hamba/avro@v2.0.0", "hamba/avro"},
	}

	for _, tc := range cases {
		owner, repo, ok := ExtractGitHubRepo(tc.purl)
		if !ok {
			t.Errorf("%s: not recognised as a GitHub package", tc.purl)
			continue
		}
		if got := RepoKey(owner, repo); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.purl, got, tc.want)
		}
	}
}

