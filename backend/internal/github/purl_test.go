package github

import "testing"

func TestExtractGitHubRepo(t *testing.T) {
	tests := []struct {
		name      string
		purl      string
		wantOwner string
		wantRepo  string
		wantOK    bool
	}{
		{
			name:      "golang github.com package",
			purl:      "pkg:golang/github.com/chaos-mesh/k8s_dns_chaos@v0.0.0",
			wantOwner: "chaos-mesh",
			wantRepo:  "k8s_dns_chaos",
			wantOK:    true,
		},
		{
			name:      "go standard library",
			purl:      "pkg:golang/stdlib@v1.25.0",
			wantOwner: "golang",
			wantRepo:  "go",
			wantOK:    true,
		},
		{
			name:      "golang with subpath",
			purl:      "pkg:golang/github.com/prometheus/client_golang/prometheus@v1.19.0",
			wantOwner: "prometheus",
			wantRepo:  "client_golang",
			wantOK:    true,
		},
		{
			name:      "pkg:github scheme",
			purl:      "pkg:github/kubernetes/kubernetes@v1.30.0",
			wantOwner: "kubernetes",
			wantRepo:  "kubernetes",
			wantOK:    true,
		},
		{
			name:      "golang.org/x/crypto (well-known mapping)",
			purl:      "pkg:golang/golang.org/x/crypto@v0.21.0",
			wantOwner: "golang",
			wantRepo:  "crypto",
			wantOK:    true,
		},
		{
			name:      "npm package (not supported)",
			purl:      "pkg:npm/%40angular/core@17.0.0",
			wantOwner: "",
			wantRepo:  "",
			wantOK:    false,
		},
		{
			name:      "empty purl",
			purl:      "",
			wantOwner: "",
			wantRepo:  "",
			wantOK:    false,
		},
		{
			name:      "with qualifiers",
			purl:      "pkg:golang/github.com/gin-gonic/gin@v1.9.1?type=module",
			wantOwner: "gin-gonic",
			wantRepo:  "gin",
			wantOK:    true,
		},
		{
			name:      "with subpath fragment",
			purl:      "pkg:golang/github.com/hashicorp/go-hclog@v1.5.0#subdir",
			wantOwner: "hashicorp",
			wantRepo:  "go-hclog",
			wantOK:    true,
		},
		{
			name:      "missing repo",
			purl:      "pkg:golang/github.com/onlyowner",
			wantOwner: "",
			wantRepo:  "",
			wantOK:    false,
		},
		{
			name:      "azure go-autorest submodule",
			purl:      "pkg:golang/github.com/Azure/go-autorest/autorest@v0.11.29",
			wantOwner: "Azure",
			wantRepo:  "go-autorest",
			wantOK:    true,
		},
		{
			name:      "hamba avro v2",
			purl:      "pkg:golang/github.com/hamba/avro/v2@v2.31.0",
			wantOwner: "hamba",
			wantRepo:  "avro",
			wantOK:    true,
		},
		{
			name:      "gopkg.in/yaml.v3 (well-known mapping)",
			purl:      "pkg:golang/gopkg.in/yaml.v3@v3.0.1",
			wantOwner: "go-yaml",
			wantRepo:  "yaml",
			wantOK:    true,
		},
		{
			name:      "go.uber.org/zap (well-known mapping)",
			purl:      "pkg:golang/go.uber.org/zap@v1.26.0",
			wantOwner: "uber-go",
			wantRepo:  "zap",
			wantOK:    true,
		},
		{
			name:      "k8s.io/client-go (well-known mapping)",
			purl:      "pkg:golang/k8s.io/client-go@v0.29.0",
			wantOwner: "kubernetes",
			wantRepo:  "client-go",
			wantOK:    true,
		},
		{
			name:      "oras.land/oras-go/v2 (well-known with version suffix)",
			purl:      "pkg:golang/oras.land/oras-go/v2@v2.6.0",
			wantOwner: "oras-project",
			wantRepo:  "oras-go",
			wantOK:    true,
		},
		{
			name:      "dario.cat/mergo (well-known mapping)",
			purl:      "pkg:golang/dario.cat/mergo@v1.0.2",
			wantOwner: "darccio",
			wantRepo:  "mergo",
			wantOK:    true,
		},
		{
			name:      "go.yaml.in/yaml/v4 (well-known with version suffix)",
			purl:      "pkg:golang/go.yaml.in/yaml/v4@v4.0.0-rc.4",
			wantOwner: "go-yaml",
			wantRepo:  "yaml",
			wantOK:    true,
		},
		{
			name:      "unknown non-github golang package",
			purl:      "pkg:golang/some.random.domain/pkg@v1.0.0",
			wantOwner: "",
			wantRepo:  "",
			wantOK:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, ok := ExtractGitHubRepo(tt.purl)
			if ok != tt.wantOK {
				t.Errorf("ExtractGitHubRepo(%q) ok = %v, want %v", tt.purl, ok, tt.wantOK)
			}
			if owner != tt.wantOwner {
				t.Errorf("ExtractGitHubRepo(%q) owner = %q, want %q", tt.purl, owner, tt.wantOwner)
			}
			if repo != tt.wantRepo {
				t.Errorf("ExtractGitHubRepo(%q) repo = %q, want %q", tt.purl, repo, tt.wantRepo)
			}
		})
	}
}

func TestRepoKey(t *testing.T) {
	tests := []struct {
		owner string
		repo  string
		want  string
	}{
		{"Azure", "go-autorest", "azure/go-autorest"},
		{"OWNER", "REPO", "owner/repo"},
		{"", "repo", "/repo"},
		{"owner", "", "owner/"},
	}

	for _, tt := range tests {
		t.Run(tt.owner+"/"+tt.repo, func(t *testing.T) {
			got := RepoKey(tt.owner, tt.repo)
			if got != tt.want {
				t.Errorf("RepoKey(%q, %q) = %q, want %q", tt.owner, tt.repo, got, tt.want)
			}
		})
	}
}

func TestExtractGitHubRepo_GopkgInRedirectRule(t *testing.T) {
	tests := []struct {
		purl, owner, repo string
		ok                bool
	}{
		{"pkg:golang/gopkg.in/bsm/ratelimit.v1@v1.0.0-20170922094635-f56db5e73a5e", "bsm", "ratelimit", true},
		{"pkg:golang/gopkg.in/couchbaselabs/gojcbmock.v1@v1.0.4", "couchbaselabs", "gojcbmock", true},
		{"pkg:golang/gopkg.in/ini.v1@v1.67.0", "go-ini", "ini", true},
		{"pkg:golang/gopkg.in/user/pkg.v2/subpkg@v2.0.0", "user", "pkg", true},
		// The well-known table still wins over the generic rule.
		{"pkg:golang/gopkg.in/yaml.v3@v3.0.1", "go-yaml", "yaml", true},
		{"pkg:golang/gopkg.in/noversion@v1.0.0", "", "", false},
		{"pkg:golang/gopkg.in/user/pkg.vx@v1.0.0", "", "", false},
	}
	for _, tc := range tests {
		owner, repo, ok := ExtractGitHubRepo(tc.purl)
		if owner != tc.owner || repo != tc.repo || ok != tc.ok {
			t.Errorf("ExtractGitHubRepo(%q) = (%q, %q, %v), want (%q, %q, %v)", tc.purl, owner, repo, ok, tc.owner, tc.repo, tc.ok)
		}
	}
}
