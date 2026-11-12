package apikey

import (
	"context"
	"strings"
	"testing"
)

func TestParseKeysJSON_Empty(t *testing.T) {
	for _, raw := range []string{"", "   ", "\n\t"} {
		keys, err := ParseKeysJSON(raw)
		if err != nil {
			t.Fatalf("expected nil error for empty string, got: %v", err)
		}
		if len(keys) != 0 {
			t.Fatalf("expected 0 keys, got %d", len(keys))
		}
	}
}

func TestParseKeysJSON_Valid(t *testing.T) {
	raw := `[
		{
			"name": "ci-builder",
			"secret": "secret-123",
			"scope": {
				"origins": ["ci"],
				"clusters": ["prod-cluster"],
				"namespaces": ["core"],
				"projects": ["my-org/backend"]
			}
		},
		{
			"name": "runtime-scanner",
			"secret": "secret-456",
			"scope": {
				"origins": ["cluster-scan"]
			}
		},
		{
			"name": "unscoped-admin",
			"secret": "secret-789"
		}
	]`

	keys, err := ParseKeysJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error parsing valid JSON: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}

	if keys[0].Name != "ci-builder" || keys[0].Secret != "secret-123" {
		t.Errorf("key[0] mismatch: %+v", keys[0])
	}
	if len(keys[0].Scope.Origins) != 1 || keys[0].Scope.Origins[0] != "ci" {
		t.Errorf("key[0] origins mismatch: %+v", keys[0].Scope.Origins)
	}
	if keys[0].Scope.DefaultOrigin() != "ci" {
		t.Errorf("expected default origin 'ci', got %q", keys[0].Scope.DefaultOrigin())
	}
	if keys[0].Scope.DefaultCluster() != "prod-cluster" {
		t.Errorf("expected default cluster 'prod-cluster', got %q", keys[0].Scope.DefaultCluster())
	}
	if keys[0].Scope.DefaultNamespace() != "core" {
		t.Errorf("expected default namespace 'core', got %q", keys[0].Scope.DefaultNamespace())
	}
	if keys[0].Scope.DefaultProject() != "my-org/backend" {
		t.Errorf("expected default project 'my-org/backend', got %q", keys[0].Scope.DefaultProject())
	}

	if keys[2].Scope.DefaultOrigin() != "" {
		t.Errorf("unscoped key should have empty default origin, got %q", keys[2].Scope.DefaultOrigin())
	}
}

func TestParseKeysJSON_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr string
	}{
		{
			name:    "malformed JSON",
			json:    `{ not json }`,
			wantErr: "malformed API_KEYS_JSON",
		},
		{
			name:    "empty key name",
			json:    `[{"name": "", "secret": "sec"}]`,
			wantErr: "empty name",
		},
		{
			name:    "empty secret",
			json:    `[{"name": "k1", "secret": "  "}]`,
			wantErr: "empty secret",
		},
		{
			name: "duplicate key name",
			json: `[
				{"name": "k1", "secret": "sec1"},
				{"name": "k1", "secret": "sec2"}
			]`,
			wantErr: "duplicate API key name",
		},
		{
			name: "invalid origin in scope",
			json: `[
				{
					"name": "k1",
					"secret": "sec1",
					"scope": {
						"origins": ["unknown-origin"]
					}
				}
			]`,
			wantErr: "invalid origin in scope",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseKeysJSON(tc.json)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestScope_CheckUpload(t *testing.T) {
	scope := Scope{
		Origins:    []string{"ci", "manual"},
		Clusters:   []string{"prod-eu"},
		Namespaces: []string{"payments"},
		Projects:   []string{"my-org/pay-service"},
	}

	// Permitted
	if err := scope.CheckUpload("test-key", "ci", "prod-eu", "payments", "my-org/pay-service"); err != nil {
		t.Fatalf("expected upload permitted, got: %v", err)
	}

	// Origin mismatch
	err := scope.CheckUpload("test-key", "cluster-scan", "prod-eu", "payments", "my-org/pay-service")
	if err == nil {
		t.Fatal("expected origin mismatch error")
	}
	if !strings.Contains(err.Error(), `credential "test-key" is not permitted for origin "cluster-scan"`) {
		t.Fatalf("unexpected error message: %v", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Errorf("error leaked secrets: %v", err)
	}

	// Cluster mismatch
	err = scope.CheckUpload("test-key", "ci", "prod-us", "payments", "my-org/pay-service")
	if err == nil || !strings.Contains(err.Error(), `credential "test-key" is not permitted for cluster "prod-us"`) {
		t.Fatalf("unexpected cluster error: %v", err)
	}

	// Namespace mismatch
	err = scope.CheckUpload("test-key", "ci", "prod-eu", "auth", "my-org/pay-service")
	if err == nil || !strings.Contains(err.Error(), `credential "test-key" is not permitted for namespace "auth"`) {
		t.Fatalf("unexpected namespace error: %v", err)
	}

	// Project mismatch
	err = scope.CheckUpload("test-key", "ci", "prod-eu", "payments", "other/project")
	if err == nil || !strings.Contains(err.Error(), `credential "test-key" is not permitted for project "other/project"`) {
		t.Fatalf("unexpected project error: %v", err)
	}

	// Missing dimension when required
	err = scope.CheckUpload("test-key", "", "prod-eu", "payments", "my-org/pay-service")
	if err == nil || !strings.Contains(err.Error(), `credential "test-key" requires origin to be one of [ci, manual]`) {
		t.Fatalf("unexpected empty origin error: %v", err)
	}
}

func TestScope_UnscopedAllowsEverything(t *testing.T) {
	scope := Scope{}
	if err := scope.CheckUpload("open-key", "anything", "any-cluster", "any-ns", "any-proj"); err != nil {
		t.Fatalf("unscoped should allow anything, got: %v", err)
	}
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()
	if got := FromContext(ctx); got != nil {
		t.Fatalf("expected nil key from empty context, got %+v", got)
	}

	key := &Key{Name: "my-key", Secret: "sec-1"}
	ctxWithKey := WithKey(ctx, key)
	got := FromContext(ctxWithKey)
	if got == nil || got.Name != "my-key" {
		t.Fatalf("expected key with name 'my-key', got %+v", got)
	}
}
