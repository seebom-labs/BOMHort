// Package apikey manages named, scoped API keys (#456) for API authentication
// and upload authorization.
//
// A named key pairs a secret with an identifier (attributed in sboms.uploaded_by)
// and an optional scope restricting which origins, clusters, namespaces, or
// projects the credential can upload to.
//
// The Scope type is designed to be reused by #520 for workload identity trust rules.
package apikey

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ValidOrigins defines the allowed origin values (#455, #456).
var ValidOrigins = []string{
	"cluster-scan",
	"ci",
	"registry",
	"vendor",
	"manual",
}

var validOriginMap = map[string]bool{
	"cluster-scan": true,
	"ci":           true,
	"registry":     true,
	"vendor":       true,
	"manual":       true,
}

func isValidOrigin(o string) bool {
	return validOriginMap[normalizeOrigin(o)]
}

func normalizeOrigin(o string) string {
	return strings.ToLower(strings.TrimSpace(o))
}

// Scope defines the dimensions an API key is restricted to (#456).
// An empty slice on any dimension means unrestricted for that dimension.
type Scope struct {
	Origins    []string `json:"origins,omitempty"`
	Clusters   []string `json:"clusters,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
	Projects   []string `json:"projects,omitempty"`
}

// Key represents a named API key with an optional dimension scope (#456).
type Key struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
	Scope  Scope  `json:"scope,omitempty"`
}

// Validate checks that the scope entries are valid.
func (s *Scope) Validate() error {
	for i, o := range s.Origins {
		trimmed := normalizeOrigin(o)
		if trimmed == "" || !isValidOrigin(trimmed) {
			return fmt.Errorf("invalid origin in scope: %q (must be one of %s)", o, strings.Join(ValidOrigins, ", "))
		}
		s.Origins[i] = trimmed
	}
	for i, c := range s.Clusters {
		s.Clusters[i] = strings.TrimSpace(c)
	}
	for i, ns := range s.Namespaces {
		s.Namespaces[i] = strings.TrimSpace(ns)
	}
	for i, p := range s.Projects {
		s.Projects[i] = strings.TrimSpace(p)
	}
	return nil
}

// DefaultOrigin returns the single allowed origin if exactly one is scoped,
// or empty string if unscoped or multiple origins are allowed.
func (s Scope) DefaultOrigin() string {
	if len(s.Origins) == 1 {
		return s.Origins[0]
	}
	return ""
}

// DefaultCluster returns the single allowed cluster if exactly one is scoped,
// or empty string if unscoped or multiple clusters are allowed.
func (s Scope) DefaultCluster() string {
	if len(s.Clusters) == 1 {
		return s.Clusters[0]
	}
	return ""
}

// DefaultNamespace returns the single allowed namespace if exactly one is scoped,
// or empty string if unscoped or multiple namespaces are allowed.
func (s Scope) DefaultNamespace() string {
	if len(s.Namespaces) == 1 {
		return s.Namespaces[0]
	}
	return ""
}

// DefaultProject returns the single allowed project if exactly one is scoped,
// or empty string if unscoped or multiple projects are allowed.
func (s Scope) DefaultProject() string {
	if len(s.Projects) == 1 {
		return s.Projects[0]
	}
	return ""
}

func sliceContains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// AllowsOrigin checks whether the given origin is permitted by this scope.
func (s Scope) AllowsOrigin(o string) bool {
	if len(s.Origins) == 0 {
		return true
	}
	return sliceContains(s.Origins, normalizeOrigin(o))
}

// AllowsCluster checks whether the given cluster is permitted by this scope.
func (s Scope) AllowsCluster(c string) bool {
	if len(s.Clusters) == 0 {
		return true
	}
	return sliceContains(s.Clusters, strings.TrimSpace(c))
}

// AllowsNamespace checks whether the given namespace is permitted by this scope.
func (s Scope) AllowsNamespace(ns string) bool {
	if len(s.Namespaces) == 0 {
		return true
	}
	return sliceContains(s.Namespaces, strings.TrimSpace(ns))
}

// AllowsProject checks whether the given project is permitted by this scope.
func (s Scope) AllowsProject(p string) bool {
	if len(s.Projects) == 0 {
		return true
	}
	return sliceContains(s.Projects, strings.TrimSpace(p))
}

// CheckUpload checks whether an upload with the given dimensions is authorized
// under this key. Returns nil if permitted, or an error detailing the violation.
// The error mentions keyName and the rejected dimension; it never reveals secrets.
func (s Scope) CheckUpload(keyName, originVal, cluster, namespace, project string) error {
	if !s.AllowsOrigin(originVal) {
		if originVal == "" {
			return fmt.Errorf("credential %q requires origin to be one of [%s]", keyName, strings.Join(s.Origins, ", "))
		}
		return fmt.Errorf("credential %q is not permitted for origin %q", keyName, originVal)
	}
	if !s.AllowsCluster(cluster) {
		if cluster == "" {
			return fmt.Errorf("credential %q requires cluster to be one of [%s]", keyName, strings.Join(s.Clusters, ", "))
		}
		return fmt.Errorf("credential %q is not permitted for cluster %q", keyName, cluster)
	}
	if !s.AllowsNamespace(namespace) {
		if namespace == "" {
			return fmt.Errorf("credential %q requires namespace to be one of [%s]", keyName, strings.Join(s.Namespaces, ", "))
		}
		return fmt.Errorf("credential %q is not permitted for namespace %q", keyName, namespace)
	}
	if !s.AllowsProject(project) {
		if project == "" {
			return fmt.Errorf("credential %q requires project to be one of [%s]", keyName, strings.Join(s.Projects, ", "))
		}
		return fmt.Errorf("credential %q is not permitted for project %q", keyName, project)
	}
	return nil
}

// ParseKeysJSON parses and validates a JSON array of Key objects from an
// API_KEYS_JSON string. Returns nil, nil if raw is empty or whitespace.
func ParseKeysJSON(raw string) ([]Key, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	var keys []Key
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		return nil, fmt.Errorf("malformed API_KEYS_JSON: %w", err)
	}

	seenNames := make(map[string]struct{}, len(keys))
	for i := range keys {
		k := &keys[i]
		k.Name = strings.TrimSpace(k.Name)
		k.Secret = strings.TrimSpace(k.Secret)
		if k.Name == "" {
			return nil, fmt.Errorf("key at index %d has empty name", i)
		}
		if k.Secret == "" {
			return nil, fmt.Errorf("key %q has empty secret", k.Name)
		}
		if _, exists := seenNames[k.Name]; exists {
			return nil, fmt.Errorf("duplicate API key name %q", k.Name)
		}
		seenNames[k.Name] = struct{}{}

		if err := k.Scope.Validate(); err != nil {
			return nil, fmt.Errorf("key %q has invalid scope: %w", k.Name, err)
		}
	}

	return keys, nil
}

type contextKey struct{}

// WithKey stores the authenticated Key in the context.
func WithKey(ctx context.Context, key *Key) context.Context {
	return context.WithValue(ctx, contextKey{}, key)
}

// FromContext retrieves the authenticated Key from the context, or nil.
func FromContext(ctx context.Context) *Key {
	if v, ok := ctx.Value(contextKey{}).(*Key); ok {
		return v
	}
	return nil
}
