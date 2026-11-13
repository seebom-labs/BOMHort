package vexsub

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/goccy/go-json"
	"github.com/seebom-labs/bomhort/backend/internal/vex"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

const maxOCIManifestsPerTarget = 50

type ociIndex struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []ociDescriptor `json:"manifests"`
}

type ociManifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType"`
	Config        ociDescriptor     `json:"config"`
	Layers        []ociDescriptor   `json:"layers"`
	Annotations   map[string]string `json:"annotations"`
}

type ociDescriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType"`
	Annotations  map[string]string `json:"annotations"`
}

type ociReferrerTarget struct {
	scheme   string
	registry string
	repo     string
	digest   string
}

// FetchOCIReferrers queries an OCI Distribution 1.1 Referrers API (or falls
// back to a direct HTTP OpenVEX/CSAF endpoint) for VEX documents attached to
// container image digests (#525, #538).
func FetchOCIReferrers(ctx context.Context, client *http.Client, sourceURL string, knownPURLs []string) (SourceResult, error) {
	if sourceURL == "" {
		return SourceResult{Complete: true}, nil
	}

	client = ensureHTTPClient(client)
	targets, explicitReferrers := resolveOCITargets(sourceURL, knownPURLs)

	if len(targets) > 0 {
		tokenCache := make(map[string]string)
		var all []models.VEXStatement
		var errs []error
		succeeded := 0
		allComplete := true

		for _, target := range targets {
			res, err := fetchReferrersForTarget(ctx, client, target, sourceURL, tokenCache)
			if err != nil {
				errs = append(errs, err)
				allComplete = false
				continue
			}
			if !res.Complete {
				allComplete = false
			}
			succeeded++
			all = append(all, res.Statements...)
		}
		if succeeded == 0 && len(errs) > 0 {
			return SourceResult{}, errors.Join(errs...)
		}
		return SourceResult{
			Statements: all,
			Complete:   allComplete && len(errs) == 0 && succeeded > 0,
		}, nil
	}

	if explicitReferrers {
		return SourceResult{Complete: true}, nil
	}

	// Fallback for direct HTTP URLs serving an OpenVEX or CSAF JSON document directly.
	if !strings.HasPrefix(sourceURL, "http://") && !strings.HasPrefix(sourceURL, "https://") {
		return SourceResult{Complete: true}, nil
	}
	body, _, err := fetchBytes(ctx, client, sourceURL, map[string]string{"Accept": "application/json"})
	if err != nil {
		return SourceResult{}, err
	}
	stmts, err := parseVEXOrCSAF(body, sourceURL)
	if err != nil {
		return SourceResult{}, err
	}
	return SourceResult{
		Statements: stmts,
		Complete:   true,
	}, nil
}

func resolveOCITargets(sourceURL string, knownPURLs []string) ([]ociReferrerTarget, bool) {
	normalized := sourceURL
	if strings.HasPrefix(normalized, "oci://") {
		normalized = "https://" + strings.TrimPrefix(normalized, "oci://")
	} else if !strings.HasPrefix(normalized, "http://") && !strings.HasPrefix(normalized, "https://") {
		normalized = "https://" + normalized
	}

	u, err := url.Parse(normalized)
	if err != nil || u.Host == "" {
		return nil, false
	}

	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}

	// Case 1: explicit /v2/<repo>/referrers/<digest> URL
	cleanPath := strings.Trim(u.Path, "/")
	if strings.HasPrefix(cleanPath, "v2/") && strings.Contains(cleanPath, "/referrers/sha256:") {
		inner := strings.TrimPrefix(cleanPath, "v2/")
		repo, digest, ok := strings.Cut(inner, "/referrers/")
		if ok && repo != "" && strings.HasPrefix(digest, "sha256:") {
			return []ociReferrerTarget{{scheme: scheme, registry: u.Host, repo: repo, digest: digest}}, true
		}
	}

	// Case 2: direct JSON endpoint (for non-registry test or direct VEX URLs)
	if strings.HasSuffix(strings.ToLower(cleanPath), ".json") {
		return nil, false
	}

	// Case 3: reference with explicit @sha256:... in sourceURL
	if repoWithDigest, digest, hasDigest := strings.Cut(cleanPath, "@"); hasDigest && strings.HasPrefix(digest, "sha256:") {
		if repoWithDigest != "" {
			return []ociReferrerTarget{{scheme: scheme, registry: u.Host, repo: repoWithDigest, digest: digest}}, true
		}
	}

	// Case 3: registry host (or registry/prefix) paired with pkg:oci/... digests in knownPURLs
	var targets []ociReferrerTarget
	seen := make(map[string]struct{})
	sourceRepoPrefix := cleanPath

	for _, rawPURL := range knownPURLs {
		p, ok := ParsePURL(rawPURL)
		if !ok || p.Type != "oci" || !strings.HasPrefix(p.Version, "sha256:") {
			continue
		}
		targetReg, targetRepo := resolveOCIRepoFromPURL(u.Host, sourceRepoPrefix, p)
		if targetReg == "" || targetRepo == "" {
			continue
		}
		if !strings.EqualFold(targetReg, u.Host) {
			continue
		}
		key := targetReg + "/" + targetRepo + "@" + p.Version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, ociReferrerTarget{
			scheme:   scheme,
			registry: targetReg,
			repo:     targetRepo,
			digest:   p.Version,
		})
	}
	return targets, len(targets) > 0
}

func resolveOCIRepoFromPURL(sourceHost, sourceRepoPrefix string, p ParsedPURL) (string, string) {
	if repoURL := strings.TrimSpace(p.Qualifiers["repository_url"]); repoURL != "" {
		repoURL = strings.TrimPrefix(repoURL, "https://")
		repoURL = strings.TrimPrefix(repoURL, "http://")
		host, repo, ok := strings.Cut(strings.Trim(repoURL, "/"), "/")
		if ok && host != "" && repo != "" {
			if sourceRepoPrefix != "" && repo != sourceRepoPrefix && !strings.HasPrefix(repo, sourceRepoPrefix+"/") {
				return "", ""
			}
			return host, repo
		}
		// repository_url without host (for example "library/nginx")
		if sourceRepoPrefix != "" && repoURL != sourceRepoPrefix {
			return "", ""
		}
		return sourceHost, strings.Trim(repoURL, "/")
	}

	repo := p.Name
	if p.Namespace != "" {
		repo = p.Namespace + "/" + p.Name
	}
	if sourceRepoPrefix != "" {
		if repo == sourceRepoPrefix || strings.HasPrefix(repo, sourceRepoPrefix+"/") {
			return sourceHost, repo
		}
		return sourceHost, sourceRepoPrefix
	}
	return sourceHost, repo
}

func fetchReferrersForTarget(ctx context.Context, client *http.Client, target ociReferrerTarget, sourceURL string, tokenCache map[string]string) (SourceResult, error) {
	cacheKey := target.registry + "/" + target.repo
	refURL := fmt.Sprintf("%s://%s/v2/%s/referrers/%s", target.scheme, target.registry, target.repo, target.digest)
	body, err := fetchOCIAuth(ctx, client, refURL, "application/vnd.oci.image.index.v1+json", cacheKey, tokenCache)
	if err != nil {
		var he *httpError
		if errors.As(err, &he) && he.StatusCode == http.StatusNotFound {
			return SourceResult{Complete: true}, nil
		}
		return SourceResult{}, err
	}

	var index ociIndex
	if err := json.Unmarshal(body, &index); err != nil {
		return SourceResult{}, fmt.Errorf("decoding OCI referrers index from %s: %w", refURL, err)
	}

	var all []models.VEXStatement
	checked := 0
	capped := false
	hasErrors := false
	for _, desc := range index.Manifests {
		if desc.Digest == "" {
			continue
		}
		if desc.ArtifactType != "" && !isVEXMediaType(desc.ArtifactType) {
			continue
		}
		checked++
		if checked > maxOCIManifestsPerTarget {
			capped = true
			break
		}

		manifestURL := fmt.Sprintf("%s://%s/v2/%s/manifests/%s", target.scheme, target.registry, target.repo, desc.Digest)
		mBody, err := fetchOCIAuth(ctx, client, manifestURL, "application/vnd.oci.image.manifest.v1+json, application/json", cacheKey, tokenCache)
		if err != nil {
			hasErrors = true
			continue
		}
		var manifest ociManifest
		if err := json.Unmarshal(mBody, &manifest); err != nil {
			hasErrors = true
			continue
		}

		manifestIsVEX := isVEXMediaType(manifest.ArtifactType) || isVEXMediaType(manifest.Config.MediaType) || isVEXMediaType(desc.ArtifactType)
		for _, layer := range manifest.Layers {
			if layer.Digest == "" {
				continue
			}
			if !isVEXMediaType(layer.MediaType) && !(manifestIsVEX && strings.Contains(strings.ToLower(layer.MediaType), "json")) {
				continue
			}
			blobURL := fmt.Sprintf("%s://%s/v2/%s/blobs/%s", target.scheme, target.registry, target.repo, layer.Digest)
			blob, err := fetchOCIAuth(ctx, client, blobURL, "application/json", cacheKey, tokenCache)
			if err != nil {
				hasErrors = true
				continue
			}
			stmts, err := parseVEXOrCSAF(blob, sourceURL)
			if err == nil {
				all = append(all, stmts...)
			} else {
				hasErrors = true
			}
		}
	}

	return SourceResult{
		Statements: all,
		Complete:   !capped && !hasErrors,
	}, nil
}

func fetchOCIAuth(ctx context.Context, client *http.Client, rawURL, accept, cacheKey string, tokenCache map[string]string) ([]byte, error) {
	headers := map[string]string{"Accept": accept}
	if tok := tokenCache[cacheKey]; tok != "" {
		headers["Authorization"] = "Bearer " + tok
	}

	body, respHeaders, err := fetchBytes(ctx, client, rawURL, headers)
	if err == nil {
		return body, nil
	}

	var he *httpError
	if !errors.As(err, &he) || he.StatusCode != http.StatusUnauthorized {
		return nil, err
	}

	token, authErr := fetchOCIBearerToken(ctx, client, respHeaders.Get("Www-Authenticate"))
	if authErr != nil || token == "" {
		return nil, err
	}
	tokenCache[cacheKey] = token
	headers["Authorization"] = "Bearer " + token

	body, _, retryErr := fetchBytes(ctx, client, rawURL, headers)
	return body, retryErr
}

func fetchOCIBearerToken(ctx context.Context, client *http.Client, challenge string) (string, error) {
	challenge = strings.TrimSpace(challenge)
	if len(challenge) < 7 || !strings.EqualFold(challenge[:7], "Bearer ") {
		return "", fmt.Errorf("unsupported auth challenge")
	}

	params := parseBearerParams(challenge[7:])
	realm := params["realm"]
	if realm == "" {
		return "", fmt.Errorf("missing bearer realm")
	}

	tokenURL, err := url.Parse(realm)
	if err != nil {
		return "", err
	}
	q := tokenURL.Query()
	if svc := params["service"]; svc != "" {
		q.Set("service", svc)
	}
	if scope := params["scope"]; scope != "" {
		q.Set("scope", scope)
	}
	tokenURL.RawQuery = q.Encode()

	body, _, err := fetchBytes(ctx, client, tokenURL.String(), map[string]string{"Accept": "application/json"})
	if err != nil {
		return "", err
	}

	var resp struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}
	if resp.Token != "" {
		return resp.Token, nil
	}
	return resp.AccessToken, nil
}

func parseBearerParams(raw string) map[string]string {
	params := make(map[string]string)
	for _, part := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.Trim(strings.TrimSpace(v), `"`)
		params[k] = v
	}
	return params
}

func isVEXMediaType(mt string) bool {
	lower := strings.ToLower(strings.TrimSpace(mt))
	return strings.Contains(lower, "openvex") ||
		strings.Contains(lower, "csaf") ||
		strings.Contains(lower, "vex")
}

func parseVEXOrCSAF(body []byte, sourceURL string) ([]models.VEXStatement, error) {
	if res, err := vex.Parse(bytes.NewReader(body), sourceURL); err == nil && len(res.Statements) > 0 {
		for i := range res.Statements {
			stampUpstream(&res.Statements[i], sourceURL)
		}
		return res.Statements, nil
	}
	return ParseCSAF(bytes.NewReader(body), sourceURL)
}
