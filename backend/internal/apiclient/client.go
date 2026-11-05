// Package apiclient is a read-only HTTP client for the BOMHort REST API.
//
// It exists for the MCP server (#399), which is deliberately a *consumer* of
// the frozen REST contract rather than a second reader of ClickHouse. That
// costs one HTTP hop and buys three things: the MCP server needs no database
// credentials, it cannot expose a field the API does not expose, and every
// contract hole an agent trips over is a hole a UI or a CI script would hit
// too — which is the whole reason #398 was found.
//
// Only GET requests are implemented. There is no write path here by design;
// MCP write tools are explicitly out of scope for 1.0.
package apiclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// DefaultTimeout is used when Options.Timeout is zero.
const DefaultTimeout = 30 * time.Second

// maxErrorBody caps how much of a non-2xx response body is read back into the
// error message. Upstream errors are JSON one-liners; anything larger is a
// misrouted proxy page and does not belong in a log line.
const maxErrorBody = 4 << 10

// Options configures a Client.
type Options struct {
	// BaseURL is the API gateway root, e.g. "http://bomhort-api:8080".
	// A trailing slash and a trailing "/api/v1" are both tolerated.
	BaseURL string
	// APIKey is sent as X-API-Key, ServiceToken as Authorization: Bearer.
	// Both are optional; an API gateway with AUTH_ENABLED=false needs neither.
	APIKey       string
	ServiceToken string
	// Timeout bounds a single upstream request. Zero means DefaultTimeout.
	Timeout time.Duration
	// UserAgent identifies the caller in the gateway's access logs. Zero value
	// means "bomhort-mcp-server".
	UserAgent string
	// HTTPClient allows tests to inject a transport. Zero value means a client
	// with Timeout.
	HTTPClient *http.Client
}

// Client is a read-only BOMHort API client. It is safe for concurrent use.
type Client struct {
	baseURL      *url.URL
	http         *http.Client
	apiKey       string
	serviceToken string
	userAgent    string
}

// New validates the options and returns a Client.
func New(opts Options) (*Client, error) {
	raw := strings.TrimSpace(opts.BaseURL)
	if raw == "" {
		return nil, fmt.Errorf("apiclient: BaseURL is required")
	}
	// Operators copy the URL out of a browser, where it reads
	// ".../api/v1/projects". Accepting the prefix here avoids a confusing
	// 404 on ".../api/v1/api/v1/projects".
	raw = strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(raw, "/"), "/api/v1"), "/")

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("apiclient: invalid BaseURL %q: %w", opts.BaseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("apiclient: BaseURL %q must be http or https", opts.BaseURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("apiclient: BaseURL %q has no host", opts.BaseURL)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: timeout}
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = "bomhort-mcp-server"
	}

	return &Client{
		baseURL:      u,
		http:         hc,
		apiKey:       opts.APIKey,
		serviceToken: opts.ServiceToken,
		userAgent:    ua,
	}, nil
}

// BaseURL returns the normalised API root, for logging.
func (c *Client) BaseURL() string { return c.baseURL.String() }

// StatusError is returned when the API answers with a non-2xx status.
// Callers can distinguish "no such project" from "the API is down" without
// parsing strings.
type StatusError struct {
	StatusCode int
	Path       string
	Body       string
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("bomhort api: GET %s: %s", e.Path, http.StatusText(e.StatusCode))
	}
	return fmt.Sprintf("bomhort api: GET %s: %s: %s", e.Path, http.StatusText(e.StatusCode), e.Body)
}

// NotFound reports whether the API answered 404.
func (e *StatusError) NotFound() bool { return e.StatusCode == http.StatusNotFound }

// get performs a GET against path (which must start with "/" and may contain
// already-escaped segments) and decodes the JSON body into out.
//
// The URL is assembled as a string rather than through url.URL.Path, because
// assigning to Path re-escapes the '%' of an escaped segment: a project named
// "cncf/bomhort" would go out as "cncf%252Fbomhort" and 404.
func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	target := c.baseURL.String() + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("bomhort api: build request for %s: %w", path, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if c.serviceToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.serviceToken)
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("bomhort api: GET %s: %w", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only request

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return &StatusError{
			StatusCode: resp.StatusCode,
			Path:       path,
			Body:       strings.TrimSpace(string(body)),
		}
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("bomhort api: decode %s response: %w", path, err)
	}
	return nil
}

// pageQuery builds the page/page_size pair the API uses everywhere. Zero
// values are omitted so the server's own defaults apply rather than this
// client pinning them — the defaults are part of the contract, not of us.
// scopeQuery adds ?scope= to q (allocating it when nil) unless scope is "".
func scopeQuery(q url.Values, scope string) url.Values {
	if scope == "" {
		return q
	}
	if q == nil {
		q = url.Values{}
	}
	q.Set("scope", scope)
	return q
}

func pageQuery(page, pageSize uint64) url.Values {
	q := url.Values{}
	if page > 0 {
		q.Set("page", strconv.FormatUint(page, 10))
	}
	if pageSize > 0 {
		q.Set("page_size", strconv.FormatUint(pageSize, 10))
	}
	return q
}

// ListProjects returns one page of GET /api/v1/projects.
func (c *Client) ListProjects(ctx context.Context, page, pageSize uint64, search, tag string) (*dto.PaginatedResponse[dto.ProjectListItem], error) {
	q := pageQuery(page, pageSize)
	if search != "" {
		q.Set("search", search)
	}
	if tag != "" {
		q.Set("tag", tag)
	}
	var out dto.PaginatedResponse[dto.ProjectListItem]
	if err := c.get(ctx, "/api/v1/projects", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetProject returns GET /api/v1/projects/{name} — the de-duplicated project
// read model from #398.
func (c *Client) GetProject(ctx context.Context, name string) (*dto.ProjectDetail, error) {
	var out dto.ProjectDetail
	if err := c.get(ctx, "/api/v1/projects/"+url.PathEscape(name), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListProjectSBOMs returns one page of GET /api/v1/projects/{name}/sboms.
func (c *Client) ListProjectSBOMs(ctx context.Context, name string, page, pageSize uint64) (*dto.PaginatedResponse[dto.SBOMListItem], error) {
	var out dto.PaginatedResponse[dto.SBOMListItem]
	if err := c.get(ctx, "/api/v1/projects/"+url.PathEscape(name)+"/sboms", pageQuery(page, pageSize), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListProjectVulnerabilities returns GET /api/v1/projects/{name}/vulnerabilities.
// The endpoint is not paginated: it answers with the project's distinct
// findings, one row per (vuln_id, purl), latest VEX statement winning.
// scope narrows to one dependency scope (root, direct, transitive, unknown);
// "" means all.
func (c *Client) ListProjectVulnerabilities(ctx context.Context, name, scope string) ([]dto.VulnerabilityListItem, error) {
	var out []dto.VulnerabilityListItem
	if err := c.get(ctx, "/api/v1/projects/"+url.PathEscape(name)+"/vulnerabilities", scopeQuery(nil, scope), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListVulnerabilities returns one page of the instance-wide
// GET /api/v1/vulnerabilities. scope narrows to one dependency scope
// (root, direct, transitive, unknown); "" means all. owner holds the
// ownership filters (cluster, namespace, project, parent, tag; #459), each
// comma-separated; empty values are not sent.
func (c *Client) ListVulnerabilities(ctx context.Context, page, pageSize uint64, scope string, owner map[string]string) (*dto.PaginatedResponse[dto.VulnerabilityListItem], error) {
	q := ownerQuery(scopeQuery(pageQuery(page, pageSize), scope), owner)
	var out dto.PaginatedResponse[dto.VulnerabilityListItem]
	if err := c.get(ctx, "/api/v1/vulnerabilities", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DashboardStats returns GET /api/v1/stats/dashboard, narrowed by the
// ownership filters in owner (see ListVulnerabilities).
func (c *Client) DashboardStats(ctx context.Context, owner map[string]string) (*dto.DashboardStats, error) {
	var out dto.DashboardStats
	if err := c.get(ctx, "/api/v1/stats/dashboard", ownerQuery(url.Values{}, owner), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AffectedProjects returns GET /api/v1/vulnerabilities/{id}/affected-projects,
// narrowed by the ownership filters in owner. id may be any alias.
func (c *Client) AffectedProjects(ctx context.Context, id string, owner map[string]string) ([]dto.AffectedProject, error) {
	var out []dto.AffectedProject
	if err := c.get(ctx, "/api/v1/vulnerabilities/"+url.PathEscape(id)+"/affected-projects", ownerQuery(url.Values{}, owner), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func ownerQuery(q url.Values, owner map[string]string) url.Values {
	for k, v := range owner {
		if v != "" {
			q.Set(k, v)
		}
	}
	return q
}

// SearchPackages returns GET /api/v1/packages/search.
func (c *Client) SearchPackages(ctx context.Context, query string, page, pageSize uint64) (*dto.DependencySearchResponse, error) {
	q := pageQuery(page, pageSize)
	q.Set("q", query)
	var out dto.DependencySearchResponse
	if err := c.get(ctx, "/api/v1/packages/search", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetSBOMDetail returns GET /api/v1/sboms/{id}/detail.
func (c *Client) GetSBOMDetail(ctx context.Context, sbomID string) (*dto.SBOMDetail, error) {
	var out dto.SBOMDetail
	if err := c.get(ctx, "/api/v1/sboms/"+url.PathEscape(sbomID)+"/detail", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListSBOMVulnerabilities returns GET /api/v1/sboms/{id}/vulnerabilities.
func (c *Client) ListSBOMVulnerabilities(ctx context.Context, sbomID string) ([]dto.VulnerabilityListItem, error) {
	var out []dto.VulnerabilityListItem
	if err := c.get(ctx, "/api/v1/sboms/"+url.PathEscape(sbomID)+"/vulnerabilities", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Health pings GET /healthz. Used once at startup so a misconfigured base URL
// or a wrong token is reported by the process that owns it, instead of
// surfacing as a failing tool call in someone's agent transcript.
func (c *Client) Health(ctx context.Context) error {
	var out map[string]any
	return c.get(ctx, "/healthz", nil, &out)
}
