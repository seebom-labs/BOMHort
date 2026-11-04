package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/seebom-labs/bomhort/backend/internal/apiclient"
	"github.com/seebom-labs/bomhort/backend/internal/depgraph"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// defaultPageSize is what a tool asks for when the caller says nothing. It is
// smaller than the API's own default of 50 on purpose: every row here ends up
// in a model's context window, and an agent that wants more can page.
const defaultPageSize = 25

// maxPageSize mirrors the API gateway's clamp so an oversized request is
// rejected here rather than being silently reshaped upstream.
const maxPageSize = 500

// registerTools installs the read-only tool surface.
//
// Read-only is a design constraint, not an omission: BOMHort's frontend is
// public and its policies are config files, so there is no mutation this
// server could legitimately offer. Every tool is annotated ReadOnlyHint so a
// client can tell an agent it never needs to ask for confirmation.
func registerTools(s *mcp.Server, c *apiclient.Client) {
	// Closed world: every answer comes from this BOMHort instance, never from
	// the internet. Read-only and idempotent are facts here, not hints we hope
	// hold — there is no write path in this binary at all.
	closedWorld := false
	readOnly := func(title string) *mcp.ToolAnnotations {
		return &mcp.ToolAnnotations{
			Title:          title,
			ReadOnlyHint:   true,
			IdempotentHint: true,
			OpenWorldHint:  &closedWorld,
		}
	}

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_projects",
		Title:       "List projects",
		Description: "List the projects known to this BOMHort instance with their de-duplicated SBOM, package and vulnerability counts. Optionally filtered by a name substring or by a grouping tag. Paginated.",
		Annotations: readOnly("List projects"),
	}, toolListProjects(c))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_project",
		Title:       "Get a project",
		Description: "Get one project as a unit: severity breakdown, license breakdown, where it is deployed, its newest version, and the list of its ingested versions. Counts are de-duplicated across versions — a package present in ten versions counts once.",
		Annotations: readOnly("Get a project"),
	}, toolGetProject(c))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "search_packages",
		Title:       "Search packages",
		Description: "Find which projects ship a package, and in which versions. Matches on package name substring; answers the blast-radius question 'who uses log4j-core?'.",
		Annotations: readOnly("Search packages"),
	}, toolSearchPackages(c))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_vulnerabilities",
		Title:       "List vulnerabilities",
		Description: "List vulnerability findings, instance-wide or scoped to one project. Each finding carries its VEX status, so a finding suppressed as not_affected is visible and labelled rather than hidden, and its dependency_scope (root, direct, transitive, unknown) so a CVE in a library the project pulls in itself reads differently from one buried deep in the tree. vuln_id is OSV's id (often GHSA-, GO- or PYSEC-); cve_id is the CVE of the same flaw when one exists, and aliases lists every other name.",
		Annotations: readOnly("List vulnerabilities"),
	}, toolListVulnerabilities(c))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_dashboard_stats",
		Title:       "Get dashboard statistics",
		Description: "Instance-wide totals: SBOMs, packages, findings by severity and dependency scope, VEX-suppressed findings and the license breakdown. Optionally narrowed to clusters, namespaces, projects, parents or tags.",
		Annotations: readOnly("Get dashboard statistics"),
	}, toolDashboardStats(c))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_affected_projects",
		Title:       "Get projects affected by a vulnerability",
		Description: "Which SBOMs ship a package affected by one vulnerability, with cluster, namespace, package version, severity, VEX status and dependency_scope. The id may be any alias (CVE, GHSA, GO-, PYSEC-). Optionally narrowed by the ownership filters.",
		Annotations: readOnly("Get affected projects"),
	}, toolAffectedProjects(c))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_sbom",
		Title:       "Get an SBOM",
		Description: "Get one SBOM document by its id: metadata, package count and severity breakdown, optionally with its vulnerability findings.",
		Annotations: readOnly("Get an SBOM"),
	}, toolGetSBOM(c))
}

// ── list_projects ──────────────────────────────────────────────────────────

type listProjectsInput struct {
	Page     uint64 `json:"page,omitempty" jsonschema:"1-based page number (default 1)"`
	PageSize uint64 `json:"page_size,omitempty" jsonschema:"rows per page (default 25, max 500)"`
	Search   string `json:"search,omitempty" jsonschema:"substring match on the project name"`
	Tag      string `json:"tag,omitempty" jsonschema:"restrict to projects carrying this grouping tag"`
}

type listProjectsOutput struct {
	Projects []dto.ProjectListItem `json:"projects"`
	Total    uint64                `json:"total"`
	Page     uint64                `json:"page"`
	PageSize uint64                `json:"page_size"`
}

func toolListProjects(c *apiclient.Client) mcp.ToolHandlerFor[listProjectsInput, listProjectsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in listProjectsInput) (*mcp.CallToolResult, listProjectsOutput, error) {
		page, pageSize, err := normalizePaging(in.Page, in.PageSize)
		if err != nil {
			return nil, listProjectsOutput{}, err
		}
		resp, err := c.ListProjects(ctx, page, pageSize, strings.TrimSpace(in.Search), strings.TrimSpace(in.Tag))
		if err != nil {
			return nil, listProjectsOutput{}, toolError(err)
		}
		return nil, listProjectsOutput{
			Projects: normalizeProjectList(resp.Data),
			Total:    resp.Total,
			Page:     resp.Page,
			PageSize: resp.PageSize,
		}, nil
	}
}

// ── get_project ────────────────────────────────────────────────────────────

type getProjectInput struct {
	Name string `json:"name" jsonschema:"the project name exactly as list_projects reports it"`
	// A project with 200 versions would otherwise push its whole history into
	// the answer, so the caller decides how much history it wants. A pointer
	// because 0 is a meaningful value here ("no version list at all") and JSON
	// cannot otherwise tell it apart from "not specified".
	MaxVersions *uint64 `json:"max_versions,omitempty" jsonschema:"how many of the project's versions to include (default 10, max 500, 0 for none)"`
}

type getProjectOutput struct {
	Project dto.ProjectDetail `json:"project"`
	// Versions is the newest-first page of the project's SBOMs. TotalVersions
	// is the full count, which is what ProjectDetail.SBOMCount reports too.
	Versions      []dto.SBOMListItem `json:"versions"`
	TotalVersions uint64             `json:"total_versions"`
}

func toolGetProject(c *apiclient.Client) mcp.ToolHandlerFor[getProjectInput, getProjectOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in getProjectInput) (*mcp.CallToolResult, getProjectOutput, error) {
		name := strings.TrimSpace(in.Name)
		if name == "" {
			return nil, getProjectOutput{}, errors.New("name is required")
		}

		detail, err := c.GetProject(ctx, name)
		if err != nil {
			return nil, getProjectOutput{}, toolError(err)
		}

		out := getProjectOutput{Project: normalizeProjectDetail(*detail), Versions: []dto.SBOMListItem{}, TotalVersions: detail.SBOMCount}

		maxVersions := uint64(10)
		if in.MaxVersions != nil {
			maxVersions = *in.MaxVersions
		}
		if maxVersions > maxPageSize {
			return nil, getProjectOutput{}, fmt.Errorf("max_versions must be <= %d", maxPageSize)
		}
		if maxVersions > 0 {
			sboms, err := c.ListProjectSBOMs(ctx, name, 1, maxVersions)
			if err != nil {
				return nil, getProjectOutput{}, toolError(err)
			}
			out.Versions = nonNil(sboms.Data)
			out.TotalVersions = sboms.Total
		}
		return nil, out, nil
	}
}

// ── search_packages ────────────────────────────────────────────────────────

type searchPackagesInput struct {
	Query    string `json:"query" jsonschema:"package name or substring, e.g. 'log4j-core' or 'golang.org/x/net'"`
	Page     uint64 `json:"page,omitempty" jsonschema:"1-based page number (default 1)"`
	PageSize uint64 `json:"page_size,omitempty" jsonschema:"rows per page (default 25, max 500)"`
}

type searchPackagesOutput struct {
	Query    string                       `json:"query"`
	Packages []dto.DependencySearchResult `json:"packages"`
	Total    uint64                       `json:"total"`
	Page     uint64                       `json:"page"`
	PageSize uint64                       `json:"page_size"`
}

func toolSearchPackages(c *apiclient.Client) mcp.ToolHandlerFor[searchPackagesInput, searchPackagesOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in searchPackagesInput) (*mcp.CallToolResult, searchPackagesOutput, error) {
		q := strings.TrimSpace(in.Query)
		if q == "" {
			return nil, searchPackagesOutput{}, errors.New("query is required")
		}
		page, pageSize, err := normalizePaging(in.Page, in.PageSize)
		if err != nil {
			return nil, searchPackagesOutput{}, err
		}
		resp, err := c.SearchPackages(ctx, q, page, pageSize)
		if err != nil {
			return nil, searchPackagesOutput{}, toolError(err)
		}
		return nil, searchPackagesOutput{
			Query:    resp.Query,
			Packages: normalizePackageResults(resp.Items),
			Total:    resp.TotalResults,
			Page:     resp.Page,
			PageSize: resp.PageSize,
		}, nil
	}
}

// ── list_vulnerabilities ───────────────────────────────────────────────────

type listVulnerabilitiesInput struct {
	Project   string `json:"project,omitempty" jsonschema:"scope the findings to one project; omit for the whole instance"`
	Severity  string `json:"severity,omitempty" jsonschema:"keep only findings of this severity: CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN"`
	Scope     string `json:"scope,omitempty" jsonschema:"keep only findings in packages of this dependency scope: root, direct, transitive or unknown (unknown = the SBOM carries no dependency graph)"`
	Cluster   string `json:"cluster,omitempty" jsonschema:"instance-wide only: keep findings of SBOMs in these clusters (comma-separated)"`
	Namespace string `json:"namespace,omitempty" jsonschema:"instance-wide only: keep findings of SBOMs in these namespaces (comma-separated)"`
	Parent    string `json:"parent,omitempty" jsonschema:"instance-wide only: keep findings of the projects grouped under these parents (comma-separated)"`
	Tag       string `json:"tag,omitempty" jsonschema:"instance-wide only: keep findings of SBOMs carrying any of these tags (comma-separated)"`
	Page      uint64 `json:"page,omitempty" jsonschema:"1-based page number (default 1)"`
	PageSize  uint64 `json:"page_size,omitempty" jsonschema:"rows per page (default 25, max 500)"`
}

type listVulnerabilitiesOutput struct {
	Project         string                      `json:"project,omitempty"`
	Vulnerabilities []dto.VulnerabilityListItem `json:"vulnerabilities"`
	Total           uint64                      `json:"total"`
	Page            uint64                      `json:"page"`
	PageSize        uint64                      `json:"page_size"`
}

func toolListVulnerabilities(c *apiclient.Client) mcp.ToolHandlerFor[listVulnerabilitiesInput, listVulnerabilitiesOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in listVulnerabilitiesInput) (*mcp.CallToolResult, listVulnerabilitiesOutput, error) {
		page, pageSize, err := normalizePaging(in.Page, in.PageSize)
		if err != nil {
			return nil, listVulnerabilitiesOutput{}, err
		}
		severity, err := normalizeSeverity(in.Severity)
		if err != nil {
			return nil, listVulnerabilitiesOutput{}, err
		}
		scope, err := normalizeScope(in.Scope)
		if err != nil {
			return nil, listVulnerabilitiesOutput{}, err
		}

		project := strings.TrimSpace(in.Project)
		owner := map[string]string{"cluster": in.Cluster, "namespace": in.Namespace, "parent": in.Parent, "tag": in.Tag}
		if project != "" && in.Cluster+in.Namespace+in.Parent+in.Tag != "" {
			return nil, listVulnerabilitiesOutput{}, errors.New("cluster, namespace, parent and tag filter the instance-wide listing; omit project to use them")
		}
		if project == "" {
			// Instance-wide: the API paginates, and a severity filter would
			// then mean "filter this page", which reads as a lie. Reject it
			// rather than return a number nobody can act on.
			if severity != "" {
				return nil, listVulnerabilitiesOutput{}, errors.New("severity filtering requires a project; the instance-wide listing is paginated server-side")
			}
			resp, err := c.ListVulnerabilities(ctx, page, pageSize, scope, owner)
			if err != nil {
				return nil, listVulnerabilitiesOutput{}, toolError(err)
			}
			return nil, listVulnerabilitiesOutput{
				Vulnerabilities: nonNil(resp.Data),
				Total:           resp.Total,
				Page:            resp.Page,
				PageSize:        resp.PageSize,
			}, nil
		}

		// The project endpoint answers with the project's distinct findings in
		// one response — de-duplication across versions is the point of #398
		// and cannot be done a page at a time. Paging therefore happens here,
		// over the complete, already de-duplicated set.
		items, err := c.ListProjectVulnerabilities(ctx, project, scope)
		if err != nil {
			return nil, listVulnerabilitiesOutput{}, toolError(err)
		}
		if severity != "" {
			filtered := items[:0:0]
			for _, it := range items {
				if strings.EqualFold(it.Severity, severity) {
					filtered = append(filtered, it)
				}
			}
			items = filtered
		}

		total := uint64(len(items))
		return nil, listVulnerabilitiesOutput{
			Project:         project,
			Vulnerabilities: nonNil(paginate(items, page, pageSize)),
			Total:           total,
			Page:            page,
			PageSize:        pageSize,
		}, nil
	}
}

// ── get_dashboard_stats / get_affected_projects ───────────────────────────

type ownerInput struct {
	Cluster   string `json:"cluster,omitempty" jsonschema:"keep SBOMs in these clusters (comma-separated)"`
	Namespace string `json:"namespace,omitempty" jsonschema:"keep SBOMs in these namespaces (comma-separated)"`
	Project   string `json:"project,omitempty" jsonschema:"keep SBOMs of these projects (comma-separated)"`
	Parent    string `json:"parent,omitempty" jsonschema:"keep the projects grouped under these parents (comma-separated)"`
	Tag       string `json:"tag,omitempty" jsonschema:"keep SBOMs carrying any of these tags (comma-separated)"`
}

func (o ownerInput) query() map[string]string {
	return map[string]string{"cluster": o.Cluster, "namespace": o.Namespace, "project": o.Project, "parent": o.Parent, "tag": o.Tag}
}

type dashboardStatsOutput struct {
	Stats dto.DashboardStats `json:"stats"`
}

func toolDashboardStats(c *apiclient.Client) mcp.ToolHandlerFor[ownerInput, dashboardStatsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ownerInput) (*mcp.CallToolResult, dashboardStatsOutput, error) {
		st, err := c.DashboardStats(ctx, in.query())
		if err != nil {
			return nil, dashboardStatsOutput{}, toolError(err)
		}
		st.LicenseBreakdown = nonNilMap(st.LicenseBreakdown)
		return nil, dashboardStatsOutput{Stats: *st}, nil
	}
}

type affectedProjectsInput struct {
	VulnID string `json:"vuln_id" jsonschema:"the vulnerability id or any alias, e.g. CVE-2024-45338 or GHSA-w32m-9786-jp63"`
	ownerInput
}

type affectedProjectsOutput struct {
	VulnID   string                `json:"vuln_id"`
	Affected []dto.AffectedProject `json:"affected"`
}

func toolAffectedProjects(c *apiclient.Client) mcp.ToolHandlerFor[affectedProjectsInput, affectedProjectsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in affectedProjectsInput) (*mcp.CallToolResult, affectedProjectsOutput, error) {
		id := strings.TrimSpace(in.VulnID)
		if id == "" {
			return nil, affectedProjectsOutput{}, errors.New("vuln_id is required")
		}
		rows, err := c.AffectedProjects(ctx, id, in.query())
		if err != nil {
			return nil, affectedProjectsOutput{}, toolError(err)
		}
		return nil, affectedProjectsOutput{VulnID: id, Affected: nonNil(rows)}, nil
	}
}

// ── get_sbom ───────────────────────────────────────────────────────────────

type getSBOMInput struct {
	SBOMID                 string `json:"sbom_id" jsonschema:"the SBOM uuid, as reported by get_project or list_projects"`
	IncludeVulnerabilities bool   `json:"include_vulnerabilities,omitempty" jsonschema:"also return this SBOM's findings (default false)"`
}

type getSBOMOutput struct {
	SBOM            dto.SBOMDetail              `json:"sbom"`
	Vulnerabilities []dto.VulnerabilityListItem `json:"vulnerabilities,omitempty"`
}

func toolGetSBOM(c *apiclient.Client) mcp.ToolHandlerFor[getSBOMInput, getSBOMOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in getSBOMInput) (*mcp.CallToolResult, getSBOMOutput, error) {
		id := strings.TrimSpace(in.SBOMID)
		if id == "" {
			return nil, getSBOMOutput{}, errors.New("sbom_id is required")
		}
		detail, err := c.GetSBOMDetail(ctx, id)
		if err != nil {
			return nil, getSBOMOutput{}, toolError(err)
		}
		out := getSBOMOutput{SBOM: *detail}
		if in.IncludeVulnerabilities {
			vulns, err := c.ListSBOMVulnerabilities(ctx, id)
			if err != nil {
				return nil, getSBOMOutput{}, toolError(err)
			}
			out.Vulnerabilities = nonNil(vulns)
		}
		return nil, out, nil
	}
}

// ── shared helpers ─────────────────────────────────────────────────────────

func normalizePaging(page, pageSize uint64) (uint64, uint64, error) {
	if page == 0 {
		page = 1
	}
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		return 0, 0, fmt.Errorf("page_size must be <= %d", maxPageSize)
	}
	return page, pageSize, nil
}

var knownSeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

func normalizeSeverity(raw string) (string, error) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	if s == "" {
		return "", nil
	}
	for _, known := range knownSeverities {
		if s == known {
			return s, nil
		}
	}
	return "", fmt.Errorf("unknown severity %q (want one of %s)", raw, strings.Join(knownSeverities, ", "))
}

// normalizeScope validates a dependency scope. Unlike severity it is filtered
// server-side on both endpoints, so it is allowed instance-wide: the total
// stays honest.
func normalizeScope(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return "", nil
	}
	if !depgraph.IsValidScope(s) {
		return "", fmt.Errorf("unknown dependency scope %q (want one of root, direct, transitive, unknown)", raw)
	}
	return s, nil
}

func paginate[T any](items []T, page, pageSize uint64) []T {
	start := (page - 1) * pageSize
	if start >= uint64(len(items)) {
		return nil
	}
	end := start + pageSize
	if end > uint64(len(items)) {
		end = uint64(len(items))
	}
	return items[start:end]
}

// nonNil turns a nil slice into an empty one so the JSON output carries [] and
// not null. Two reasons: an agent told "vulnerabilities: null" tends to report
// that it could not determine the vulnerabilities, and the SDK validates every
// result against the inferred output schema — a null where the schema says
// "array" or "object" is a protocol error, not a tool error, so it would break
// the session rather than the call.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func nonNilMap[K comparable, V any](m map[K]V) map[K]V {
	if m == nil {
		return map[K]V{}
	}
	return m
}

// normalizeProjectDetail fills the collection fields the read model leaves
// empty on a catalogue instance (no clusters, no namespaces, no tags).
func normalizeProjectDetail(d dto.ProjectDetail) dto.ProjectDetail {
	d.Tags = nonNil(d.Tags)
	d.Parents = nonNil(d.Parents)
	d.Children = nonNil(d.Children)
	d.Clusters = nonNil(d.Clusters)
	d.Namespaces = nonNil(d.Namespaces)
	d.LicenseBreakdown = nonNilMap(d.LicenseBreakdown)
	return d
}

func normalizeProjectList(items []dto.ProjectListItem) []dto.ProjectListItem {
	for i := range items {
		items[i].Tags = nonNil(items[i].Tags)
	}
	return nonNil(items)
}

func normalizePackageResults(items []dto.DependencySearchResult) []dto.DependencySearchResult {
	for i := range items {
		items[i].Versions = nonNil(items[i].Versions)
		items[i].Projects = nonNil(items[i].Projects)
	}
	return nonNil(items)
}

// toolError converts an upstream failure into a message a model can act on.
// A 404 is a fact about the data ("no such project"), not an outage, and
// saying so prevents the agent from retrying a request that will never work.
func toolError(err error) error {
	var se *apiclient.StatusError
	if errors.As(err, &se) && se.NotFound() {
		return fmt.Errorf("not found: %s", strings.TrimPrefix(se.Path, "/api/v1/"))
	}
	return err
}
