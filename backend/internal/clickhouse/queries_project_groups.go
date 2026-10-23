package clickhouse

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/projectgroup"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// Parent grouping of projects (internal/projectgroup).
//
// The parent is resolved at query time in Go, from one row of signals per
// project. That keeps the rules (owner extraction per forge and purl type, the
// ambiguity guard, the mapping file) testable without a database, and lets a
// changed mapping file take effect without re-ingesting. Projects are the
// low-cardinality dimension (50–5 000 per instance), so reading all of them is
// cheap next to any query that touches packages or findings.

// QueryProjectSignals returns the grouping signals of every project: for each
// one the newest non-empty explicit parent, source_repo, root purl and
// supplier, the newest document name, and the union of its tags.
func (c *Client) QueryProjectSignals(ctx context.Context) ([]projectgroup.Signals, error) {
	rows, err := c.Conn.Query(ctx, fmt.Sprintf(`
		SELECT
			project_name,
			argMaxIf(parent, ingested_at, parent != '') AS explicit_parent,
			arraySort(groupUniqArrayArray(tags)) AS all_tags,
			argMaxIf(source_repo, ingested_at, source_repo != '') AS repo,
			argMax(document_name, ingested_at) AS doc_name,
			argMaxIf(root_purl, ingested_at, root_purl != '') AS purl,
			argMaxIf(supplier, ingested_at, supplier != '') AS supplier_name
		FROM (
			SELECT
				s.ingested_at AS ingested_at,
				s.parent AS parent,
				s.tags AS tags,
				s.source_repo AS source_repo,
				s.document_name AS document_name,
				s.root_purl AS root_purl,
				s.supplier AS supplier,
				%s AS project_name
			FROM (SELECT * FROM sboms FINAL) AS s
		)
		GROUP BY project_name
	`, projectKeyExpr))
	if err != nil {
		return nil, fmt.Errorf("failed to query project signals: %w", err)
	}
	defer rows.Close()

	var out []projectgroup.Signals
	for rows.Next() {
		var s projectgroup.Signals
		if err := rows.Scan(&s.Project, &s.ExplicitParent, &s.Tags, &s.SourceRepo, &s.DocumentName, &s.RootPURL, &s.Supplier); err != nil {
			return nil, fmt.Errorf("failed to scan project signals: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// AnnotateParents sets Parent/ParentSource on listed projects from resolved
// assignments.
func AnnotateParents(items []dto.ProjectListItem, assignments map[string]projectgroup.Assignment) {
	for i := range items {
		if a, ok := assignments[items[i].ProjectName]; ok {
			items[i].Parent = a.Parent
			items[i].ParentSource = string(a.Source)
		}
	}
}

// AnnotateProjectDetail sets the parent and the children of one project.
func AnnotateProjectDetail(d *dto.ProjectDetail, assignments map[string]projectgroup.Assignment) {
	if a, ok := assignments[d.ProjectName]; ok {
		d.Parent, d.ParentSource, d.ParentOwner = a.Parent, string(a.Source), a.Owner
	}
	d.Children = childrenOf(d.ProjectName, assignments)
}

func childrenOf(name string, assignments map[string]projectgroup.Assignment) []string {
	children := []string{}
	for project, a := range assignments {
		if a.Parent == name {
			children = append(children, project)
		}
	}
	sort.Strings(children)
	return children
}

// groupName is the group a project is listed under: its parent, or itself.
// A project that other projects name as their parent always heads its own
// group, even if it has a parent of its own — the hierarchy is one level deep.
func groupName(project string, assignments map[string]projectgroup.Assignment, heads map[string]bool) string {
	if heads[project] {
		return project
	}
	if a, ok := assignments[project]; ok {
		return a.Parent
	}
	return project
}

// QueryProjectGroups lists projects grouped by their resolved parent, paged
// by group. search matches the group name or any member name; tag restricts
// the members to projects carrying it, like QueryProjects.
func (c *Client) QueryProjectGroups(ctx context.Context, assignments map[string]projectgroup.Assignment, page, pageSize uint64, search, tag string) (*dto.PaginatedResponse[dto.ProjectGroupItem], error) {
	if page == 0 {
		page = 1
	}

	projects, err := c.queryAllProjectRows(ctx, tag)
	if err != nil {
		return nil, err
	}
	AnnotateParents(projects, assignments)

	heads := make(map[string]bool)
	for _, a := range assignments {
		heads[a.Parent] = true
	}

	byGroup := make(map[string][]dto.ProjectListItem)
	isProject := make(map[string]bool)
	for _, p := range projects {
		g := groupName(p.ProjectName, assignments, heads)
		byGroup[g] = append(byGroup[g], p)
		if g == p.ProjectName {
			isProject[g] = true
		}
	}

	needle := strings.ToLower(search)
	names := make([]string, 0, len(byGroup))
	for g, members := range byGroup {
		if needle == "" || strings.Contains(strings.ToLower(g), needle) || anyMemberContains(members, needle) {
			names = append(names, g)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		li, lj := strings.ToLower(names[i]), strings.ToLower(names[j])
		if li != lj {
			return li < lj
		}
		return names[i] < names[j]
	})

	total := uint64(len(names))
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	pageNames := names[start:end]

	items := make([]dto.ProjectGroupItem, 0, len(pageNames))
	var pageMembers []dto.ProjectListItem
	for _, g := range pageNames {
		items = append(items, buildGroup(g, isProject[g], byGroup[g], assignments))
		pageMembers = append(pageMembers, byGroup[g]...)
	}

	if len(items) > 0 {
		// Member counts (each member de-duplicated over its own versions),
		// then group counts (de-duplicated over all members' versions).
		c.enrichProjectStats(ctx, pageMembers)
		memberStats := make(map[string]dto.ProjectListItem, len(pageMembers))
		for _, m := range pageMembers {
			memberStats[m.ProjectName] = m
		}
		for i := range items {
			for j := range items[i].Members {
				items[i].Members[j].PackageCount = memberStats[items[i].Members[j].ProjectName].PackageCount
				items[i].Members[j].VulnCount = memberStats[items[i].Members[j].ProjectName].VulnCount
			}
		}
		c.enrichGroupStats(ctx, items)
	}

	return &dto.PaginatedResponse[dto.ProjectGroupItem]{
		Data:     items,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

func anyMemberContains(members []dto.ProjectListItem, needle string) bool {
	for _, m := range members {
		if strings.Contains(strings.ToLower(m.ProjectName), needle) {
			return true
		}
	}
	return false
}

// buildGroup assembles one group row from its members (stats other than the
// de-duplicated counts, which enrichGroupStats fills).
func buildGroup(name string, isProject bool, members []dto.ProjectListItem, assignments map[string]projectgroup.Assignment) dto.ProjectGroupItem {
	sort.Slice(members, func(i, j int) bool {
		if (members[i].ProjectName == name) != (members[j].ProjectName == name) {
			return members[i].ProjectName == name
		}
		return members[i].ProjectName < members[j].ProjectName
	})

	g := dto.ProjectGroupItem{
		Name:         name,
		IsProject:    isProject,
		ProjectCount: uint64(len(members)),
		Tags:         []string{},
		Sources:      []string{},
		Members:      members,
	}
	tags := map[string]bool{}
	sources := map[string]bool{}
	var latest string
	for _, m := range members {
		g.SBOMCount += m.SBOMCount
		if m.LatestIngested > latest {
			latest = m.LatestIngested // RFC3339 UTC sorts lexically
		}
		for _, t := range m.Tags {
			tags[t] = true
		}
		if a, ok := assignments[m.ProjectName]; ok && m.ProjectName != name {
			sources[string(a.Source)] = true
			if g.Owner == "" {
				g.Owner = a.Owner
			}
		}
	}
	g.LatestIngested = latest
	for t := range tags {
		g.Tags = append(g.Tags, t)
	}
	sort.Strings(g.Tags)
	for s := range sources {
		g.Sources = append(g.Sources, s)
	}
	sort.Strings(g.Sources)
	return g
}

// queryAllProjectRows returns every project (optionally restricted to those
// carrying tag) with its SBOM count, newest ingest and newest SBOM id. The
// same aggregation as QueryProjects, without paging.
func (c *Client) queryAllProjectRows(ctx context.Context, tag string) ([]dto.ProjectListItem, error) {
	tagWhere := ""
	var args []interface{}
	if tag != "" {
		tagWhere = "WHERE has(s.tags, ?)"
		args = append(args, tag)
	}
	rows, err := c.Conn.Query(ctx, fmt.Sprintf(`
		SELECT
			project_name,
			count() AS sbom_count,
			max(s.ingested_at) AS latest_ingested,
			argMax(toString(s.sbom_id), `+fmt.Sprintf(latestKey, "s")+`) AS latest_sbom_id,
			arraySort(groupUniqArrayArray(s.tags)) AS project_tags
		FROM (
			SELECT
				s.sbom_id,
				s.ingested_at,
				s.document_version,
				s.tags,
				%s AS project_name
			FROM (SELECT * FROM sboms FINAL) AS s
			%s
		) AS s
		GROUP BY project_name
	`, projectKeyExpr, tagWhere), args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query projects for grouping: %w", err)
	}
	defer rows.Close()

	var items []dto.ProjectListItem
	for rows.Next() {
		var item dto.ProjectListItem
		var latest time.Time
		if err := rows.Scan(&item.ProjectName, &item.SBOMCount, &latest, &item.LatestSBOMID, &item.Tags); err != nil {
			return nil, fmt.Errorf("failed to scan project row: %w", err)
		}
		item.LatestIngested = latest.UTC().Format(time.RFC3339)
		items = append(items, item)
	}
	return items, rows.Err()
}

// enrichGroupStats fills PackageCount and VulnCount of each group,
// de-duplicated across all SBOMs of all its members: a component shipped by
// argo and by argo-cd/argo-workflows counts once for the argo group.
//
// transform() maps each member project to its group inside the query, so one
// pass per table covers the whole page. Errors are logged and leave the
// counts at zero, like enrichProjectStats.
func (c *Client) enrichGroupStats(ctx context.Context, items []dto.ProjectGroupItem) {
	var memberNames, groupOf []string
	for _, g := range items {
		for _, m := range g.Members {
			memberNames = append(memberNames, m.ProjectName)
			groupOf = append(groupOf, g.Name)
		}
	}
	if len(memberNames) == 0 {
		return
	}

	pkgQuery := fmt.Sprintf(`
		SELECT transform(toString(s.project_name), ?, ?, '') AS grp, uniqExact(pk.pkg_key) AS package_count
		FROM %s AS s
		INNER JOIN (
			SELECT p.sbom_id AS sbom_id, arrayJoin(%s) AS pkg_key
			FROM %s AS p
		) AS pk ON pk.sbom_id = s.sbom_id
		GROUP BY grp
	`, projectSBOMs, packageKeyExpr, projectRows("*", "sbom_packages", "s.project_name IN (?)"))
	pkgs := c.groupCounts(ctx, "package", pkgQuery, memberNames, groupOf)

	vulnQuery := fmt.Sprintf(`
		SELECT transform(toString(s.project_name), ?, ?, '') AS grp, uniqExact(v.vuln_id, v.purl) AS vuln_count
		FROM %s AS s
		INNER JOIN %s AS v
			ON v.sbom_id = s.sbom_id
		GROUP BY grp
	`, projectSBOMs, projectRows("sbom_id, vuln_id, purl", "vulnerabilities", "s.project_name IN (?)"))
	vulns := c.groupCounts(ctx, "vulnerability", vulnQuery, memberNames, groupOf)

	for i := range items {
		items[i].PackageCount = pkgs[items[i].Name]
		items[i].VulnCount = vulns[items[i].Name]
	}
}

func (c *Client) groupCounts(ctx context.Context, what, query string, memberNames, groupOf []string) map[string]uint64 {
	out := make(map[string]uint64)
	rows, err := c.Conn.Query(ctx, query, memberNames, groupOf, memberNames)
	if err != nil {
		log.Printf("WARNING: project group %s counts: %v", what, err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var g string
		var n uint64
		if err := rows.Scan(&g, &n); err != nil {
			log.Printf("WARNING: project group %s counts: %v", what, err)
			return out
		}
		out[g] = n
	}
	if err := rows.Err(); err != nil {
		log.Printf("WARNING: project group %s counts: %v", what, err)
	}
	return out
}
