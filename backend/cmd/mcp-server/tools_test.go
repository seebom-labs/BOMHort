package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/seebom-labs/bomhort/backend/internal/apiclient"
)

// newSession wires a real MCP client to a real MCP server over the SDK's
// in-memory transport, with the tool handlers pointed at a stub API. The whole
// path an agent takes — schema validation, JSON-RPC, structured output — is
// exercised, which is the point: #399 exists because a consumer finds holes an
// internal caller does not.
func newSession(t *testing.T, api http.Handler) *mcp.ClientSession {
	t.Helper()

	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	client, err := apiclient.New(apiclient.Options{BaseURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("apiclient.New: %v", err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "bomhort", Version: "test"}, nil)
	registerTools(server, client)

	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, st, nil); err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): protocol error: %v", name, err)
	}
	return res
}

func decodeOutput(t *testing.T, res *mcp.CallToolResult, out any) {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool returned an error result: %s", resultText(res))
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("unmarshal structured content %s: %v", raw, err)
	}
}

func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// routes is a tiny stand-in for the API gateway: exact paths only, so a tool
// asking for the wrong endpoint fails loudly instead of matching a prefix.
func routes(t *testing.T, m map[string]string) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	for path, body := range m {
		body := body
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	})
	return mux
}

// The tool surface is contract: 1.0 freezes these seven names and their
// read-only annotations. A sixth tool, or a tool that loses ReadOnlyHint,
// should fail here before it reaches a consumer.
func TestToolSurfaceIsReadOnlyAndComplete(t *testing.T) {
	cs := newSession(t, routes(t, nil))

	want := map[string]bool{
		"list_projects":         false,
		"get_project":           false,
		"search_packages":       false,
		"list_vulnerabilities":  false,
		"get_sbom":              false,
		"get_dashboard_stats":   false,
		"get_affected_projects": false,
	}

	for tool, err := range cs.Tools(context.Background(), nil) {
		if err != nil {
			t.Fatalf("list tools: %v", err)
		}
		if _, ok := want[tool.Name]; !ok {
			t.Errorf("unexpected tool %q — the 1.0 surface is read-only and fixed", tool.Name)
			continue
		}
		want[tool.Name] = true

		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("tool %q is not annotated read-only", tool.Name)
		}
		if tool.Description == "" {
			t.Errorf("tool %q has no description", tool.Name)
		}
		if tool.InputSchema == nil {
			t.Errorf("tool %q has no input schema", tool.Name)
		}
	}

	for name, seen := range want {
		if !seen {
			t.Errorf("tool %q is missing", name)
		}
	}
}

func TestListProjects(t *testing.T) {
	cs := newSession(t, routes(t, map[string]string{
		"/api/v1/projects": `{"data":[{"project_name":"payment-service","sbom_count":11,"package_count":420,"vuln_count":7}],"total":1,"page":1,"page_size":25}`,
	}))

	var out listProjectsOutput
	decodeOutput(t, call(t, cs, "list_projects", nil), &out)

	if out.Total != 1 || len(out.Projects) != 1 {
		t.Fatalf("out = %+v", out)
	}
	if out.Projects[0].ProjectName != "payment-service" || out.Projects[0].SBOMCount != 11 {
		t.Errorf("project = %+v", out.Projects[0])
	}
}

// The exit criterion of #399: an MCP client asks get_project and gets the
// de-duplicated numbers, not a sum over versions.
func TestGetProjectReturnsDeduplicatedCountsAndVersions(t *testing.T) {
	cs := newSession(t, routes(t, map[string]string{
		"/api/v1/projects/payment-service":       `{"project_name":"payment-service","sbom_count":11,"package_count":420,"vuln_count":7,"critical_vulns":1,"high_vulns":2,"clusters":["prod-eu"],"namespaces":["payments"],"license_breakdown":{"permissive":400}}`,
		"/api/v1/projects/payment-service/sboms": `{"data":[{"sbom_id":"11111111-1111-1111-1111-111111111111","document_name":"payment-service","document_version":"2.3.0"}],"total":11,"page":1,"page_size":10}`,
	}))

	var out getProjectOutput
	decodeOutput(t, call(t, cs, "get_project", map[string]any{"name": "payment-service"}), &out)

	if out.Project.PackageCount != 420 || out.Project.VulnCount != 7 {
		t.Errorf("counts = %+v", out.Project)
	}
	if out.TotalVersions != 11 {
		t.Errorf("total_versions = %d, want 11", out.TotalVersions)
	}
	if len(out.Versions) != 1 || out.Versions[0].DocumentVersion != "2.3.0" {
		t.Errorf("versions = %+v", out.Versions)
	}
}

func TestGetProjectMaxVersionsZeroSkipsTheVersionList(t *testing.T) {
	var sbomsCalled bool
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/payment-service", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"project_name":"payment-service","sbom_count":11}`))
	})
	mux.HandleFunc("/api/v1/projects/payment-service/sboms", func(w http.ResponseWriter, r *http.Request) {
		sbomsCalled = true
		_, _ = w.Write([]byte(`{"data":[],"total":11,"page":1,"page_size":10}`))
	})
	cs := newSession(t, mux)

	var out getProjectOutput
	decodeOutput(t, call(t, cs, "get_project", map[string]any{"name": "payment-service", "max_versions": 0}), &out)

	if sbomsCalled {
		t.Error("max_versions=0 still fetched the version list")
	}
	if out.TotalVersions != 11 {
		t.Errorf("total_versions = %d, want the project's own count 11", out.TotalVersions)
	}
	if out.Versions == nil {
		t.Error("versions is null; want an empty array")
	}
}

// A 404 is a fact about the data, not an outage. The model has to be told the
// difference or it retries a call that can never succeed.
func TestGetProjectUnknownNameIsAToolErrorNotAProtocolError(t *testing.T) {
	cs := newSession(t, routes(t, nil))

	res := call(t, cs, "get_project", map[string]any{"name": "ghost"})
	if !res.IsError {
		t.Fatal("want IsError for an unknown project")
	}
	if !strings.Contains(strings.ToLower(resultText(res)), "not found") {
		t.Errorf("error text %q does not say 'not found'", resultText(res))
	}
}

func TestGetProjectRequiresAName(t *testing.T) {
	cs := newSession(t, routes(t, nil))

	if res := call(t, cs, "get_project", map[string]any{"name": "  "}); !res.IsError {
		t.Error("a blank name must be rejected")
	}
	// A missing required property is rejected by schema validation, before the
	// handler runs — proof that the inferred schema marks name as required.
	if res := call(t, cs, "get_project", map[string]any{}); !res.IsError {
		t.Error("a missing name must be rejected")
	}
}

func TestSearchPackages(t *testing.T) {
	cs := newSession(t, routes(t, map[string]string{
		"/api/v1/packages/search": `{"total_results":1,"items":[{"package_name":"log4j-core","purl":"pkg:maven/org.apache.logging.log4j/log4j-core","project_count":3,"versions":["2.14.1"]}],"page":1,"page_size":25,"query":"log4j"}`,
	}))

	var out searchPackagesOutput
	decodeOutput(t, call(t, cs, "search_packages", map[string]any{"query": "log4j"}), &out)

	if out.Total != 1 || len(out.Packages) != 1 || out.Packages[0].ProjectCount != 3 {
		t.Fatalf("out = %+v", out)
	}
	if out.Query != "log4j" {
		t.Errorf("query = %q", out.Query)
	}
}

func TestListVulnerabilitiesInstanceWide(t *testing.T) {
	cs := newSession(t, routes(t, map[string]string{
		"/api/v1/vulnerabilities": `{"data":[{"vuln_id":"CVE-2026-1","severity":"CRITICAL"}],"total":1,"page":1,"page_size":25}`,
	}))

	var out listVulnerabilitiesOutput
	decodeOutput(t, call(t, cs, "list_vulnerabilities", nil), &out)

	if len(out.Vulnerabilities) != 1 || out.Vulnerabilities[0].VulnID != "CVE-2026-1" {
		t.Fatalf("out = %+v", out)
	}
	if out.Project != "" {
		t.Errorf("project = %q, want empty for an instance-wide listing", out.Project)
	}
}

// Suppressed findings are returned and labelled, never hidden: that is the
// same rule the dashboard follows, and an agent that cannot see a
// not_affected finding cannot explain why a CVE is not on the list.
func TestListVulnerabilitiesForProjectKeepsVEXStatus(t *testing.T) {
	cs := newSession(t, routes(t, map[string]string{
		"/api/v1/projects/payment-service/vulnerabilities": `[
			{"vuln_id":"CVE-2026-1","severity":"CRITICAL"},
			{"vuln_id":"CVE-2026-2","severity":"HIGH","vex_status":"not_affected","vex_justification":"vulnerable_code_not_in_execute_path"},
			{"vuln_id":"CVE-2026-3","severity":"HIGH"}
		]`,
	}))

	var out listVulnerabilitiesOutput
	decodeOutput(t, call(t, cs, "list_vulnerabilities", map[string]any{"project": "payment-service"}), &out)

	if out.Total != 3 || len(out.Vulnerabilities) != 3 {
		t.Fatalf("out = %+v", out)
	}
	if out.Vulnerabilities[1].VEXStatus != "not_affected" {
		t.Errorf("the suppressed finding lost its vex_status: %+v", out.Vulnerabilities[1])
	}
}

// scope is passed through to the API (server-side filter) and the rows keep
// their dependency_scope, so an agent can tell a direct from a transitive
// finding. An invalid scope is rejected before any HTTP call.
func TestListVulnerabilitiesScopePassthrough(t *testing.T) {
	var gotScope []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		gotScope = append(gotScope, r.URL.Query().Get("scope"))
		_, _ = w.Write([]byte(`{"data":[{"vuln_id":"CVE-2026-1","severity":"HIGH","dependency_scope":"transitive","dependency_depth":3}],"total":1,"page":1,"page_size":25}`))
	})
	mux.HandleFunc("/api/v1/projects/payment-service/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		gotScope = append(gotScope, r.URL.Query().Get("scope"))
		_, _ = w.Write([]byte(`[{"vuln_id":"CVE-2026-2","severity":"HIGH","dependency_scope":"direct","dependency_depth":1}]`))
	})
	cs := newSession(t, mux)

	var out listVulnerabilitiesOutput
	decodeOutput(t, call(t, cs, "list_vulnerabilities", map[string]any{"scope": "Transitive"}), &out)
	if out.Vulnerabilities[0].DependencyScope != "transitive" || out.Vulnerabilities[0].DependencyDepth == nil || *out.Vulnerabilities[0].DependencyDepth != 3 {
		t.Errorf("instance-wide row lost its scope: %+v", out.Vulnerabilities[0])
	}

	decodeOutput(t, call(t, cs, "list_vulnerabilities", map[string]any{"project": "payment-service", "scope": "direct"}), &out)
	if out.Vulnerabilities[0].DependencyScope != "direct" {
		t.Errorf("project row lost its scope: %+v", out.Vulnerabilities[0])
	}

	if want := []string{"transitive", "direct"}; !reflect.DeepEqual(gotScope, want) {
		t.Errorf("scope query params = %v, want %v", gotScope, want)
	}

	res := call(t, cs, "list_vulnerabilities", map[string]any{"scope": "deep"})
	if !res.IsError {
		t.Error("scope=deep accepted, want tool error")
	}
	if len(gotScope) != 2 {
		t.Errorf("invalid scope reached the API: %v", gotScope)
	}
}

func TestListVulnerabilitiesSeverityFilterAndPaging(t *testing.T) {
	cs := newSession(t, routes(t, map[string]string{
		"/api/v1/projects/payment-service/vulnerabilities": `[
			{"vuln_id":"CVE-2026-1","severity":"CRITICAL"},
			{"vuln_id":"CVE-2026-2","severity":"HIGH"},
			{"vuln_id":"CVE-2026-3","severity":"high"}
		]`,
	}))

	var out listVulnerabilitiesOutput
	decodeOutput(t, call(t, cs, "list_vulnerabilities", map[string]any{
		"project":  "payment-service",
		"severity": "high",
	}), &out)

	if out.Total != 2 {
		t.Fatalf("total = %d, want 2 (severity match is case-insensitive)", out.Total)
	}

	var page2 listVulnerabilitiesOutput
	decodeOutput(t, call(t, cs, "list_vulnerabilities", map[string]any{
		"project":   "payment-service",
		"page":      2,
		"page_size": 2,
	}), &page2)
	if len(page2.Vulnerabilities) != 1 || page2.Vulnerabilities[0].VulnID != "CVE-2026-3" {
		t.Errorf("page 2 = %+v", page2.Vulnerabilities)
	}
	if page2.Total != 3 {
		t.Errorf("total = %d, want the unpaged total 3", page2.Total)
	}
}

// Filtering one page of a server-paginated list and calling the result a
// severity count would be a lie, so the tool refuses instead.
func TestSeverityFilterRequiresAProject(t *testing.T) {
	cs := newSession(t, routes(t, map[string]string{
		"/api/v1/vulnerabilities": `{"data":[],"total":0,"page":1,"page_size":25}`,
	}))

	res := call(t, cs, "list_vulnerabilities", map[string]any{"severity": "CRITICAL"})
	if !res.IsError {
		t.Fatal("want an error: severity filtering without a project is not answerable")
	}
	if !strings.Contains(resultText(res), "project") {
		t.Errorf("error text %q does not explain the constraint", resultText(res))
	}
}

func TestUnknownSeverityIsRejected(t *testing.T) {
	cs := newSession(t, routes(t, nil))

	res := call(t, cs, "list_vulnerabilities", map[string]any{"project": "p", "severity": "URGENT"})
	if !res.IsError {
		t.Fatal("want an error for an unknown severity")
	}
}

func TestGetSBOM(t *testing.T) {
	const id = "11111111-1111-1111-1111-111111111111"
	cs := newSession(t, routes(t, map[string]string{
		"/api/v1/sboms/" + id + "/detail":          `{"sbom_id":"` + id + `","document_name":"payment-service","package_count":420,"critical_vulns":1}`,
		"/api/v1/sboms/" + id + "/vulnerabilities": `[{"vuln_id":"CVE-2026-1","severity":"CRITICAL"}]`,
	}))

	var out getSBOMOutput
	decodeOutput(t, call(t, cs, "get_sbom", map[string]any{"sbom_id": id}), &out)
	if out.SBOM.PackageCount != 420 {
		t.Errorf("sbom = %+v", out.SBOM)
	}
	if len(out.Vulnerabilities) != 0 {
		t.Errorf("findings were included without being asked for: %+v", out.Vulnerabilities)
	}

	var withVulns getSBOMOutput
	decodeOutput(t, call(t, cs, "get_sbom", map[string]any{"sbom_id": id, "include_vulnerabilities": true}), &withVulns)
	if len(withVulns.Vulnerabilities) != 1 {
		t.Errorf("vulnerabilities = %+v", withVulns.Vulnerabilities)
	}
}

func TestPageSizeAboveTheAPIClampIsRejected(t *testing.T) {
	cs := newSession(t, routes(t, nil))

	res := call(t, cs, "list_projects", map[string]any{"page_size": maxPageSize + 1})
	if !res.IsError {
		t.Fatal("want an error for a page_size above the API clamp")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	for _, in := range []string{"critical", " HIGH ", "Medium", "low", "unknown"} {
		if _, err := normalizeSeverity(in); err != nil {
			t.Errorf("normalizeSeverity(%q) = %v, want nil", in, err)
		}
	}
	if got, err := normalizeSeverity(""); err != nil || got != "" {
		t.Errorf(`normalizeSeverity("") = %q, %v`, got, err)
	}
	if _, err := normalizeSeverity("urgent"); err == nil {
		t.Error("normalizeSeverity(urgent) = nil error, want error")
	}
}

func TestPaginate(t *testing.T) {
	items := []int{1, 2, 3, 4, 5}
	cases := []struct {
		page, size uint64
		want       []int
	}{
		{1, 2, []int{1, 2}},
		{3, 2, []int{5}},
		{4, 2, nil},
		{1, 10, []int{1, 2, 3, 4, 5}},
	}
	for _, tc := range cases {
		got := paginate(items, tc.page, tc.size)
		if len(got) != len(tc.want) {
			t.Fatalf("paginate(page=%d,size=%d) = %v, want %v", tc.page, tc.size, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("paginate(page=%d,size=%d) = %v, want %v", tc.page, tc.size, got, tc.want)
			}
		}
	}
}

func TestListVulnerabilitiesOwnerFilters(t *testing.T) {
	var got url.Values
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		_, _ = w.Write([]byte(`{"data":[],"total":0,"page":1,"page_size":25}`))
	})
	cs := newSession(t, mux)

	var out listVulnerabilitiesOutput
	decodeOutput(t, call(t, cs, "list_vulnerabilities", map[string]any{"cluster": "prod-eu,prod-us", "tag": "sandbox"}), &out)
	if got.Get("cluster") != "prod-eu,prod-us" || got.Get("tag") != "sandbox" || got.Has("namespace") || got.Has("parent") {
		t.Errorf("query = %v", got)
	}

	got = nil
	if res := call(t, cs, "list_vulnerabilities", map[string]any{"project": "p", "cluster": "c"}); !res.IsError {
		t.Error("project + cluster accepted, want tool error")
	}
	if got != nil {
		t.Errorf("rejected call reached the API: %v", got)
	}
}

func TestDashboardAndAffectedProjectsOwnerFilters(t *testing.T) {
	got := map[string]url.Values{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/stats/dashboard", func(w http.ResponseWriter, r *http.Request) {
		got["dash"] = r.URL.Query()
		_, _ = w.Write([]byte(`{"total_sboms":3}`))
	})
	mux.HandleFunc("/api/v1/vulnerabilities/CVE-2024-1/affected-projects", func(w http.ResponseWriter, r *http.Request) {
		got["aff"] = r.URL.Query()
		_, _ = w.Write([]byte(`[{"sbom_id":"x","cluster":"prod-eu","namespace":"apps"}]`))
	})
	cs := newSession(t, mux)

	var dash dashboardStatsOutput
	decodeOutput(t, call(t, cs, "get_dashboard_stats", map[string]any{"cluster": "prod-eu", "project": "p"}), &dash)
	if q := got["dash"]; q.Get("cluster") != "prod-eu" || q.Get("project") != "p" || q.Has("tag") {
		t.Errorf("dashboard query = %v", q)
	}
	if dash.Stats.TotalSBOMs != 3 || dash.Stats.LicenseBreakdown == nil {
		t.Errorf("dashboard = %+v", dash.Stats)
	}

	var aff affectedProjectsOutput
	decodeOutput(t, call(t, cs, "get_affected_projects", map[string]any{"vuln_id": "CVE-2024-1", "namespace": "apps"}), &aff)
	if q := got["aff"]; q.Get("namespace") != "apps" || q.Has("cluster") {
		t.Errorf("affected query = %v", q)
	}
	if len(aff.Affected) != 1 || aff.Affected[0].Cluster != "prod-eu" {
		t.Errorf("affected = %+v", aff.Affected)
	}
	if res := call(t, cs, "get_affected_projects", map[string]any{}); !res.IsError {
		t.Error("missing vuln_id accepted")
	}
}
