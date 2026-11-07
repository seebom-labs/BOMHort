package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/projectgroup"
	tagpkg "github.com/seebom-labs/bomhort/backend/internal/tags"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// vulnFilterFunc reads the ownership filters (#459) of a vulnerability
// listing request. A non-zero status means the request must be answered with
// that status and message instead.
type vulnFilterFunc func(r *http.Request) (f clickhouse.VulnFilter, status int, msg string)

// splitOwnerList splits a comma-separated filter value, dropping blanks.
func splitOwnerList(raw string) ([]string, bool) {
	var out []string
	for _, v := range strings.Split(raw, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if len(v) > maxOwnerNameLen {
			return nil, false
		}
		out = append(out, v)
	}
	return out, true
}

// parentMembers returns the projects listed under the given parents, the way
// QueryProjectGroups groups them: the parent itself plus every project
// assigned to it, except a project that heads a group of its own.
func parentMembers(parents []string, assignments map[string]projectgroup.Assignment) []string {
	want := map[string]bool{}
	heads := map[string]bool{}
	for _, p := range parents {
		want[p] = true
	}
	for _, a := range assignments {
		heads[a.Parent] = true
	}
	members := append([]string(nil), parents...)
	for project, a := range assignments {
		if want[a.Parent] && !heads[project] && !want[project] {
			members = append(members, project)
		}
	}
	return members
}

// newVulnFilter builds the request parser. ?cluster=, ?namespace=,
// ?project=, ?parent= and ?tag= each take comma-separated values, ORed within
// one parameter and ANDed across parameters.
func newVulnFilter(assignments func(context.Context) (map[string]projectgroup.Assignment, error)) vulnFilterFunc {
	return func(r *http.Request) (clickhouse.VulnFilter, int, string) {
		q := r.URL.Query()
		var f clickhouse.VulnFilter
		var parents []string
		for _, p := range []struct {
			name string
			dst  *[]string
		}{
			{"cluster", &f.Clusters}, {"namespace", &f.Namespaces},
			{"project", &f.Projects}, {"parent", &parents},
		} {
			vals, ok := splitOwnerList(q.Get(p.name))
			if !ok {
				return f, http.StatusBadRequest, fmt.Sprintf("Invalid %s (each value at most %d characters)", p.name, maxOwnerNameLen)
			}
			*p.dst = vals
		}
		f.Tags = tagpkg.Parse(q.Get("tag"))
		kind := strings.TrimSpace(q.Get("kind"))
		if kind != "" {
			if kind != models.FindingKindVulnerability && kind != models.FindingKindMalicious {
				return f, http.StatusBadRequest, "Invalid kind (expected vulnerability or malicious)"
			}
			f.Kind = kind
		}
		if len(parents) > 0 {
			a, err := assignments(r.Context())
			if err != nil {
				log.Printf("ERROR: resolve parents: %v", err)
				return f, http.StatusInternalServerError, "Failed to resolve parents"
			}
			f.ParentMembers = parentMembers(parents, a)
		}
		return f, 0, ""
	}
}

// vulnListHandler serves a paginated vulnerability listing; preset pins the
// filter dimension taken from the URL path (cluster or namespace routes).
func vulnListHandler(chClient *clickhouse.Client, filter vulnFilterFunc, preset func(r *http.Request, f *clickhouse.VulnFilter) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		page := parseUint64(r.URL.Query().Get("page"), 1)
		pageSize := clampPageSize(parseUint64(r.URL.Query().Get("page_size"), 50))
		scope, ok := parseScope(r.URL.Query().Get("scope"))
		if !ok {
			writeError(w, http.StatusBadRequest, "Invalid scope (expected direct, transitive, root or unknown)")
			return
		}
		f, status, msg := filter(r)
		if status == 0 && preset != nil {
			if msg = preset(r, &f); msg != "" {
				status = http.StatusBadRequest
			}
		}
		if status != 0 {
			writeError(w, status, msg)
			return
		}

		resp, err := chClient.QueryVulnerabilities(r.Context(), page, pageSize, scope, f)
		if err != nil {
			log.Printf("ERROR: list vulnerabilities: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch vulnerabilities")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// pathOwner pins one ownership dimension to the {name} path value.
func pathOwner(kind string, dst func(*clickhouse.VulnFilter) *[]string) func(*http.Request, *clickhouse.VulnFilter) string {
	return func(r *http.Request, f *clickhouse.VulnFilter) string {
		name := r.PathValue("name")
		if name == "" || len(name) > maxOwnerNameLen {
			return "Invalid " + kind + " name"
		}
		// The path names the one value; a second one in ?kind= would either
		// be ignored or empty the result, both surprising.
		if r.URL.Query().Has(kind) {
			return "Set the " + kind + " in the path, not in ?" + kind + "="
		}
		*dst(f) = []string{name}
		return ""
	}
}
