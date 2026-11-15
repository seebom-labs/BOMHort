// Package depgraph derives each package's distance from the product an SBOM
// describes, so that findings can be told apart as direct or transitive.
//
// The parsers keep the relationship graph as parallel index arrays
// (rel_source_indices / rel_target_indices / rel_types). This package walks
// that graph breadth-first from the described root(s) and assigns every
// reachable package a depth: 0 for the root itself, 1 for a direct dependency,
// 2 and more for transitive ones. Packages the walk never reaches – because
// the document has no relationship graph at all, or because a generator only
// listed packages without connecting them – are marked Unknown rather than
// guessed. An SBOM without a graph must not make every package look
// transitive.
package depgraph

import "strings"

// Unknown marks a package whose depth could not be derived: no relationship
// graph, or the package is not connected to the root. Stored as-is in
// ClickHouse (Array(UInt16)); rows written before the column existed carry an
// empty array and are treated the same way by readers.
const Unknown uint16 = 65535

// Scope labels used in API responses.
const (
	ScopeRoot       = "root"
	ScopeDirect     = "direct"
	ScopeTransitive = "transitive"
	ScopeUnknown    = "unknown"
)

// Scope maps a depth to its API label.
func Scope(depth uint16) string {
	switch {
	case depth == Unknown:
		return ScopeUnknown
	case depth == 0:
		return ScopeRoot
	case depth == 1:
		return ScopeDirect
	default:
		return ScopeTransitive
	}
}

// ScopeOf returns the scope for the package at idx in a depths array, or
// ScopeUnknown when the array is shorter (data written before migration 025).
func ScopeOf(depths []uint16, idx int) string {
	return Scope(DepthOf(depths, idx))
}

// DepthOf returns the depth for the package at idx, or Unknown when the array
// is shorter.
func DepthOf(depths []uint16, idx int) uint16 {
	if idx < 0 || idx >= len(depths) {
		return Unknown
	}
	return depths[idx]
}

// IsValidScope reports whether s is a scope label a client may filter by.
func IsValidScope(s string) bool {
	switch s {
	case ScopeRoot, ScopeDirect, ScopeTransitive, ScopeUnknown:
		return true
	}
	return false
}

// edgeDirection says what a relationship type means for the dependency walk.
type edgeDirection int

const (
	ignore   edgeDirection = iota
	forward                // source depends on target: walk source → target
	backward               // target depends on source: walk target → source
)

// classifyRelationship normalises an SPDX relationship type ("DEPENDS_ON"),
// a protobom edge type ("dependsOn") or a CycloneDX dependsOn edge to a walk
// direction. Case and underscores are insignificant.
func classifyRelationship(relType string) edgeDirection {
	key := strings.ToLower(strings.ReplaceAll(relType, "_", ""))
	switch key {
	case "dependson",
		"contains",
		"hasprerequisite", "prerequisite",
		"staticlink", "dynamiclink",
		"runtimedependency", "builddependency", "devdependency",
		"optionaldependency", "provideddependency", "testdependency",
		"optionalcomponent",
		"packageof", "packages":
		return forward
	case "dependencyof",
		"runtimedependencyof", "builddependencyof", "devdependencyof",
		"optionaldependencyof", "provideddependencyof", "testdependencyof",
		"containedby",
		"prerequisitefor":
		return backward
	}
	return ignore
}

// Compute assigns a depth to each of n packages.
//
//   - roots are depth 0 (the product the SBOM describes).
//   - directSeeds are depth 1 regardless of edges. CycloneDX keeps the
//     product in metadata.component, outside the component array, so the
//     parser passes the product's dependsOn targets here.
//   - Every other package gets the length of the shortest dependency path
//     from a root or seed; unreachable packages stay Unknown.
//
// When neither roots nor seeds are given, the walk starts from a single
// package that nothing depends on but that depends on others – the usual
// shape of an SPDX document whose generator forgot DESCRIBES. If there is
// more than one such candidate the structure is ambiguous and everything
// stays Unknown.
func Compute(n int, relSources, relTargets []uint32, relTypes []string, roots, directSeeds []uint32) []uint16 {
	depths := make([]uint16, n)
	for i := range depths {
		depths[i] = Unknown
	}
	if n == 0 {
		return depths
	}

	adj, inDegree, edges := dependencyEdges(n, relSources, relTargets, relTypes)

	var queue []uint32
	for _, r := range roots {
		if int(r) < n && depths[r] == Unknown {
			depths[r] = 0
			queue = append(queue, r)
		}
	}
	for _, s := range directSeeds {
		if int(s) < n && depths[s] == Unknown {
			depths[s] = 1
			queue = append(queue, s)
		}
	}

	if len(queue) == 0 {
		if edges == 0 {
			return depths
		}
		candidate := -1
		for i := 0; i < n; i++ {
			if inDegree[i] == 0 && len(adj[uint32(i)]) > 0 {
				if candidate >= 0 {
					return depths // ambiguous: several unconnected sources
				}
				candidate = i
			}
		}
		if candidate < 0 {
			return depths // every package is depended upon: a cycle, no root
		}
		depths[candidate] = 0
		queue = append(queue, uint32(candidate))
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		next := depths[cur] + 1
		if next == Unknown {
			continue
		}
		for _, child := range adj[cur] {
			if depths[child] == Unknown {
				depths[child] = next
				queue = append(queue, child)
			}
		}
	}
	return depths
}

// MinDepthForPURL returns the smallest depth among all packages sharing purl,
// or Unknown when none is known. A finding against a package URL concerns the
// nearest place it is pulled in from.
func MinDepthForPURL(purls []string, depths []uint16, purl string) uint16 {
	best := Unknown
	for i, p := range purls {
		if p != purl {
			continue
		}
		if d := DepthOf(depths, i); d < best {
			best = d
		}
	}
	return best
}

// Children returns, for each of n packages, the packages it depends on:
// the same edges the depth walk follows, with reverse relationship types
// (DEPENDENCY_OF, CONTAINED_BY, …) turned around and non-dependency types
// (DESCRIBES, GENERATED_FROM, …) left out. Each list keeps the order of the
// relationships in the document and names a child once.
//
// This is the parent→child structure a dependency tree is drawn from; it
// agrees with Compute by construction.
func Children(n int, relSources, relTargets []uint32, relTypes []string) [][]uint32 {
	out := make([][]uint32, n)
	adj, _, _ := dependencyEdges(n, relSources, relTargets, relTypes)
	for parent, children := range adj {
		seen := make(map[uint32]struct{}, len(children))
		for _, c := range children {
			if _, dup := seen[c]; dup {
				continue
			}
			seen[c] = struct{}{}
			out[parent] = append(out[parent], c)
		}
	}
	return out
}

// dependencyEdges normalises the relationship arrays to "depends on" edges:
// adj[parent] lists its dependencies in document order, inDegree counts the
// edges into each package and edges is their total. Self-references and
// out-of-range indices are dropped.
func dependencyEdges(n int, relSources, relTargets []uint32, relTypes []string) (adj map[uint32][]uint32, inDegree []int, edges int) {
	adj = make(map[uint32][]uint32)
	inDegree = make([]int, n)
	for i := range relSources {
		if i >= len(relTargets) {
			break
		}
		src, tgt := relSources[i], relTargets[i]
		if int(src) >= n || int(tgt) >= n || src == tgt {
			continue
		}
		relType := ""
		if i < len(relTypes) {
			relType = relTypes[i]
		}
		switch classifyRelationship(relType) {
		case forward:
			adj[src] = append(adj[src], tgt)
			inDegree[tgt]++
			edges++
		case backward:
			adj[tgt] = append(adj[tgt], src)
			inDegree[src]++
			edges++
		}
	}
	return adj, inDegree, edges
}
