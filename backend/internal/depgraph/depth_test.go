package depgraph

import (
	"reflect"
	"testing"
)

func TestCompute_SPDXDependsOnChain(t *testing.T) {
	// 0 (root) → 1 → 2 → 3 ; 0 → 4 ; 5 unconnected
	depths := Compute(6,
		[]uint32{0, 1, 2, 0},
		[]uint32{1, 2, 3, 4},
		[]string{"DEPENDS_ON", "DEPENDS_ON", "DEPENDS_ON", "DEPENDS_ON"},
		[]uint32{0}, nil)
	want := []uint16{0, 1, 2, 3, 1, Unknown}
	if !reflect.DeepEqual(depths, want) {
		t.Fatalf("got %v, want %v", depths, want)
	}
}

func TestCompute_ReversedRelationships(t *testing.T) {
	// SPDX DEPENDENCY_OF: "1 is a dependency of 0" is written source=1, target=0.
	depths := Compute(3,
		[]uint32{1, 2},
		[]uint32{0, 1},
		[]string{"DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF"},
		[]uint32{0}, nil)
	want := []uint16{0, 1, 2}
	if !reflect.DeepEqual(depths, want) {
		t.Fatalf("got %v, want %v", depths, want)
	}
}

func TestCompute_ShortestPathWins(t *testing.T) {
	// 0 → 1 → 2 and 0 → 2: package 2 is both direct and transitive; direct wins.
	depths := Compute(3,
		[]uint32{0, 1, 0},
		[]uint32{1, 2, 2},
		[]string{"DEPENDS_ON", "DEPENDS_ON", "DEPENDS_ON"},
		[]uint32{0}, nil)
	if depths[2] != 1 {
		t.Fatalf("package 2 should be direct (depth 1), got %d", depths[2])
	}
}

func TestCompute_CycleTerminates(t *testing.T) {
	depths := Compute(3,
		[]uint32{0, 1, 2},
		[]uint32{1, 2, 1},
		[]string{"DEPENDS_ON", "DEPENDS_ON", "DEPENDS_ON"},
		[]uint32{0}, nil)
	want := []uint16{0, 1, 2}
	if !reflect.DeepEqual(depths, want) {
		t.Fatalf("got %v, want %v", depths, want)
	}
}

func TestCompute_NoGraphIsUnknown(t *testing.T) {
	// A flat package list with a root but no relationships must not be
	// declared transitive.
	depths := Compute(4, nil, nil, nil, []uint32{0}, nil)
	want := []uint16{0, Unknown, Unknown, Unknown}
	if !reflect.DeepEqual(depths, want) {
		t.Fatalf("got %v, want %v", depths, want)
	}
}

func TestCompute_CycloneDXDirectSeeds(t *testing.T) {
	// metadata.component is not in the array; its dependsOn targets are seeds.
	// seeds {0, 1}; 1 → 2 → 3
	depths := Compute(4,
		[]uint32{1, 2},
		[]uint32{2, 3},
		[]string{"DEPENDS_ON", "DEPENDS_ON"},
		nil, []uint32{0, 1})
	want := []uint16{1, 1, 2, 3}
	if !reflect.DeepEqual(depths, want) {
		t.Fatalf("got %v, want %v", depths, want)
	}
}

func TestCompute_FallbackSingleSource(t *testing.T) {
	// No DESCRIBES, but exactly one package nothing depends on: 2 → 0 → 1.
	depths := Compute(3,
		[]uint32{2, 0},
		[]uint32{0, 1},
		[]string{"DEPENDS_ON", "DEPENDS_ON"},
		nil, nil)
	want := []uint16{1, 2, 0}
	if !reflect.DeepEqual(depths, want) {
		t.Fatalf("got %v, want %v", depths, want)
	}
}

func TestCompute_FallbackAmbiguousStaysUnknown(t *testing.T) {
	// Two unrelated sources: 0 → 1 and 2 → 3. No root to pick.
	depths := Compute(4,
		[]uint32{0, 2},
		[]uint32{1, 3},
		[]string{"DEPENDS_ON", "DEPENDS_ON"},
		nil, nil)
	for i, d := range depths {
		if d != Unknown {
			t.Fatalf("package %d should be unknown, got %d", i, d)
		}
	}
}

func TestCompute_IgnoresNonDependencyRelationships(t *testing.T) {
	depths := Compute(3,
		[]uint32{0, 0},
		[]uint32{1, 2},
		[]string{"GENERATED_FROM", "DEPENDS_ON"},
		[]uint32{0}, nil)
	want := []uint16{0, Unknown, 1}
	if !reflect.DeepEqual(depths, want) {
		t.Fatalf("got %v, want %v", depths, want)
	}
}

func TestCompute_ProtobomEdgeNames(t *testing.T) {
	depths := Compute(3,
		[]uint32{0, 2},
		[]uint32{1, 1},
		[]string{"dependsOn", "dependencyOf"},
		[]uint32{0}, nil)
	// 0 → 1 (dependsOn); "2 is a dependency of 1" → 1 → 2
	want := []uint16{0, 1, 2}
	if !reflect.DeepEqual(depths, want) {
		t.Fatalf("got %v, want %v", depths, want)
	}
}

func TestCompute_OutOfRangeIndicesAreSkipped(t *testing.T) {
	depths := Compute(2,
		[]uint32{0, 0, 7},
		[]uint32{1, 9, 1},
		[]string{"DEPENDS_ON", "DEPENDS_ON", "DEPENDS_ON"},
		[]uint32{0, 42}, nil)
	want := []uint16{0, 1}
	if !reflect.DeepEqual(depths, want) {
		t.Fatalf("got %v, want %v", depths, want)
	}
}

func TestScope(t *testing.T) {
	cases := map[uint16]string{0: ScopeRoot, 1: ScopeDirect, 2: ScopeTransitive, 17: ScopeTransitive, Unknown: ScopeUnknown}
	for d, want := range cases {
		if got := Scope(d); got != want {
			t.Errorf("Scope(%d) = %q, want %q", d, got, want)
		}
	}
	if got := ScopeOf([]uint16{0, 1}, 5); got != ScopeUnknown {
		t.Errorf("ScopeOf out of range = %q, want unknown", got)
	}
	if got := ScopeOf(nil, 0); got != ScopeUnknown {
		t.Errorf("ScopeOf nil = %q, want unknown", got)
	}
}

func TestMinDepthForPURL(t *testing.T) {
	purls := []string{"pkg:golang/a@1", "pkg:golang/b@1", "pkg:golang/a@1"}
	depths := []uint16{3, 1, 2}
	if got := MinDepthForPURL(purls, depths, "pkg:golang/a@1"); got != 2 {
		t.Errorf("got %d, want 2", got)
	}
	if got := MinDepthForPURL(purls, depths, "pkg:golang/zzz@1"); got != Unknown {
		t.Errorf("missing purl: got %d, want Unknown", got)
	}
	if got := MinDepthForPURL(purls, nil, "pkg:golang/a@1"); got != Unknown {
		t.Errorf("no depths: got %d, want Unknown", got)
	}
}

func TestIsValidScope(t *testing.T) {
	for _, s := range []string{ScopeRoot, ScopeDirect, ScopeTransitive, ScopeUnknown} {
		if !IsValidScope(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range []string{"", "all", "DIRECT", "indirect"} {
		if IsValidScope(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}

// Children is the parent→child view of the same edges Compute walks (#56):
// reverse types are turned around, non-dependency types left out.
func TestChildren_NormalisesRelationships(t *testing.T) {
	got := Children(6,
		[]uint32{0, 2, 0, 3, 0, 1, 4, 9, 1},
		[]uint32{1, 0, 5, 1, 1, 1, 0, 1, 3},
		[]string{
			"DEPENDS_ON",     // 0 → 1
			"DEPENDENCY_OF",  // 2 is a dependency of 0: 0 → 2
			"DESCRIBES",      // not a dependency
			"CONTAINED_BY",   // 3 is contained by 1: 1 → 3
			"DEPENDS_ON",     // duplicate of the first edge
			"DEPENDS_ON",     // self-reference
			"GENERATED_FROM", // not a dependency
			"DEPENDS_ON",     // out of range
			"CONTAINS",       // 1 → 3 again, other spelling
		})
	want := [][]uint32{{1, 2}, {3}, nil, nil, nil, nil}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestChildren_AgreesWithCompute(t *testing.T) {
	src := []uint32{1, 2, 0, 3}
	tgt := []uint32{0, 1, 3, 4}
	types := []string{"DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF", "DEPENDS_ON", "DEPENDS_ON"}
	depths := Compute(5, src, tgt, types, []uint32{0}, nil)
	for parent, children := range Children(5, src, tgt, types) {
		for _, c := range children {
			// A tree drawn from Children never shows a child above its
			// parent's depth + 1: the edge is one the depth walk followed.
			if depths[c] > depths[parent]+1 {
				t.Errorf("edge %d → %d: depth %d below parent depth %d", parent, c, depths[c], depths[parent])
			}
		}
	}
}

func TestChildren_Empty(t *testing.T) {
	if got := Children(0, nil, nil, nil); len(got) != 0 {
		t.Errorf("Children(0) = %v", got)
	}
	if got := Children(2, nil, nil, nil); !reflect.DeepEqual(got, [][]uint32{nil, nil}) {
		t.Errorf("no relationships: %v", got)
	}
}
