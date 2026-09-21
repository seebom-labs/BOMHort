package tags

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "nil in, nil out",
			in:   nil,
			want: nil,
		},
		{
			// An empty array must not become [""], which would surface in the
			// UI as a nameless grouping that matches nothing.
			name: "blank entries are dropped entirely",
			in:   []string{"", "   ", "\t"},
			want: nil,
		},
		{
			name: "trims and lowercases",
			in:   []string{"  Sandbox-Applications  "},
			want: []string{"sandbox-applications"},
		},
		{
			// Case folding is what makes a filter typed by hand match data
			// written by a CI pipeline.
			name: "case variants collapse to one tag",
			in:   []string{"Graduated", "graduated", "GRADUATED"},
			want: []string{"graduated"},
		},
		{
			// Two uploads naming the same tags in different orders must
			// produce equal rows, or dedup and comparisons turn
			// order-sensitive for no reason.
			name: "output is sorted regardless of input order",
			in:   []string{"sandbox", "cncf", "observability"},
			want: []string{"cncf", "observability", "sandbox"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Normalize(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Normalize(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// An over-long tag is truncated rather than rejected: a tag list arrives
// alongside an SBOM, and failing the whole upload over a cosmetic label would
// lose data that is otherwise perfectly good.
func TestNormalizeTruncatesOverLongTags(t *testing.T) {
	got := Normalize([]string{strings.Repeat("a", MaxLen+50)})

	if len(got) != 1 {
		t.Fatalf("Normalize() = %v, want one tag", got)
	}
	if len(got[0]) != MaxLen {
		t.Errorf("tag length = %d, want %d", len(got[0]), MaxLen)
	}
}

func TestNormalizeCapsTagCount(t *testing.T) {
	in := make([]string, 0, MaxCount+10)
	for i := range MaxCount + 10 {
		in = append(in, string(rune('a'+i%26))+strings.Repeat("x", i))
	}

	if got := Normalize(in); len(got) > MaxCount {
		t.Errorf("len(Normalize()) = %d, want at most %d", len(got), MaxCount)
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty", in: "", want: nil},
		{name: "whitespace only", in: "   ", want: nil},
		{name: "single", in: "sandbox-applications", want: []string{"sandbox-applications"}},
		{
			name: "comma separated with spacing",
			in:   "cncf, Sandbox-Applications ,observability",
			want: []string{"cncf", "observability", "sandbox-applications"},
		},
		{
			// A trailing comma is the most common hand-typed mistake; it must
			// not produce an empty tag.
			name: "trailing comma",
			in:   "cncf,",
			want: []string{"cncf"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Parse(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// Tags are additive across configuration levels, unlike namespace/project
// which override. A bucket saying "sandbox-applications" does not contradict
// an instance-wide "cncf", so both must survive -- if Merge overrode instead,
// operators would have to repeat every global tag in every bucket.
func TestMergeIsAdditive(t *testing.T) {
	got := Merge([]string{"cncf"}, []string{"sandbox-applications"})
	want := []string{"cncf", "sandbox-applications"}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Merge() = %v, want %v", got, want)
	}
}

func TestMergeDeduplicatesAcrossLevels(t *testing.T) {
	got := Merge([]string{"cncf"}, []string{"CNCF", "sandbox"})
	want := []string{"cncf", "sandbox"}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Merge() = %v, want %v", got, want)
	}
}

func TestMergeEmpty(t *testing.T) {
	if got := Merge(nil, nil); got != nil {
		t.Errorf("Merge(nil, nil) = %v, want nil", got)
	}
}
