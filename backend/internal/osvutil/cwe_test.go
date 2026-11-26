package osvutil

import (
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/osv"
)

// #409: CWE identifiers come from OSV database_specific.cwe_ids (GitHub
// Advisory Database). The extractor is tolerant of the shapes seen in the
// wild — an array, a single string, junk — normalises to CWE-<number> and
// returns them sorted and deduplicated. Entries without CWEs yield nil, the
// column default, so nothing changes for NVD-sourced records.
func TestExtractCWEs(t *testing.T) {
	tests := []struct {
		name     string
		specific map[string]interface{}
		want     []string
	}{
		{
			name:     "array sorted and normalised",
			specific: map[string]interface{}{"cwe_ids": []interface{}{"CWE-80", "CWE-79"}},
			want:     []string{"CWE-79", "CWE-80"},
		},
		{
			name:     "single string",
			specific: map[string]interface{}{"cwe_ids": "CWE-79"},
			want:     []string{"CWE-79"},
		},
		{
			name:     "lowercase and prefix variants normalise",
			specific: map[string]interface{}{"cwe_ids": []interface{}{"cwe-79", "CWE-79", "79"}},
			want:     []string{"CWE-79"},
		},
		{
			name:     "non-string entries ignored",
			specific: map[string]interface{}{"cwe_ids": []interface{}{"CWE-79", 42, nil}},
			want:     []string{"CWE-79"},
		},
		{
			name:     "wrong key absent",
			specific: map[string]interface{}{"severity": "HIGH"},
			want:     nil,
		},
		{
			name:     "nil map",
			specific: nil,
			want:     nil,
		},
		{
			name:     "malformed values dropped",
			specific: map[string]interface{}{"cwe_ids": []interface{}{"CWE-", "CWE-x", ""}},
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractCWEs(osv.VulnEntry{DatabaseSpecific: tt.specific})
			if len(got) != len(tt.want) {
				t.Fatalf("ExtractCWEs() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("ExtractCWEs() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
