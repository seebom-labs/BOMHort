package clickhouse

import (
	"reflect"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// package_license_sources is a parallel array to package_licenses; a length
// mismatch would shift every source onto the wrong package in the UI.
func TestLicenseSourcesFor(t *testing.T) {
	tests := []struct {
		name     string
		licenses []string
		sources  []string
		want     []string
	}{
		{"aligned", []string{"MIT", "NOASSERTION"}, []string{"declared", "not-published"}, []string{"declared", "not-published"}},
		{"missing sources are padded", []string{"MIT", "Apache-2.0"}, []string{"declared"}, []string{"declared", ""}},
		{"no sources at all", []string{"MIT"}, nil, []string{""}},
		{"extra sources are trimmed", []string{"MIT"}, []string{"declared", "npm"}, []string{"declared"}},
		{"no packages", nil, []string{"declared"}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := &models.SBOMPackages{PackageLicenses: tt.licenses, PackageLicenseSources: tt.sources}
			got := licenseSourcesFor(pkg)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
