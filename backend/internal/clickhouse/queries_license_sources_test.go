package clickhouse

import (
	"reflect"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

func TestDescribeLicenseSource(t *testing.T) {
	tests := []struct {
		source    string
		origin    string
		modifiers []string
		resolved  bool
	}{
		{"declared", "declared", []string{}, true},
		{"depsdev+latest", "depsdev", []string{"latest"}, true},
		{"packagist+latest+normalized", "packagist", []string{"latest", "normalized"}, true},
		{"not-published", "not-published", []string{}, false},
		{"first-party", "first-party", []string{}, false},
		{"unrecorded", "unrecorded", []string{}, false},
	}
	for _, tc := range tests {
		item := dto.LicenseSourceItem{Source: tc.source}
		describeLicenseSource(&item)
		if item.Origin != tc.origin || !reflect.DeepEqual(item.Modifiers, tc.modifiers) || item.Resolved != tc.resolved {
			t.Errorf("%s: got (%q, %v, %v), want (%q, %v, %v)", tc.source,
				item.Origin, item.Modifiers, item.Resolved, tc.origin, tc.modifiers, tc.resolved)
		}
		if item.Examples == nil {
			t.Errorf("%s: examples must serialise as [], not null", tc.source)
		}
	}
}
