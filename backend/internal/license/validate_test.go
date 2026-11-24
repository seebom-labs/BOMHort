package license

import "testing"

func TestValidVersion(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"1.0.0", true},
		{"v2.1.0-alpha.1", true},
		{"1.0.0+build2026", true},
		{"4.18.4", true},
		{"13.0.3", true},
		{"", false},
		{"   ", false},
		{".", false},
		{"..", false},
		{"../evil", false},
		{"evil/..", false},
		{"foo/bar", false},
		{"foo\\bar", false},
		{"1.0 2.0", false},
		{"1.0\t2.0", false},
		{"1.0\n2.0", false},
		{"1.0\r2.0", false},
		{"${version}", false},
		{"foo..bar", false},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if got := ValidVersion(tt.version); got != tt.want {
				t.Errorf("ValidVersion(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}
