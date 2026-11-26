package clickhouse

import "testing"

func TestEscapeLikePattern(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain term unchanged", "grpc", "grpc"},
		{"percent escaped", "100%", `100\%`},
		{"only percent escaped", "%", `\%`},
		{"underscore escaped", "my_pkg", `my\_pkg`},
		{"multiple underscores escaped", "___", `\_\_\_`},
		{"backslash escaped", `a\b`, `a\\b`},
		{"backslash before wildcard escaped first", `\%`, `\\\%`},
		{"mixed wildcards", `x_%\`, `x\_\%\\`},
		{"empty string", "", ""},
		{"package with underscore", "typing_extensions", `typing\_extensions`},
		{"package with multiple underscores and version", "py_lib_common_v2", `py\_lib\_common\_v2`},
		{"percent encoded lookalike", "foo%20bar", `foo\%20bar`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeLikePattern(tt.in); got != tt.want {
				t.Errorf("escapeLikePattern(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
