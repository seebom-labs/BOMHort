package sanitize

import (
	"strings"
	"testing"
)

func TestLogParam(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain string unchanged",
			input:    "cluster-prod-1",
			expected: "cluster-prod-1",
		},
		{
			name:     "strips newlines and carriage returns",
			input:    "line1\r\nline2\nline3\r",
			expected: "line1line2line3",
		},
		{
			name:     "strips ANSI escapes, NUL, and C0 control characters",
			input:    "\x1b[31;1mCRITICAL\x1b[0m\x00\a\b\f\x7flog",
			expected: "[31;1mCRITICAL[0mlog",
		},
		{
			name:     "strips tab characters",
			input:    "col1\tcol2",
			expected: "col1col2",
		},
		{
			name:     "strips C1 control characters (U+0080 to U+009F)",
			input:    "a\u009b31mb",
			expected: "a31mb",
		},
		{
			name:     "strips C1 next-line character (U+0085)",
			input:    "line1\u0085line2",
			expected: "line1line2",
		},
		{
			name:     "preserves exact 200 characters without ellipsis",
			input:    strings.Repeat("a", 200),
			expected: strings.Repeat("a", 200),
		},
		{
			name:     "truncates strings exceeding 200 runes with ellipsis",
			input:    strings.Repeat("a", 205),
			expected: strings.Repeat("a", 200) + "...",
		},
		{
			name:     "unicode multi-byte safe truncation",
			input:    strings.Repeat("日", 210),
			expected: strings.Repeat("日", 200) + "...",
		},
		{
			name:     "ignores control characters when counting rune bounds",
			input:    strings.Repeat("\n", 50) + strings.Repeat("x", 200),
			expected: strings.Repeat("x", 200),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LogParam(tt.input)
			if got != tt.expected {
				t.Errorf("LogParam(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
