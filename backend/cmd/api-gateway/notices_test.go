package main

import (
	"testing"
)

func TestNoticeFilename(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"", "NOTICE.txt"},
		{"   ", "NOTICE.txt"},
		{"my-project", "NOTICE-my-project.txt"},
		{"my-project (v1.0.0)", "NOTICE-my-project--v1.0.0.txt"},
		{"org/repo", "NOTICE-org-repo.txt"},
		{"../../evil", "NOTICE-evil.txt"},
	} {
		got := noticeFilename(tc.input)
		if got != tc.want {
			t.Errorf("noticeFilename(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
