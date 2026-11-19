package clearlydefined

import (
	"strings"
	"testing"
)

func TestGenerateNotice(t *testing.T) {
	pkgs := []NoticePackage{
		{
			Name:             "express",
			Version:          "4.18.2",
			PURL:             "pkg:npm/express@4.18.2",
			License:          "MIT",
			CopyrightParties: []string{"Copyright (c) 2014 TJ Holowaychuk", "Copyright (c) 2014 Douglas Christopher Wilson"},
		},
		{
			Name:             "lodash",
			Version:          "4.17.21",
			PURL:             "pkg:npm/lodash@4.17.21",
			License:          "MIT",
			CopyrightParties: []string{"Copyright JS Foundation and other contributors"},
		},
		{
			Name:    "internal-secret",
			Version: "1.0.0",
			PURL:    "pkg:npm/internal-secret@1.0.0",
			License: "NOASSERTION", // Must be excluded from notice!
		},
	}

	notice := GenerateNotice("demo-fleet-app", pkgs)

	if !strings.Contains(notice, "Target: demo-fleet-app") {
		t.Errorf("notice missing target header: %s", notice)
	}
	if !strings.Contains(notice, "Package: express") {
		t.Errorf("notice missing express package entry")
	}
	if !strings.Contains(notice, "Package: lodash") {
		t.Errorf("notice missing lodash package entry")
	}
	if strings.Contains(notice, "Package: internal-secret") {
		t.Errorf("notice should NOT contain unresolved/NOASSERTION packages")
	}
	if !strings.Contains(notice, "Copyright (c) 2014 TJ Holowaychuk") {
		t.Errorf("notice missing express copyright party")
	}
	if !strings.Contains(notice, "Permission is hereby granted, free of charge") {
		t.Errorf("notice missing MIT license text")
	}
}

func TestGenerateNoticeWithFallback(t *testing.T) {
	pkgs := []NoticePackage{
		{
			Name:    "express",
			Version: "4.18.2",
			PURL:    "pkg:npm/express@4.18.2",
			License: "MIT",
		},
	}

	// With nil resolver: immediate local generation fallback.
	notice := (*Resolver)(nil).GenerateNoticeWithFallback(nil, "my-app", pkgs)
	if !strings.Contains(notice, "Package: express") {
		t.Errorf("expected local fallback notice with express")
	}
}
