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
			Name:             "express",
			Version:          "4.18.2",
			PURL:             "pkg:npm/express@4.18.2",
			License:          "MIT",
			CopyrightParties: []string{"Copyright (c) 2014 TJ Holowaychuk"},
		},
		{
			Name:    "internal-helper",
			Version: "1.0.0",
			PURL:    "pkg:generic/internal-helper@1.0.0",
			License: "Apache-2.0",
			// No CopyrightParties: must be flagged explicitly as missing upstream copyright notice!
		},
		{
			Name:    "unharvested-pkg",
			Version: "2.1.0",
			PURL:    "pkg:npm/unharvested-pkg@2.1.0",
			License: "BSD-3-Clause",
			// Unharvested: must be retained and flagged for manual review!
		},
	}

	// With nil resolver: immediate local generation fallback with full package coverage (#530).
	notice := (*Resolver)(nil).GenerateNoticeWithFallback(nil, "my-app", pkgs)

	// All 3 packages must be retained in the notice (#530).
	if !strings.Contains(notice, "Package: express") {
		t.Errorf("expected notice to contain express package")
	}
	if !strings.Contains(notice, "Package: internal-helper") {
		t.Errorf("expected notice to keep pkg:generic package internal-helper")
	}
	if !strings.Contains(notice, "Package: unharvested-pkg") {
		t.Errorf("expected notice to keep unharvested package")
	}

	// Express has copyright party
	if !strings.Contains(notice, "Copyright (c) 2014 TJ Holowaychuk") {
		t.Errorf("expected express copyright party in notice")
	}

	// Missing copyright notices must be explicitly flagged for manual review (#530).
	if !strings.Contains(notice, "[No upstream copyright statement recorded; manual review required]") {
		t.Errorf("expected missing copyright notices to be explicitly flagged")
	}

	// Summary banner must report missing attribution count (#530).
	if !strings.Contains(notice, "Components missing upstream copyright notice: 2 (flagged for manual review)") {
		t.Errorf("expected summary banner to report missing attribution count")
	}

	// Appendix must include complete license texts for MIT, Apache-2.0, and BSD-3-Clause
	if !strings.Contains(notice, "APPENDIX: FULL LICENSE TERMS") {
		t.Errorf("expected appendix with full license terms")
	}
	if !strings.Contains(notice, "License Terms: Apache-2.0") || !strings.Contains(notice, "License Terms: MIT") {
		t.Errorf("expected license terms sections for Apache-2.0 and MIT")
	}
}
