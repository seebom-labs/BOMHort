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
			Name:    "unknown-lib",
			Version: "1.0.0",
			PURL:    "pkg:generic/unknown-lib@1.0.0",
			License: "NOASSERTION", // Must be retained with manual review flag (#530)!
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
	if !strings.Contains(notice, "Package: unknown-lib") {
		t.Errorf("notice must retain unresolved/NOASSERTION packages for complete coverage")
	}
	if !strings.Contains(notice, "License: NOASSERTION [Unresolved license; manual review required]") {
		t.Errorf("notice missing unresolved license manual review flag")
	}
	if !strings.Contains(notice, "Components with unresolved licenses: 1 (flagged for manual review)") {
		t.Errorf("notice coverage summary missing unresolved license count: %s", notice)
	}
	if !strings.Contains(notice, "Copyright (c) 2014 TJ Holowaychuk") {
		t.Errorf("notice missing express copyright party")
	}
	if !strings.Contains(notice, "Permission is hereby granted, free of charge") {
		t.Errorf("notice missing MIT license text")
	}
}

func TestGenerateNotice_DeduplicatesByPURL(t *testing.T) {
	pkgs := []NoticePackage{
		{
			Name:             "core",
			Version:          "1.0.0",
			PURL:             "pkg:npm/%40team-a/core@1.0.0",
			License:          "MIT",
			CopyrightParties: []string{"Copyright Team A Authors"},
		},
		{
			Name:             "core",
			Version:          "1.0.0",
			PURL:             "pkg:npm/%40team-b/core@1.0.0",
			License:          "MIT",
			CopyrightParties: []string{"Copyright Team B Authors"},
		},
		// Duplicate of team-a should merge copyright
		{
			Name:             "core",
			Version:          "1.0.0",
			PURL:             "pkg:npm/%40team-a/core@1.0.0",
			License:          "MIT",
			CopyrightParties: []string{"Copyright Team A Contributor 2"},
		},
		// Components without PURL fallback to name/version/license
		{
			Name:             "embedded-tool",
			Version:          "2.0",
			License:          "Apache-2.0",
			CopyrightParties: []string{"Copyright Tool Authors"},
		},
		{
			Name:             "embedded-tool",
			Version:          "2.0",
			License:          "Apache-2.0",
			CopyrightParties: []string{"Copyright Tool Authors Extra"},
		},
	}

	notice := GenerateNotice("multi-scope-app", pkgs)

	// Both distinct scoped packages must be preserved separately (#530).
	if !strings.Contains(notice, "PURL: pkg:npm/%40team-a/core@1.0.0") {
		t.Errorf("expected team-a/core in notice")
	}
	if !strings.Contains(notice, "PURL: pkg:npm/%40team-b/core@1.0.0") {
		t.Errorf("expected team-b/core in notice")
	}
	if !strings.Contains(notice, "Copyright Team A Authors") {
		t.Errorf("expected team-a copyright in notice")
	}
	if !strings.Contains(notice, "Copyright Team A Contributor 2") {
		t.Errorf("expected merged team-a contributor in notice")
	}
	if !strings.Contains(notice, "Copyright Team B Authors") {
		t.Errorf("expected team-b copyright in notice")
	}

	// Total components should be 3 (team-a/core, team-b/core, embedded-tool)
	if !strings.Contains(notice, "Total third-party components: 3") {
		t.Errorf("expected 3 total third-party components in summary: %s", notice)
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
