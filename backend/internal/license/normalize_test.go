package license

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := []struct{ in, want string }{
		// Free-text spellings seen in real SBOMs.
		{"MPL 2.0", "MPL-2.0"},
		{"CC BY-SA 4.0", "CC-BY-SA-4.0"},
		{"CC BY 3.0", "CC-BY-3.0"},
		{"cc by-nc-nd 4.0", "CC-BY-NC-ND-4.0"},
		{"Apache License, Version 2.0", "Apache-2.0"},
		{"The  MIT  License", "MIT"},
		{"New BSD License", "BSD-3-Clause"},
		{"GPLv2", "GPL-2.0-only"},
		{"Apache 2.0 WITH LLVM-exception", "Apache-2.0 WITH LLVM-exception"},
		// Inside expressions, operators and parentheses survive.
		{"MIT AND CC BY-SA 4.0", "MIT AND CC-BY-SA-4.0"},
		{"(MPL 2.0 OR Apache 2.0) AND MIT", "(MPL-2.0 OR Apache-2.0) AND MIT"},
		{"mit and mpl 2.0", "MIT AND MPL-2.0"},
		{"Apache 2.0 with LLVM-exception", "Apache-2.0 WITH LLVM-exception"},
		// Maven POM / PyPI names as returned raw by deps.dev.
		{"The Apache Software License, Version 2.0", "Apache-2.0"},
		{"Apache Software License - Version 2.0", "Apache-2.0"},
		{"Apache Public License 2.0", "Apache-2.0"},
		{"Eclipse Public License - v 1.0", "EPL-1.0"},
		{"Eclipse Public License v. 2.0", "EPL-2.0"},
		{"EPL 2.0", "EPL-2.0"},
		{"Eclipse Distribution License - v 1.0", "BSD-3-Clause"},
		{"EDL 1.0", "BSD-3-Clause"},
		{"The MIT License", "MIT"},
		{"BSD New license", "BSD-3-Clause"},
		{"BSD License 3", "BSD-3-Clause"},
		{"Lesser General Public License, version 3 or greater", "LGPL-3.0-or-later"},
		{"LGPL 2.1", "LGPL-2.1-only"},
		{"GNU General Public License, version 2 with the GNU Classpath Exception", "GPL-2.0-only WITH Classpath-exception-2.0"},
		{"GPL2 w/ CPE", "GPL-2.0-only WITH Classpath-exception-2.0"},
		{"GPL-2.0+", "GPL-2.0-or-later"},
		{"Mozilla Public License Version 2.0", "MPL-2.0"},
		{"MPL 1.1", "MPL-1.1"},
		{"Common Development and Distribution License (CDDL) Version 1.0", "CDDL-1.0"},
		{"Universal Permissive License, Version 1.0", "UPL-1.0"},
		{"Universal Permissive License 1.0 or Apache License 2.0", "UPL-1.0 OR Apache-2.0"},
		{"PSF license", "PSF-2.0"},
		{"Public Domain, per Creative Commons CC0", "CC0-1.0"},
		{"Go License", "BSD-3-Clause"},
		{"Bouncy Castle Licence", "MIT"},
		// Valid SPDX and anything unrecognised is untouched.
		{"Apache-2.0", "Apache-2.0"},
		{"MIT OR Apache-2.0", "MIT OR Apache-2.0"},
		{"NOASSERTION", "NOASSERTION"},
		{"", ""},
		// Ambiguous spellings are deliberately not guessed.
		{"BSD", "BSD"},
		{"Public Domain", "Public Domain"},
		{"Remix Icon License 1.0", "Remix Icon License 1.0"},
		{"Apache Software License", "Apache Software License"},
		{"GNU Lesser General Public License", "GNU Lesser General Public License"},
		{"CDDL + GPLv2 with classpath exception", "CDDL + GPLv2 with classpath exception"},
		{"BSD 3-clause License w/nuclear disclaimer", "BSD 3-clause License w/nuclear disclaimer"},
		// Current SPDX IDs keep their exact form.
		{"GPL-2.0-only", "GPL-2.0-only"},
		{"GPL-3.0-or-later", "GPL-3.0-or-later"},
		{"BSD-3-Clause", "BSD-3-Clause"},
		{"BSD-2-Clause-Views", "BSD-2-Clause-Views"},
		{"MPL-2.0-no-copyleft-exception", "MPL-2.0-no-copyleft-exception"},
		{"Python-2.0", "Python-2.0"},
	}
	for _, c := range cases {
		if got := Normalize(c.in); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCategorize_NormalizesFreeTextSpellings(t *testing.T) {
	if got := Categorize("MPL 2.0"); got != CategoryCopyleft {
		t.Errorf("Categorize(MPL 2.0) = %q, want copyleft", got)
	}
	if got := Categorize("Apache License, Version 2.0"); got != CategoryPermissive {
		t.Errorf("Categorize(Apache License, Version 2.0) = %q, want permissive", got)
	}
	if got := Categorize("BSD"); got != CategoryUnapproved {
		t.Errorf("Categorize(BSD) = %q, want unapproved", got)
	}
}

func TestLooksLikeSPDX(t *testing.T) {
	cases := map[string]bool{
		"MIT":                       true,
		"MIT OR Apache-2.0":         true,
		"(MIT or Apache-2.0) AND X": true,
		"GPL-2.0-only WITH Classpath-exception-2.0": true,
		"LicenseRef-Foo-1.0":                        true,
		"Go License":                                false,
		"MIT AND":                                   false,
		"AND MIT":                                   false,
		"https://aka.ms/x":                          false,
		"":                                          false,
	}
	for in, want := range cases {
		if got := LooksLikeSPDX(in); got != want {
			t.Errorf("LooksLikeSPDX(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestLicenseRef(t *testing.T) {
	cases := map[string]string{
		"Remix Icon License 1.0":     "LicenseRef-Remix-Icon-License-1.0",
		"BSD":                        "LicenseRef-BSD",
		"  Public Domain  ":          "LicenseRef-Public-Domain",
		"CDDL + GPLv2 w/ classpath!": "LicenseRef-CDDL-GPLv2-w-classpath",
		"!!!":                        "",
	}
	for in, want := range cases {
		if got := LicenseRef(in); got != want {
			t.Errorf("LicenseRef(%q) = %q, want %q", in, got, want)
		}
	}
	if got := LicenseRef(strings.Repeat("a", 100)); len(got) != len("LicenseRef-")+64 {
		t.Errorf("LicenseRef did not truncate: %q", got)
	}
}

func TestRecover(t *testing.T) {
	tests := []struct{ in, want string }{
		// Recognisable spellings become SPDX.
		{"The MIT License", "MIT"},
		{"Apache License, Version 2.0", "Apache-2.0"},
		{"  MIT  ", "MIT"},
		{"MIT OR Apache-2.0", "MIT OR Apache-2.0"},
		// Unrecognised names keep the declared license as a LicenseRef.
		{"Remix Icon License 1.0", "LicenseRef-Remix-Icon-License-1.0"},
		{"Public Domain", "LicenseRef-Public-Domain"},
		{"proprietary", "LicenseRef-proprietary"},
		// A single ID-like token is kept as declared (unapproved), not guessed.
		{"BSD", "BSD"},
		// No license name at all.
		{"", ""},
		{"NOASSERTION", ""},
		{"NONE", ""},
		{"https://opensource.org/licenses/MIT", ""},
		{"HTTP://example.com/LICENSE", ""},
	}
	for _, tt := range tests {
		if got := Recover(tt.in); got != tt.want {
			t.Errorf("Recover(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLicenseRefLength(t *testing.T) {
	long := strings.Repeat("Very Long License Name ", 10)
	ref := LicenseRef(long)
	if !strings.HasPrefix(ref, "LicenseRef-") || len(ref) > len("LicenseRef-")+64 {
		t.Errorf("LicenseRef(long) = %q, want a LicenseRef of at most 64 characters", ref)
	}
	if strings.HasSuffix(ref, "-") {
		t.Errorf("LicenseRef(long) = %q ends with a separator", ref)
	}
	if got := LicenseRef(" -- "); got != "" {
		t.Errorf("LicenseRef(punctuation) = %q, want \"\"", got)
	}
}
