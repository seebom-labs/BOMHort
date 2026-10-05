package license

import (
	"regexp"
	"strings"
)

// spdxAliases maps free-text license names that carry no version but are
// still unambiguous onto SPDX IDs. Keys are lower-case with collapsed
// whitespace.
//
// Only unambiguous spellings belong here or in familyRules. "BSD" (which
// clause count?), "Apache Software License" (1.1 or 2.0?) and "Public Domain"
// (no SPDX ID) are deliberately absent: guessing would turn an unapproved
// license into an approved one without anyone having decided so.
var spdxAliases = map[string]string{
	"simplified bsd license": "BSD-2-Clause",
	"freebsd license":        "BSD-2-Clause",
	// re2j and other Go ports ship Go's license, which is BSD-3-Clause.
	"go license": "BSD-3-Clause",
	// SPDX lists the Bouncy Castle Licence as MIT.
	"bouncy castle licence": "MIT",
	"bouncy castle license": "MIT",
	"the unlicense":         "Unlicense",
	"unlicense":             "Unlicense",
	// Composer's documented value for closed-source packages. Not an SPDX ID;
	// as a LicenseRef it is reported as unapproved rather than mistaken for one.
	"proprietary": "LicenseRef-proprietary",
}

// familyRule maps one spelling family to an SPDX ID. spdx receives the
// submatches and returns "" if the match is not usable.
type familyRule struct {
	re   *regexp.Regexp
	spdx func(m []string) string
}

// ver is the optional "version"/"v"/"v." prefix in front of a version number,
// with the separators POM and package.json authors put before it.
const ver = `[ ,-]*(?:\(\w+\)[ ,-]*)?(?:version |v\. ?|v ?)?`

func fixed(id string) func([]string) string { return func([]string) string { return id } }

// gnuSuffix turns "or later"-style wording into the SPDX -or-later suffix.
func gnuSuffix(later string) string {
	if strings.TrimSpace(later) != "" {
		return "-or-later"
	}
	return "-only"
}

var familyRules = []familyRule{
	{regexp.MustCompile(`^(?:the )?(?:gnu )?(?:general public license|gpl)` + ver + `2(?:\.0)?,? (?:with|w/) (?:the )?(?:gnu )?(?:classpath(?: exception)?|cpe)$`),
		fixed("GPL-2.0-only WITH Classpath-exception-2.0")},
	{regexp.MustCompile(`^(?:the )?(?:gnu )?(?:(?:lesser|library) general public license|lgpl)` + ver + `(2\.1|2|3)(?:\.0)?( or later| or greater| or any later version|\+)?$`),
		func(m []string) string {
			v := map[string]string{"2.1": "2.1", "2": "2.0", "3": "3.0"}[m[1]]
			return "LGPL-" + v + gnuSuffix(m[2])
		}},
	{regexp.MustCompile(`^(?:the )?(?:gnu )?(?:affero general public license|agpl)` + ver + `3(?:\.0)?( or later| or greater| or any later version|\+)?$`),
		func(m []string) string { return "AGPL-3.0" + gnuSuffix(m[1]) }},
	{regexp.MustCompile(`^(?:the )?(?:gnu )?(?:general public license|gpl)` + ver + `([123])(?:\.0)?( or later| or greater| or any later version|\+)?$`),
		func(m []string) string { return "GPL-" + m[1] + ".0" + gnuSuffix(m[2]) }},
	{regexp.MustCompile(`^(?:the )?apache(?: software| public)?(?: license)?` + ver + `2(?:\.0)?(?: license)?$`),
		fixed("Apache-2.0")},
	{regexp.MustCompile(`^(?:the )?(?:eclipse public license|epl)` + ver + `([12])(?:\.0)?$`),
		func(m []string) string { return "EPL-" + m[1] + ".0" }},
	// SPDX: the Eclipse Distribution License 1.0 is BSD-3-Clause.
	{regexp.MustCompile(`^(?:the )?(?:eclipse distribution license|edl)` + ver + `1(?:\.0)?$`),
		fixed("BSD-3-Clause")},
	{regexp.MustCompile(`^(?:the )?(?:mozilla public license|mpl)` + ver + `(1\.0|1\.1|2\.0|2)$`),
		func(m []string) string {
			if m[1] == "2" {
				return "MPL-2.0"
			}
			return "MPL-" + m[1]
		}},
	{regexp.MustCompile(`^(?:the )?(?:common development and distribution license|cddl)` + ver + `(1\.0|1\.1|1)$`),
		func(m []string) string {
			if m[1] == "1" {
				return "CDDL-1.0"
			}
			return "CDDL-" + m[1]
		}},
	{regexp.MustCompile(`^(?:the )?(?:universal permissive license|upl)` + ver + `1(?:\.0)?$`),
		fixed("UPL-1.0")},
	{regexp.MustCompile(`^(?:the )?(?:(?:new|revised|modified|3-clause) bsd(?: license)?|bsd[ -](?:3[ -]?clause|new|revised|license 3|3)(?: license)?)$`),
		fixed("BSD-3-Clause")},
	{regexp.MustCompile(`^(?:the )?(?:(?:simplified|2-clause) bsd(?: license)?|bsd[ -](?:2[ -]?clause|simplified|2)(?: license)?)$`),
		fixed("BSD-2-Clause")},
	{regexp.MustCompile(`^(?:the )?(?:mit|expat)(?: license)?$`), fixed("MIT")},
	{regexp.MustCompile(`^(?:the )?isc(?: license)?$`), fixed("ISC")},
	{regexp.MustCompile(`^(?:the )?(?:psf|python software foundation)(?: license)?(?:` + ver + `2(?:\.0)?)?$`),
		fixed("PSF-2.0")},
	{regexp.MustCompile(`^(?:public domain, per creative commons )?(?:cc0|creative commons zero)(?:[ -]v?1\.0)?(?: universal)?$`),
		fixed("CC0-1.0")},
	// "CC BY-SA 4.0" → CC-BY-SA-4.0: SPDX joins every part with '-'.
	{regexp.MustCompile(`^(?:cc|creative commons)[ -]by((?:[ -](?:sa|nc|nd))*)[ -](\d\.\d)$`),
		func(m []string) string {
			return "CC-BY" + strings.ToUpper(strings.ReplaceAll(m[1], " ", "-")) + "-" + m[2]
		}},
}

// exprSeparator splits an SPDX expression into leaves while keeping the
// operators and parentheses, so they can be reassembled.
var exprSeparator = regexp.MustCompile(`(?i)\s+(?:AND|OR)\s+|[()]`)

var withSeparator = regexp.MustCompile(`(?i)\s+WITH\s+`)

var spdxIDToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]*$`)

// Normalize rewrites free-text license spellings inside a license string or
// SPDX expression to SPDX IDs ("MPL 2.0" → "MPL-2.0",
// "The Apache Software License, Version 2.0" → "Apache-2.0",
// "CC BY-SA 4.0 and MIT" → "CC-BY-SA-4.0 AND MIT"). Anything it does not
// recognise, including valid SPDX IDs, is returned unchanged.
func Normalize(expr string) string {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return expr
	}
	if spdx, ok := normalizeLeaf(trimmed); ok {
		return spdx
	}

	var b strings.Builder
	changed := false
	last := 0
	for _, loc := range exprSeparator.FindAllStringIndex(trimmed, -1) {
		changed = writeLeaf(&b, trimmed[last:loc[0]]) || changed
		b.WriteString(strings.ToUpper(trimmed[loc[0]:loc[1]]))
		last = loc[1]
	}
	changed = writeLeaf(&b, trimmed[last:]) || changed
	if !changed {
		return expr
	}
	return b.String()
}

// writeLeaf writes one expression leaf, normalised if possible, preserving its
// surrounding whitespace. It reports whether the leaf was rewritten.
func writeLeaf(b *strings.Builder, leaf string) bool {
	core := strings.TrimSpace(leaf)
	if core == "" {
		b.WriteString(leaf)
		return false
	}
	start := strings.Index(leaf, core)
	b.WriteString(leaf[:start])
	spdx, ok := normalizeLeaf(core)
	if !ok {
		spdx = core
	}
	b.WriteString(spdx)
	b.WriteString(leaf[start+len(core):])
	return ok
}

// normalizeLeaf maps a single license (optionally "X WITH exception") to its
// SPDX ID. The whole text is tried first, because free-text names such as
// "GPL version 2 with the Classpath Exception" contain "with" themselves.
func normalizeLeaf(leaf string) (string, bool) {
	if spdx, ok := lookupFamily(leaf); ok {
		return spdx, true
	}
	loc := withSeparator.FindStringIndex(leaf)
	if loc == nil {
		return "", false
	}
	exception := strings.TrimSpace(leaf[loc[1]:])
	if !spdxIDToken.MatchString(exception) {
		return "", false
	}
	spdx, ok := lookupFamily(leaf[:loc[0]])
	if !ok {
		return "", false
	}
	return spdx + " WITH " + exception, true
}

func lookupFamily(name string) (string, bool) {
	key := strings.ToLower(strings.Join(strings.Fields(name), " "))
	if spdx, ok := spdxAliases[key]; ok {
		return spdx, true
	}
	for _, r := range familyRules {
		if m := r.re.FindStringSubmatch(key); m != nil {
			if spdx := r.spdx(m); spdx != "" {
				return spdx, true
			}
		}
	}
	return "", false
}

// LooksLikeSPDX reports whether s is syntactically an SPDX license expression:
// ID tokens joined by AND/OR/WITH, optionally parenthesised. It does not check
// the IDs against the SPDX list.
func LooksLikeSPDX(s string) bool {
	tokens := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' || r == '(' || r == ')' })
	if len(tokens) == 0 {
		return false
	}
	expectID := true
	for _, t := range tokens {
		switch strings.ToUpper(t) {
		case "AND", "OR", "WITH":
			if expectID {
				return false
			}
			expectID = true
			continue
		}
		if !expectID || !spdxIDToken.MatchString(t) {
			return false
		}
		expectID = false
	}
	return !expectID
}

var licenseRefInvalid = regexp.MustCompile(`[^A-Za-z0-9.]+`)

// LicenseRef turns a declared license name that has no SPDX ID into an SPDX
// LicenseRef ("Remix Icon License 1.0" → "LicenseRef-Remix-Icon-License-1.0").
// The package keeps a declared license, which the policy can then approve by
// that exact ID, instead of degrading to NOASSERTION. Returns "" for input
// with nothing usable in it.
func LicenseRef(name string) string {
	ref := strings.Trim(licenseRefInvalid.ReplaceAllString(strings.TrimSpace(name), "-"), "-.")
	if ref == "" {
		return ""
	}
	if len(ref) > 64 {
		ref = strings.TrimRight(ref[:64], "-.")
	}
	return "LicenseRef-" + ref
}

// Recover turns one declared license name from registry metadata into an SPDX
// expression: a recognisable spelling becomes its SPDX ID ("The MIT License"
// → "MIT"), anything else a LicenseRef so the package keeps its declared
// license and is reported as unapproved instead of NOASSERTION. URLs and empty
// input carry no license name and yield "".
func Recover(raw string) string {
	raw = strings.TrimSpace(raw)
	if isNoLicenseInfo(raw) {
		return ""
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return ""
	}
	if norm := Normalize(raw); LooksLikeSPDX(norm) {
		return norm
	}
	return LicenseRef(raw)
}
