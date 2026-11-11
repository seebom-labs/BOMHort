package advisory

import (
	"strconv"
	"strings"
)

// compareFunc orders two versions of one ecosystem: <0, 0 or >0. ok is false
// when either version cannot be read in that ecosystem's syntax; a range is
// then not evaluated rather than guessed.
type compareFunc func(a, b string) (cmp int, ok bool)

// comparatorFor returns the version order of a PURL type for an ECOSYSTEM
// range, or nil when BOMHort has no comparator for it. The distro types are
// the point of advisory feeds: their versions carry the backport
// ("-r4", "+deb12u1", ".el9_2") that an upstream range cannot see.
func comparatorFor(purlType string) compareFunc {
	switch purlType {
	case "apk":
		return compareAPK
	case "deb":
		return compareDeb
	case "rpm":
		return compareRPM
	}
	return nil
}

// ---------------------------------------------------------------- semver

type semver struct {
	core [3]uint64
	pre  []string
}

func parseSemver(v string) (semver, bool) {
	var s semver
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		if i == len(v)-1 {
			return s, false
		}
		s.pre = strings.Split(v[i+1:], ".")
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return s, false
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return s, false
		}
		s.core[i] = n
	}
	return s, true
}

// compareSemver implements SemVer 2.0 precedence. OSV uses it for every range
// of type SEMVER, whatever the ecosystem.
func compareSemver(a, b string) (int, bool) {
	x, ok1 := parseSemver(a)
	y, ok2 := parseSemver(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	for i := range x.core {
		if c := cmpUint(x.core[i], y.core[i]); c != 0 {
			return c, true
		}
	}
	switch {
	case len(x.pre) == 0 && len(y.pre) == 0:
		return 0, true
	case len(x.pre) == 0:
		return 1, true
	case len(y.pre) == 0:
		return -1, true
	}
	for i := 0; i < len(x.pre) && i < len(y.pre); i++ {
		xn, xNum := strconv.ParseUint(x.pre[i], 10, 64)
		yn, yNum := strconv.ParseUint(y.pre[i], 10, 64)
		switch {
		case xNum == nil && yNum == nil:
			if c := cmpUint(xn, yn); c != 0 {
				return c, true
			}
		case xNum == nil:
			return -1, true
		case yNum == nil:
			return 1, true
		default:
			if c := strings.Compare(x.pre[i], y.pre[i]); c != 0 {
				return c, true
			}
		}
	}
	return cmpInt(len(x.pre), len(y.pre)), true
}

// ---------------------------------------------------------------- dpkg

// compareDeb implements the Debian policy order (deb-version(7)):
// [epoch:]upstream[-revision], where "~" sorts before anything, even the end
// of the string, so 1.0~rc1 < 1.0 and 1.0+deb12u1 > 1.0.
func compareDeb(a, b string) (int, bool) {
	ea, ua, ra, ok1 := splitDeb(a)
	eb, ub, rb, ok2 := splitDeb(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	if c := cmpUint(ea, eb); c != 0 {
		return c, true
	}
	if c := debVerrevcmp(ua, ub); c != 0 {
		return c, true
	}
	return debVerrevcmp(ra, rb), true
}

func splitDeb(v string) (epoch uint64, upstream, revision string, ok bool) {
	if v == "" {
		return 0, "", "", false
	}
	if i := strings.IndexByte(v, ':'); i >= 0 {
		n, err := strconv.ParseUint(v[:i], 10, 64)
		if err != nil {
			return 0, "", "", false
		}
		epoch, v = n, v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		upstream, revision = v[:i], v[i+1:]
	} else {
		upstream = v
	}
	if upstream == "" || (upstream[0] < '0' || upstream[0] > '9') {
		return 0, "", "", false
	}
	return epoch, upstream, revision, true
}

func debOrder(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	case c == '~':
		return -1
	case c == 0:
		return 0
	default:
		return int(c) + 256
	}
}

func debVerrevcmp(a, b string) int {
	i, j := 0, 0
	at := func(s string, k int) byte {
		if k < len(s) {
			return s[k]
		}
		return 0
	}
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := debOrder(at(a, i)), debOrder(at(b, j))
			if ac != bc {
				return cmpInt(ac, bc)
			}
			i++
			j++
		}
		for at(a, i) == '0' {
			i++
		}
		for at(b, j) == '0' {
			j++
		}
		for isDigit(at(a, i)) && isDigit(at(b, j)) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if isDigit(at(a, i)) {
			return 1
		}
		if isDigit(at(b, j)) {
			return -1
		}
		if firstDiff != 0 {
			return cmpInt(firstDiff, 0)
		}
	}
	return 0
}

// ---------------------------------------------------------------- rpm

// compareRPM implements rpm's [epoch:]version[-release] order (rpmvercmp):
// alphanumeric segments, numbers beat letters, "~" sorts before the end of
// the string and "^" after it but before anything else.
func compareRPM(a, b string) (int, bool) {
	ea, va, ra, ok1 := splitRPM(a)
	eb, vb, rb, ok2 := splitRPM(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	if c := cmpUint(ea, eb); c != 0 {
		return c, true
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c, true
	}
	// A range bound without a release ("1.2") covers every release of it.
	if ra == "" || rb == "" {
		return 0, true
	}
	return rpmvercmp(ra, rb), true
}

func splitRPM(v string) (epoch uint64, version, release string, ok bool) {
	if v == "" {
		return 0, "", "", false
	}
	if i := strings.IndexByte(v, ':'); i >= 0 {
		n, err := strconv.ParseUint(v[:i], 10, 64)
		if err != nil {
			return 0, "", "", false
		}
		epoch, v = n, v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		version, release = v[:i], v[i+1:]
	} else {
		version = v
	}
	return epoch, version, release, version != ""
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		// Tilde: sorts before everything, including the end.
		at, bt := i < len(a) && a[i] == '~', j < len(b) && b[j] == '~'
		if at || bt {
			if !at {
				return 1
			}
			if !bt {
				return -1
			}
			i++
			j++
			continue
		}
		// Caret: sorts after the end, before anything else.
		ac, bc := i < len(a) && a[i] == '^', j < len(b) && b[j] == '^'
		if ac || bc {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if !ac {
				return 1
			}
			if !bc {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		numeric := a[i] >= '0' && a[i] <= '9'
		si, sj := i, j
		if numeric {
			for i < len(a) && a[i] >= '0' && a[i] <= '9' {
				i++
			}
			for j < len(b) && b[j] >= '0' && b[j] <= '9' {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		segA, segB := a[si:i], b[sj:j]
		if segB == "" {
			// Different segment types: numeric is newer.
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			segA, segB = strings.TrimLeft(segA, "0"), strings.TrimLeft(segB, "0")
			if c := cmpInt(len(segA), len(segB)); c != 0 {
				return c
			}
		}
		if c := strings.Compare(segA, segB); c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	default:
		return 1
	}
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// ---------------------------------------------------------------- apk

// apk suffixes, in apk-tools order: pre-release suffixes sort before the
// plain version, post-release ones after it.
var apkSuffixRank = map[string]int{
	"alpha": -4, "beta": -3, "pre": -2, "rc": -1,
	"cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5,
}

type apkSuffix struct {
	rank int
	num  uint64
}

type apkVersion struct {
	parts    []string
	letter   byte
	suffixes []apkSuffix
	rev      uint64
}

// parseAPK reads an Alpine/Wolfi package version:
// digits{.digits}[letter]{_suffix[digits]}[~hash][-rN].
func parseAPK(v string) (apkVersion, bool) {
	var out apkVersion
	if i := strings.LastIndex(v, "-r"); i >= 0 {
		n, err := strconv.ParseUint(v[i+2:], 10, 64)
		if err != nil {
			return out, false
		}
		out.rev, v = n, v[:i]
	}
	if i := strings.IndexByte(v, '~'); i >= 0 {
		v = v[:i]
	}
	core := v
	var suffixes []string
	if i := strings.IndexByte(v, '_'); i >= 0 {
		core = v[:i]
		suffixes = strings.Split(v[i+1:], "_")
	}
	if core == "" {
		return out, false
	}
	if last := core[len(core)-1]; last >= 'a' && last <= 'z' {
		out.letter, core = last, core[:len(core)-1]
	}
	for _, p := range strings.Split(core, ".") {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return out, false
		}
		out.parts = append(out.parts, p)
	}
	for _, s := range suffixes {
		name := strings.TrimRight(s, "0123456789")
		rank, ok := apkSuffixRank[name]
		if !ok {
			return out, false
		}
		var n uint64
		if digits := s[len(name):]; digits != "" {
			var err error
			if n, err = strconv.ParseUint(digits, 10, 64); err != nil {
				return out, false
			}
		}
		out.suffixes = append(out.suffixes, apkSuffix{rank: rank, num: n})
	}
	return out, true
}

func compareAPK(a, b string) (int, bool) {
	x, ok1 := parseAPK(a)
	y, ok2 := parseAPK(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	for i := 0; i < len(x.parts) && i < len(y.parts); i++ {
		p, q := x.parts[i], y.parts[i]
		var c int
		// apk compares a later component with a leading zero as a fraction.
		if i > 0 && (p[0] == '0' || q[0] == '0') {
			c = strings.Compare(p, q)
		} else {
			c = cmpNumeric(p, q)
		}
		if c != 0 {
			return c, true
		}
	}
	if c := cmpInt(len(x.parts), len(y.parts)); c != 0 {
		return c, true
	}
	if c := cmpInt(int(x.letter), int(y.letter)); c != 0 {
		return c, true
	}
	for i := 0; i < len(x.suffixes) || i < len(y.suffixes); i++ {
		var s, t apkSuffix
		if i < len(x.suffixes) {
			s = x.suffixes[i]
		}
		if i < len(y.suffixes) {
			t = y.suffixes[i]
		}
		if c := cmpInt(s.rank, t.rank); c != 0 {
			return c, true
		}
		if c := cmpUint(s.num, t.num); c != 0 {
			return c, true
		}
	}
	return cmpUint(x.rev, y.rev), true
}

// ---------------------------------------------------------------- helpers

func cmpNumeric(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if c := cmpInt(len(a), len(b)); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
