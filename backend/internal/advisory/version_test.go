package advisory

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		name string
		cmp  compareFunc
		a, b string
		want int
	}{
		// apk: the -rN revision carries the backport.
		{"apk revision", compareAPK, "3.1.4-r2", "3.1.4-r10", -1},
		{"apk equal", compareAPK, "1.2.3-r0", "1.2.3-r0", 0},
		{"apk longer", compareAPK, "1.2", "1.2.1", -1},
		{"apk numeric", compareAPK, "1.10", "1.9", 1},
		{"apk letter", compareAPK, "1.2a", "1.2", 1},
		{"apk pre-release", compareAPK, "1.2_rc1", "1.2", -1},
		{"apk alpha<beta", compareAPK, "1.2_alpha", "1.2_beta", -1},
		{"apk post-release", compareAPK, "1.2_p1", "1.2", 1},
		{"apk leading zero", compareAPK, "1.01", "1.1", -1},
		{"apk chromium", compareAPK, "149.0.7827.53-r0", "148.0.7778.96-r1", 1},

		// dpkg: "~" before everything, "+debNuM" after the upstream.
		{"deb backport", compareDeb, "3.0.11-1~deb12u2", "3.0.11-1", -1},
		{"deb security update", compareDeb, "3.0.11-1~deb12u2", "3.0.11-1~deb12u1", 1},
		{"deb plus", compareDeb, "1.0+deb12u1", "1.0", 1},
		{"deb tilde rc", compareDeb, "1.0~rc1", "1.0", -1},
		{"deb epoch", compareDeb, "1:0.9", "2.0", 1},
		{"deb revision", compareDeb, "2.36-9+deb12u4", "2.36-9+deb12u10", -1},
		{"deb equal", compareDeb, "1.2.3-1", "1.2.3-1", 0},

		// rpm: dist tags, tilde and caret.
		{"rpm el release", compareRPM, "1.1.1k-7.el8_6", "1.1.1k-9.el8_7", -1},
		{"rpm segment", compareRPM, "2.10", "2.9", 1},
		{"rpm tilde", compareRPM, "1.0~rc1", "1.0", -1},
		{"rpm caret", compareRPM, "1.0^git1", "1.0", 1},
		{"rpm caret before next", compareRPM, "1.0^git1", "1.0.1", -1},
		{"rpm epoch", compareRPM, "1:1.0-1", "2.0-1", 1},
		{"rpm number beats letter", compareRPM, "1.0a", "1.0.1", -1},
		{"rpm no release in bound", compareRPM, "1.2-5.el9", "1.2", 0},

		// semver
		{"semver", compareSemver, "1.2.3", "1.10.0", -1},
		{"semver prerelease", compareSemver, "1.0.0-rc.1", "1.0.0", -1},
		{"semver prerelease order", compareSemver, "1.0.0-alpha.2", "1.0.0-alpha.10", -1},
		{"semver v prefix", compareSemver, "v2.0.0", "1.9.9", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := c.cmp(c.a, c.b)
			if !ok {
				t.Fatalf("%s vs %s: not comparable", c.a, c.b)
			}
			if sign(got) != c.want {
				t.Errorf("%s vs %s = %d, want %d", c.a, c.b, got, c.want)
			}
			back, _ := c.cmp(c.b, c.a)
			if sign(back) != -c.want {
				t.Errorf("%s vs %s = %d, not antisymmetric", c.b, c.a, back)
			}
		})
	}
}

// A version that does not parse is "not comparable", never a guess.
func TestCompareVersionsRejectsGarbage(t *testing.T) {
	for _, c := range []struct {
		cmp  compareFunc
		a, b string
	}{
		{compareAPK, "1.2-rx", "1.2"},
		{compareAPK, "abc", "1.0"},
		{compareDeb, "x:1.0", "1.0"},
		{compareDeb, "", "1.0"},
		{compareSemver, "1.2.3.4", "1.0.0"},
	} {
		if _, ok := c.cmp(c.a, c.b); ok {
			t.Errorf("%q vs %q reported comparable", c.a, c.b)
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
