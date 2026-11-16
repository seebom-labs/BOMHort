package license

import "sort"

// Reevaluate re-applies exception rules to a stored compliance result, so a
// newly granted (or revoked) exception reaches SBOMs that were ingested before
// it, without re-parsing them.
//
// It works from what license_compliance keeps per (SBOM, license): the
// packages that were non-compliant and the ones that were exempted. Together
// they are every package CheckWithExceptions tracked for a non-permissive
// license, so re-splitting them with the new rules gives the same result a
// fresh ingest would — for copyleft, unapproved and unknown licenses, which
// are the only ones that can produce a violation.
//
// Permissive licenses keep no package list unless a blanket exception covered
// them, so a blanket exception *added* for a permissive license cannot list
// their packages retroactively. That only affects the informational
// exempted count, never a violation: a permissive license is compliant either
// way.
//
// The category is kept as stored. Reclassifying a license is a policy change,
// and the package lists of a formerly permissive license were never recorded,
// so policy changes still need a re-scan.
func Reevaluate(r Result, exceptions *ExceptionIndex, project string) Result {
	names := make([]string, 0, len(r.NonCompliantPackages)+len(r.ExemptedPackages))
	names = append(names, r.NonCompliantPackages...)
	names = append(names, r.ExemptedPackages...)

	cat := Categorize(r.LicenseID)
	out := Result{
		LicenseID:    r.LicenseID,
		Category:     cat,
		PackageCount: r.PackageCount,
	}

	if exceptions != nil {
		if exempt, reason := exceptions.IsExempt("", r.LicenseID); exempt {
			out.ExemptedPackages = names
			out.ExemptionReason = reason
			return out
		}
	}
	if cat == CategoryPermissive {
		return out
	}
	for _, name := range names {
		if exempt, _ := exceptions.IsExempt(name, r.LicenseID, project); exempt {
			out.ExemptedPackages = append(out.ExemptedPackages, name)
		} else {
			out.NonCompliantPackages = append(out.NonCompliantPackages, name)
		}
	}
	return out
}

// SameOutcome reports whether two results have identical category and package split.
// Package order is not significant: Reevaluate regroups the stored lists, so
// an unchanged outcome usually comes back in a different order.
func SameOutcome(a, b Result) bool {
	return a.Category == b.Category &&
		a.ExemptionReason == b.ExemptionReason &&
		sameMultiset(a.NonCompliantPackages, b.NonCompliantPackages) &&
		sameMultiset(a.ExemptedPackages, b.ExemptedPackages)
}

func sameMultiset(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
