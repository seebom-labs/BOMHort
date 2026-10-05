package main

import (
	"reflect"
	"testing"
)

func TestLicenseCheckSkips(t *testing.T) {
	purls := []string{
		"pkg:npm/%40backstage/cli-node@0.0.0-use.local",
		"pkg:npm/lodash@4.17.21",
		"pkg:npm/app@0.0.0-use.local?vcs_url=x",
		"pkg:maven/a/b@0.0.0-use.local",
		"",
		"pkg:maven/${project.groupId}/athenz-zms-core@unknown",
		"pkg:maven/%24%7Bproject.parent.groupId%7D/core@1.0",
		"pkg:maven/org.scalatest/scalatest_${scala.compat.version}@3.3.0",
	}
	got := licenseCheckSkips([]uint32{4}, purls)
	want := []uint32{4, 0, 2, 5, 6}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("licenseCheckSkips() = %v, want %v", got, want)
	}

	roots := []uint32{1}
	_ = licenseCheckSkips(roots, purls)
	if !reflect.DeepEqual(roots, []uint32{1}) {
		t.Fatalf("licenseCheckSkips mutated its roots argument: %v", roots)
	}
}
