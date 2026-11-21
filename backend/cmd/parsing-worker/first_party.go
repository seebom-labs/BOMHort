package main

import "github.com/seebom-labs/bomhort/backend/internal/evaluate"

func licenseCheckSkips(roots []uint32, purls []string) []uint32 {
	return evaluate.LicenseCheckSkips(roots, purls)
}

func isFirstPartyPURL(purl string) bool {
	return evaluate.IsFirstPartyPURL(purl)
}
