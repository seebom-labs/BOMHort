package main

import (
	"log"
	"sort"
	"strings"

	"github.com/seebom-labs/bomhort/backend/internal/extrafields"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// applyExtraFields stores the operator-declared fields found in raw on
// the SBOM row. It never fails the job: an SBOM without the fields, or with
// fields in an unexpected shape, is ingested exactly as before.
func applyExtraFields(sbom *models.SBOM, raw []byte, cfg *extrafields.Config) {
	sbom.ExtraFields = extrafields.Extract(raw, cfg)
	if len(sbom.ExtraFields) == 0 {
		return
	}
	names := make([]string, 0, len(sbom.ExtraFields))
	for name := range sbom.ExtraFields {
		names = append(names, name)
	}
	sort.Strings(names)
	// Names only: the values are untrusted producer input and do not belong
	// in the log.
	log.Printf("  Recognised extra fields: %s", strings.Join(names, ", "))
}
