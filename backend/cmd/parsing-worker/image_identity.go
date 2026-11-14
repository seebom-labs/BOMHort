package main

import (
	"strings"

	"github.com/seebom-labs/bomhort/backend/internal/imagedigest"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// resolveImageIdentity determines the image reference and digest for an SBOM.
// Priority:
// 1. Explicitly supplied on the job (e.g. from upload params or headers).
// 2. Extracted from root or package PURLs matching pkg:oci/...
// 3. Extracted from document name (if it contains image@sha256:...).
func resolveImageIdentity(job models.IngestionJob, packages *models.SBOMPackages, docName string) (imageRef, imageDigest string) {
	imageRef = strings.TrimSpace(job.ImageRef)
	imageDigest = imagedigest.NormalizeDigest(job.ImageDigest)

	// If ref was supplied like "repo:tag@sha256:...", split it.
	if imageRef != "" && imageDigest == "" {
		ref, dig := imagedigest.ExtractFromRef(imageRef)
		if dig != "" {
			imageRef = ref
			imageDigest = dig
		}
	}

	if imageDigest != "" {
		return imageRef, imageDigest
	}

	// Try extracting from packages if any has a pkg:oci PURL.
	if packages != nil {
		for _, purl := range packages.PackagePURLs {
			if strings.HasPrefix(purl, "pkg:oci/") {
				ref, dig := imagedigest.ExtractFromPURL(purl)
				if dig != "" {
					if imageRef == "" {
						imageRef = ref
					}
					return imageRef, dig
				}
			}
		}
	}

	// Try extracting from document name
	if docName != "" {
		ref, dig := imagedigest.ExtractFromRef(docName)
		if dig != "" {
			if imageRef == "" {
				imageRef = ref
			}
			return imageRef, dig
		}
	}

	return imageRef, ""
}
