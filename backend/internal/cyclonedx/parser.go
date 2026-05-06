// Package cyclonedx provides a lightweight CycloneDX JSON parser.
// It extracts the same data as the SPDX parser (packages, PURLs, licenses, relationships)
// and maps it to the shared models for ClickHouse insertion.
package cyclonedx

import (
	"fmt"
	"strings"
	"time"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/seebom-labs/seebom/backend/pkg/models"
)

// ParseResult contains the extracted data from a CycloneDX document.
type ParseResult struct {
	SBOM     models.SBOM
	Packages models.SBOMPackages
}

// CDXDocument represents the top-level structure of a CycloneDX JSON BOM.
type CDXDocument struct {
	BomFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber"`
	Version      int             `json:"version"`
	Metadata     CDXMetadata     `json:"metadata"`
	Components   []CDXComponent  `json:"components"`
	Dependencies []CDXDependency `json:"dependencies"`
}

// CDXMetadata holds BOM metadata.
type CDXMetadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []CDXTool `json:"tools"`
	Component *CDXComponent `json:"component"`
}

// CDXTool represents a tool entry in metadata.
type CDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CDXComponent represents a single component in the BOM.
type CDXComponent struct {
	Type    string       `json:"type"`
	BomRef  string       `json:"bom-ref"`
	Name    string       `json:"name"`
	Version string       `json:"version"`
	PURL    string       `json:"purl"`
	Licenses []CDXLicense `json:"licenses"`
}

// CDXLicense represents a license entry (can be expression or structured).
type CDXLicense struct {
	License    *CDXLicenseID `json:"license,omitempty"`
	Expression string        `json:"expression,omitempty"`
}

// CDXLicenseID holds a specific license identifier.
type CDXLicenseID struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// CDXDependency represents a dependency relationship.
type CDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// Parse decodes a CycloneDX JSON document and extracts models for ClickHouse.
func Parse(data []byte, sourceFile, sha256Hash string) (*ParseResult, error) {
	var doc CDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to decode CycloneDX JSON: %w", err)
	}

	if doc.BomFormat != "CycloneDX" {
		return nil, fmt.Errorf("not a CycloneDX document (bomFormat=%q)", doc.BomFormat)
	}

	sbomID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(sha256Hash))
	now := time.Now()

	// Parse creation timestamp.
	creationDate, err := time.Parse(time.RFC3339, doc.Metadata.Timestamp)
	if err != nil {
		creationDate = now
	}

	// Extract tools.
	var tools []string
	for _, t := range doc.Metadata.Tools {
		toolStr := t.Name
		if t.Vendor != "" {
			toolStr = t.Vendor + " " + t.Name
		}
		if t.Version != "" {
			toolStr += " " + t.Version
		}
		tools = append(tools, "Tool: "+toolStr)
	}

	// Document name: use metadata component name or serial number.
	docName := ""
	if doc.Metadata.Component != nil {
		docName = doc.Metadata.Component.Name
		if doc.Metadata.Component.Version != "" {
			docName += " " + doc.Metadata.Component.Version
		}
	}
	if docName == "" {
		docName = doc.SerialNumber
	}

	sbom := models.SBOM{
		IngestedAt:        now,
		SBOMID:            sbomID,
		SourceFile:        sourceFile,
		SPDXVersion:       "CycloneDX-" + doc.SpecVersion,
		DocumentName:      docName,
		DocumentNamespace: doc.SerialNumber,
		SHA256Hash:        sha256Hash,
		CreationDate:      creationDate,
		CreatorTools:      tools,
	}

	// Build parallel arrays from components.
	bomRefToIndex := make(map[string]uint32, len(doc.Components))

	var (
		spdxIDs  []string
		names    []string
		versions []string
		purls    []string
		licenses []string
	)

	for i, comp := range doc.Components {
		idx := uint32(i)
		if comp.BomRef != "" {
			bomRefToIndex[comp.BomRef] = idx
		}

		// Use bom-ref as the "SPDX ID" equivalent.
		spdxIDs = append(spdxIDs, comp.BomRef)
		names = append(names, comp.Name)
		versions = append(versions, comp.Version)
		purls = append(purls, comp.PURL)

		// Extract license.
		lic := extractLicense(comp.Licenses)
		licenses = append(licenses, lic)
	}

	// Build relationship arrays from dependencies.
	var (
		relSources []uint32
		relTargets []uint32
		relTypes   []string
	)

	for _, dep := range doc.Dependencies {
		srcIdx, srcOK := bomRefToIndex[dep.Ref]
		if !srcOK {
			continue
		}
		for _, target := range dep.DependsOn {
			tgtIdx, tgtOK := bomRefToIndex[target]
			if tgtOK {
				relSources = append(relSources, srcIdx)
				relTargets = append(relTargets, tgtIdx)
				relTypes = append(relTypes, "DEPENDS_ON")
			}
		}
	}

	packages := models.SBOMPackages{
		IngestedAt:       now,
		SBOMID:           sbomID,
		SourceFile:       sourceFile,
		PackageSPDXIDs:   spdxIDs,
		PackageNames:     names,
		PackageVersions:  versions,
		PackagePURLs:     purls,
		PackageLicenses:  licenses,
		RelSourceIndices: relSources,
		RelTargetIndices: relTargets,
		RelTypes:         relTypes,
	}

	return &ParseResult{
		SBOM:     sbom,
		Packages: packages,
	}, nil
}

// extractLicense extracts the best license string from CycloneDX license entries.
func extractLicense(lics []CDXLicense) string {
	if len(lics) == 0 {
		return "NOASSERTION"
	}

	var parts []string
	for _, l := range lics {
		if l.Expression != "" {
			parts = append(parts, l.Expression)
		} else if l.License != nil {
			if l.License.ID != "" {
				parts = append(parts, l.License.ID)
			} else if l.License.Name != "" {
				parts = append(parts, l.License.Name)
			}
		}
	}

	if len(parts) == 0 {
		return "NOASSERTION"
	}
	return strings.Join(parts, " AND ")
}

