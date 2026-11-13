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

	"github.com/seebom-labs/bomhort/backend/internal/imageid"
	"github.com/seebom-labs/bomhort/backend/internal/sbomname"
	"github.com/seebom-labs/bomhort/backend/internal/sourcerepo"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
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
	Timestamp string        `json:"timestamp"`
	Tools     []CDXTool     `json:"tools"`
	Component *CDXComponent `json:"component"`
	// Manufacturer (1.6) / Manufacture (1.5, deprecated spelling) and
	// Supplier name who makes and who ships the product; used as a parent
	// grouping signal for vendor SBOMs (internal/projectgroup).
	Manufacturer *CDXOrganization `json:"manufacturer"`
	Manufacture  *CDXOrganization `json:"manufacture"`
	Supplier     *CDXOrganization `json:"supplier"`
}

// CDXOrganization is an organizational entity (manufacturer, supplier).
type CDXOrganization struct {
	Name string `json:"name"`
}

// UnmarshalJSON accepts the spec's object ({"name": …}) and, leniently, a bare
// string. Any other shape yields no name instead of an error: these fields
// were added only as grouping signals, and a document that parsed before
// must not start failing because a generator put something odd here.
func (o *CDXOrganization) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		o.Name = s
		return nil
	}
	var obj struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(b, &obj); err == nil {
		o.Name = obj.Name
	}
	return nil
}

// CDXTool represents a tool entry in metadata.
type CDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CDXComponent represents a single component in the BOM.
type CDXComponent struct {
	Type               string                 `json:"type"`
	BomRef             string                 `json:"bom-ref"`
	Name               string                 `json:"name"`
	Version            string                 `json:"version"`
	PURL               string                 `json:"purl"`
	Licenses           []CDXLicense           `json:"licenses"`
	ExternalReferences []CDXExternalReference `json:"externalReferences"`
	Pedigree           *CDXPedigree           `json:"pedigree"`
	Supplier           *CDXOrganization       `json:"supplier"`
	Manufacturer       *CDXOrganization       `json:"manufacturer"`
}

// CDXExternalReference is a typed link attached to a component; type "vcs"
// names the source repository (#332).
type CDXExternalReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// CDXPedigree captures component ancestry; commits[0].uid is the commit the
// component was built from (#332).
type CDXPedigree struct {
	Commits []CDXCommit `json:"commits"`
}

// CDXCommit is a single commit reference inside a pedigree.
type CDXCommit struct {
	UID string `json:"uid"`
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

	// Keep meaningful component names; resolve unusable ones before a version
	// suffix can disguise a temporary/empty name as a meaningful document name.
	docName := ""
	if doc.Metadata.Component != nil {
		docName = doc.Metadata.Component.Name
		if !sbomname.NeedsFallback(docName) && doc.Metadata.Component.Version != "" {
			docName += " " + doc.Metadata.Component.Version
		}
	}
	docName, err = sbomname.Resolve(data, docName, sourceFile)
	if err != nil {
		return nil, err
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
	sbom.SourceRepo, sbom.SourceRef = extractSourceRepo(&doc)
	sbom.RootPURL, sbom.Supplier = extractGroupingSignals(&doc)
	sbom.ImageRef, sbom.ImageDigest = imageid.FromPURL(sbom.RootPURL)
	// The version of the product the BOM describes; document_name may carry it
	// as a display suffix (above), document_version is the raw attribute.
	if doc.Metadata.Component != nil {
		sbom.DocumentVersion = doc.Metadata.Component.Version
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

	// The product itself lives in metadata.component, outside the component
	// array, so its dependsOn entry has no source index. Its targets are the
	// direct dependencies; remember them as depth-1 seeds for the depth walk.
	rootRef := ""
	if doc.Metadata.Component != nil {
		rootRef = doc.Metadata.Component.BomRef
	}
	var directIndices []uint32

	for _, dep := range doc.Dependencies {
		if rootRef != "" && dep.Ref == rootRef {
			if _, inArray := bomRefToIndex[rootRef]; !inArray {
				for _, target := range dep.DependsOn {
					if tgtIdx, ok := bomRefToIndex[target]; ok {
						directIndices = append(directIndices, tgtIdx)
					}
				}
				continue
			}
		}
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
		DirectIndices:    directIndices,
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

// extractSourceRepo derives (source_repo, source_ref) for #332 from the BOM's
// metadata.component — the product the BOM is about. Component-level entries
// in the components list are dependencies; their vcs references name *their*
// repos and must not be attributed to the product.
//
//  1. metadata.component.externalReferences[type=vcs].url — the CycloneDX
//     way to say "the source lives here".
//  2. pedigree.commits[0].uid as the ref if the vcs URL carried none:
//     generators that fill pedigree list the build commit first.
//  3. (#355) metadata.component.externalReferences[type=distribution] when
//     it is *evidently* a forge URL (release download, tag, .git). The CDX
//     counterpart of the SPDX documentNamespace fallback; serialNumber itself
//     is a urn:uuid by spec and never names a repository. Held to
//     NormalizeStrict so registry tarballs and CDN links are not mistaken
//     for repos.
func extractSourceRepo(doc *CDXDocument) (repo, ref string) {
	root := doc.Metadata.Component
	if root == nil {
		return "", ""
	}

	for _, er := range root.ExternalReferences {
		if er.Type != "vcs" {
			continue
		}
		if r, rf := sourcerepo.Normalize(er.URL); r != "" {
			repo, ref = r, rf
			break
		}
	}

	if repo == "" {
		for _, er := range root.ExternalReferences {
			if er.Type != "distribution" && er.Type != "distribution-intake" {
				continue
			}
			if r, rf := sourcerepo.NormalizeStrict(er.URL); r != "" {
				repo, ref = r, rf
				break
			}
		}
	}

	if repo == "" {
		return "", ""
	}

	if ref == "" && root.Pedigree != nil && len(root.Pedigree.Commits) > 0 {
		ref = strings.TrimSpace(root.Pedigree.Commits[0].UID)
	}

	return repo, ref
}

// extractGroupingSignals returns the package URL of the component the BOM
// describes and who makes or ships it. Both feed the parent grouping of
// projects (internal/projectgroup) for products that have no repository URL.
//
// Supplier precedence: the manufacturer (who makes it) over the supplier (who
// ships it), document-level metadata over the component's own fields. The
// 1.5 spelling "manufacture" is accepted next to 1.6's "manufacturer".
func extractGroupingSignals(doc *CDXDocument) (rootPURL, supplier string) {
	root := doc.Metadata.Component
	if root != nil {
		rootPURL = strings.TrimSpace(root.PURL)
	}
	candidates := []*CDXOrganization{doc.Metadata.Manufacturer, doc.Metadata.Manufacture}
	if root != nil {
		candidates = append(candidates, root.Manufacturer)
	}
	candidates = append(candidates, doc.Metadata.Supplier)
	if root != nil {
		candidates = append(candidates, root.Supplier)
	}
	for _, c := range candidates {
		if c != nil && strings.TrimSpace(c.Name) != "" {
			return rootPURL, strings.TrimSpace(c.Name)
		}
	}
	return rootPURL, ""
}
