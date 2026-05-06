// Package protobomparser provides an SBOM parser backed by protobom.
// This enables parsing of all formats supported by protobom (SPDX 2.3, CycloneDX 1.0–1.7)
// through a unified interface. It can be used as an alternative to the lightweight
// built-in parsers when broader format coverage or future protobom features are desired.
package protobomparser

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"

	"github.com/seebom-labs/seebom/backend/pkg/models"
)

// ParseResult contains the extracted data from an SBOM document parsed via protobom.
type ParseResult struct {
	SBOM     models.SBOM
	Packages models.SBOMPackages
}

// Parse reads an SBOM document (any format supported by protobom) from raw bytes
// and converts it to SeeBOM's internal model. Supported formats:
//   - SPDX 2.3 JSON
//   - CycloneDX 1.0–1.7 JSON
func Parse(data []byte, sourceFile, sha256Hash string) (*ParseResult, error) {
	r := reader.New()

	rs := bytes.NewReader(data)
	doc, err := r.ParseStreamWithOptions(rs, r.Options)
	if err != nil {
		return nil, fmt.Errorf("protobom: failed to parse %s: %w", sourceFile, err)
	}

	return convertDocument(doc, sourceFile, sha256Hash)
}

// ParseReader reads from an io.Reader and parses via protobom.
func ParseReader(input io.Reader, sourceFile, sha256Hash string) (*ParseResult, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("protobom: failed to read input: %w", err)
	}
	return Parse(data, sourceFile, sha256Hash)
}

// convertDocument maps a protobom Document to SeeBOM's internal models.
func convertDocument(doc *sbom.Document, sourceFile, sha256Hash string) (*ParseResult, error) {
	if doc == nil || doc.NodeList == nil {
		return nil, fmt.Errorf("protobom: empty document")
	}

	sbomID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(sha256Hash))
	now := time.Now()

	// Extract metadata.
	docName := ""
	docVersion := ""
	var creationDate time.Time
	var tools []string

	if doc.Metadata != nil {
		docName = doc.Metadata.GetName()
		docVersion = doc.Metadata.GetVersion()

		if doc.Metadata.GetDate() != nil {
			creationDate = doc.Metadata.GetDate().AsTime()
		}

		for _, t := range doc.Metadata.GetTools() {
			toolStr := t.GetName()
			if t.GetVendor() != "" {
				toolStr = t.GetVendor() + " " + toolStr
			}
			if t.GetVersion() != "" {
				toolStr += " " + t.GetVersion()
			}
			tools = append(tools, "Tool: "+toolStr)
		}
	}

	if creationDate.IsZero() {
		creationDate = now
	}

	// Determine format string for SPDXVersion field.
	formatStr := detectFormat(doc)

	sbomModel := models.SBOM{
		IngestedAt:        now,
		SBOMID:            sbomID,
		SourceFile:        sourceFile,
		SPDXVersion:       formatStr,
		DocumentName:      docName,
		DocumentNamespace: docVersion,
		SHA256Hash:        sha256Hash,
		CreationDate:      creationDate,
		CreatorTools:      tools,
	}

	// Build parallel arrays from nodes.
	nodeIDToIndex := make(map[string]uint32, len(doc.NodeList.GetNodes()))

	var (
		spdxIDs  []string
		names    []string
		versions []string
		purls    []string
		licenses []string
	)

	for i, node := range doc.NodeList.GetNodes() {
		idx := uint32(i)
		nodeIDToIndex[node.GetId()] = idx

		spdxIDs = append(spdxIDs, node.GetId())
		names = append(names, node.GetName())
		versions = append(versions, node.GetVersion())

		// Extract PURL from identifiers map.
		purl := ""
		identifiers := node.GetIdentifiers()
		if identifiers != nil {
			// SoftwareIdentifierType_PURL = 1
			if p, ok := identifiers[int32(sbom.SoftwareIdentifierType_PURL)]; ok {
				purl = p
			}
		}
		purls = append(purls, purl)

		// Extract license: prefer declared licenses, fall back to concluded.
		lic := extractNodeLicense(node)
		licenses = append(licenses, lic)
	}

	// Build relationship arrays from edges.
	var (
		relSources []uint32
		relTargets []uint32
		relTypes   []string
	)

	for _, edge := range doc.NodeList.GetEdges() {
		srcIdx, srcOK := nodeIDToIndex[edge.GetFrom()]
		if !srcOK {
			continue
		}
		edgeType := edge.GetType().String()
		for _, target := range edge.GetTo() {
			tgtIdx, tgtOK := nodeIDToIndex[target]
			if tgtOK {
				relSources = append(relSources, srcIdx)
				relTargets = append(relTargets, tgtIdx)
				relTypes = append(relTypes, edgeType)
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
		SBOM:     sbomModel,
		Packages: packages,
	}, nil
}

// extractNodeLicense extracts the best license string from a protobom Node.
func extractNodeLicense(node *sbom.Node) string {
	// Protobom stores declared licenses in the Licenses field.
	lics := node.GetLicenses()
	if len(lics) > 0 {
		return strings.Join(lics, " AND ")
	}

	// Fall back to concluded license.
	concluded := node.GetLicenseConcluded()
	if concluded != "" && concluded != "NOASSERTION" && concluded != "NONE" {
		return concluded
	}

	return "NOASSERTION"
}

// detectFormat tries to determine the original format from protobom metadata.
func detectFormat(doc *sbom.Document) string {
	if doc.Metadata != nil && doc.Metadata.GetSourceData() != nil {
		format := doc.Metadata.GetSourceData().GetFormat()
		if format != "" {
			// protobom formats look like "text/spdx+json;version=2.3" or "application/vnd.cyclonedx+json;version=1.5"
			if strings.Contains(format, "cyclonedx") {
				// Extract version.
				if idx := strings.Index(format, "version="); idx >= 0 {
					ver := format[idx+8:]
					return "CycloneDX-" + ver
				}
				return "CycloneDX"
			}
			if strings.Contains(format, "spdx") {
				if idx := strings.Index(format, "version="); idx >= 0 {
					ver := format[idx+8:]
					return "SPDX-" + ver
				}
				return "SPDX"
			}
		}
	}

	// Fallback: check if any node has SPDX-style IDs.
	for _, node := range doc.NodeList.GetNodes() {
		if strings.HasPrefix(node.GetId(), "SPDXRef-") {
			return "SPDX-2.3"
		}
	}

	return "Unknown"
}

