// Package protobomparser provides an SBOM parser backed by protobom.
// This enables parsing of all formats supported by protobom (SPDX 2.2/2.3, SPDX 3.0.1,
// CycloneDX 1.4–1.7)
// through a unified interface. It can be used as an alternative to the lightweight
// built-in parsers when broader format coverage or future protobom features are desired.
package protobomparser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"

	"github.com/seebom-labs/bomhort/backend/internal/imageid"
	"github.com/seebom-labs/bomhort/backend/internal/sbomname"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// ParseResult contains the extracted data from an SBOM document parsed via protobom.
type ParseResult struct {
	SBOM     models.SBOM
	Packages models.SBOMPackages
}

// Parse reads an SBOM document (any format supported by protobom) from raw bytes
// and converts it to BOMHort's internal model. Supported formats:
//   - SPDX 2.2 / 2.3 JSON
//   - SPDX 3.0.1 JSON-LD
//   - CycloneDX 1.4–1.7 JSON
func Parse(data []byte, sourceFile, sha256Hash string) (*ParseResult, error) {
	r := reader.New()

	rs := bytes.NewReader(data)
	doc, err := r.ParseStreamWithOptions(rs, r.Options)
	if err != nil {
		return nil, fmt.Errorf("protobom: failed to parse %s: %w", sourceFile, err)
	}

	result, err := convertDocument(doc, sourceFile, sha256Hash)
	if err != nil {
		return nil, err
	}
	if result.SBOM.ImageDigest == "" {
		if purl := spdx3RootContentIdentifier(data); purl != "" {
			result.SBOM.RootPURL = purl
			result.SBOM.ImageRef, result.SBOM.ImageDigest = imageid.FromPURL(purl)
		}
	}
	name, err := sbomname.Resolve(data, result.SBOM.DocumentName, sourceFile)
	if err != nil {
		return nil, err
	}
	result.SBOM.DocumentName = name
	return result, nil
}

func spdx3RootContentIdentifier(data []byte) string {
	var graph struct {
		Graph []map[string]json.RawMessage `json:"@graph"`
	}
	if json.Unmarshal(data, &graph) != nil {
		return ""
	}
	nodes := make(map[string]map[string]json.RawMessage, len(graph.Graph))
	var roots []string
	for _, node := range graph.Graph {
		var id, spdxID, typ string
		_ = json.Unmarshal(node["@id"], &id)
		_ = json.Unmarshal(node["spdxId"], &spdxID)
		_ = json.Unmarshal(node["type"], &typ)
		if id != "" {
			nodes[id] = node
		}
		if spdxID != "" {
			nodes[spdxID] = node
		}
		if strings.Contains(typ, "SpdxDocument") {
			_ = json.Unmarshal(node["rootElement"], &roots)
			if len(roots) == 0 {
				var root string
				_ = json.Unmarshal(node["rootElement"], &root)
				if root != "" {
					roots = []string{root}
				}
			}
		}
	}
	visited := make(map[string]bool)
	for len(roots) > 0 {
		root := roots[0]
		roots = roots[1:]
		if visited[root] {
			continue
		}
		visited[root] = true
		node := nodes[root]
		if purl := findOCIPURL(node["contentIdentifier"]); purl != "" {
			return purl
		}
		var children []string
		if json.Unmarshal(node["rootElement"], &children) == nil {
			roots = append(roots, children...)
		} else {
			var child string
			if json.Unmarshal(node["rootElement"], &child) == nil && child != "" {
				roots = append(roots, child)
			}
		}
	}
	return ""
}

func findOCIPURL(raw json.RawMessage) string {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		if strings.HasPrefix(v, "pkg:oci/") {
			return v
		}
	case []any:
		for _, item := range v {
			if b, err := json.Marshal(item); err == nil {
				if purl := findOCIPURL(b); purl != "" {
					return purl
				}
			}
		}
	case map[string]any:
		for _, item := range v {
			if b, err := json.Marshal(item); err == nil {
				if purl := findOCIPURL(b); purl != "" {
					return purl
				}
			}
		}
	}
	return ""
}

// ParseReader reads from an io.Reader and parses via protobom.
func ParseReader(input io.Reader, sourceFile, sha256Hash string) (*ParseResult, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("protobom: failed to read input: %w", err)
	}
	return Parse(data, sourceFile, sha256Hash)
}

// convertDocument maps a protobom Document to BOMHort's internal models.
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

	// The described product(s): protobom lists them as root elements.
	var rootIndices []uint32
	for _, rootID := range doc.NodeList.GetRootElements() {
		if idx, ok := nodeIDToIndex[rootID]; ok {
			rootIndices = append(rootIndices, idx)
		}
	}

	setRootImageIdentity(&sbomModel, purls, rootIndices)

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
		RootIndices:      rootIndices,
	}

	return &ParseResult{
		SBOM:     sbomModel,
		Packages: packages,
	}, nil
}

func setRootImageIdentity(sbomModel *models.SBOM, purls []string, rootIndices []uint32) {
	for _, rootIndex := range rootIndices {
		if int(rootIndex) >= len(purls) {
			continue
		}
		if sbomModel.RootPURL == "" {
			sbomModel.RootPURL = purls[rootIndex]
		}
		if ref, digest := imageid.FromPURL(purls[rootIndex]); digest != "" {
			sbomModel.ImageRef, sbomModel.ImageDigest = ref, digest
			break
		}
	}
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
