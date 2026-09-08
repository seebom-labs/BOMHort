// Package sbomname resolves unusable SBOM document names without changing source
// documents, package identities, or meaningful existing names.
package sbomname

import (
	"bytes"
	"fmt"
	"log"
	"net/url"
	"path"
	"regexp"
	"strings"

	json "github.com/goccy/go-json"
)

var tempName = regexp.MustCompile(`^tmp(?:\.[a-zA-Z0-9]{6,})?$`)

// NeedsFallback recognizes empty names and conservative temporary-directory
// patterns, including absolute Unix/Windows paths ending in tmp.XXXXXX.
// It deliberately leaves ordinary names such as tmp-utils and org/tmp.tool alone.
func NeedsFallback(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return true
	}
	normalized := strings.ReplaceAll(name, `\`, "/")
	if strings.HasPrefix(normalized, "/") || (len(normalized) > 2 && normalized[1:3] == ":/") {
		name = path.Base(normalized)
	}
	return tempName.MatchString(name)
}

type component struct {
	ID      string `json:"SPDXID"`
	Name    string `json:"name"`
	Version string `json:"versionInfo"`
}

// Read raw root metadata rather than relying on a parser library's inferred
// graph roots. This keeps both backends consistent for missing/multiple roots.
type document struct {
	ID                string      `json:"SPDXID"`
	Name              string      `json:"name"`
	SPDXVersion       string      `json:"spdxVersion"`
	DocumentDescribes []string    `json:"documentDescribes"`
	Packages          []component `json:"packages"`
	Relationships     []struct {
		From string `json:"spdxElementId"`
		Type string `json:"relationshipType"`
		To   string `json:"relatedSpdxElement"`
	} `json:"relationships"`
	BomFormat    string `json:"bomFormat"`
	SerialNumber string `json:"serialNumber"`
	Metadata     struct {
		Component *struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"component"`
	} `json:"metadata"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// Resolve returns an existing usable name verbatim. Only unusable names trigger
// an additional metadata pass: a unique described root + version, then a source
// label, and finally "Unnamed SBOM". CycloneDX's serial-number fallback is retained.
// Original names remain in the source document and are logged with the resolution;
// no schema change or mutation of the input bytes is required.
func Resolve(data []byte, original, source string) (string, error) {
	if !NeedsFallback(original) {
		return original, nil
	}
	var doc document
	// Protobom also accepts XML. Its parser has already validated the input;
	// JSON-specific root extraction must not reject otherwise supported formats.
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("<")) {
		if err := json.Unmarshal(data, &doc); err != nil {
			return "", fmt.Errorf("decode SBOM naming metadata: %w", err)
		}
	}
	if doc.SPDXVersion == "" && strings.Contains(doc.PredicateType, "spdx") && len(doc.Predicate) > 0 {
		var inner document
		if err := json.Unmarshal(doc.Predicate, &inner); err != nil {
			return "", fmt.Errorf("decode in-toto naming metadata: %w", err)
		}
		doc = inner
	}

	name, reason := "", ""
	switch {
	case doc.SPDXVersion != "":
		if !NeedsFallback(doc.Name) {
			name, reason = doc.Name, "document"
		} else if root := describedRoot(doc); root != nil && !NeedsFallback(root.Name) {
			name, reason = withVersion(root.Name, root.Version), "described-root"
		}
	case doc.BomFormat == "CycloneDX":
		if root := doc.Metadata.Component; root != nil && !NeedsFallback(root.Name) {
			name, reason = withVersion(root.Name, root.Version), "metadata-component"
		} else if !NeedsFallback(doc.SerialNumber) {
			name, reason = doc.SerialNumber, "serial-number"
		}
	}
	if name == "" {
		name, reason = sourceName(source), "source"
	}
	if name == "" {
		name, reason = "Unnamed SBOM", "unnamed"
	}
	// Quote untrusted metadata and bound its length to avoid multiline/oversized logs.
	log.Printf("SBOM document name fallback: source=%q original=%q resolved=%q reason=%s",
		abbreviate(sourceName(source)), abbreviate(original), abbreviate(name), reason)
	return name, nil
}

func describedRoot(doc document) *component {
	ids := make(map[string]bool)
	for _, id := range doc.DocumentDescribes {
		ids[id] = true
	}
	docID := doc.ID
	if docID == "" {
		docID = "SPDXRef-DOCUMENT"
	}
	for _, rel := range doc.Relationships {
		switch {
		case rel.Type == "DESCRIBES" && rel.From == docID:
			ids[rel.To] = true
		case rel.Type == "DESCRIBED_BY" && rel.To == docID:
			ids[rel.From] = true
		}
	}
	// Do not guess from package order, dependency roots, or only the subset of
	// references that happened to resolve. Dangling/multiple references are ambiguous.
	if len(ids) != 1 || ids[""] {
		return nil
	}
	var root *component
	for i := range doc.Packages {
		if ids[doc.Packages[i].ID] {
			if root != nil { // Duplicate package IDs are also ambiguous.
				return nil
			}
			root = &doc.Packages[i]
		}
	}
	return root
}

func withVersion(name, version string) string {
	name, version = strings.TrimSpace(name), strings.TrimSpace(version)
	switch strings.ToUpper(version) {
	case "", "NOASSERTION", "NONE", "UNKNOWN":
		return name
	default:
		return name + " " + version
	}
}

func sourceName(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}
	var label string
	if strings.Contains(source, "://") {
		u, err := url.Parse(source)
		if err != nil {
			return ""
		}
		// Keep the full S3 object key (project/version context), but never URL
		// credentials, query parameters, or fragments. Other URLs use the basename.
		if u.Scheme == "s3" {
			label = strings.TrimLeft(u.Path, "/")
		} else {
			label = path.Base(u.Path)
		}
	} else {
		label = path.Base(strings.ReplaceAll(source, `\`, "/"))
	}
	for _, suffix := range []string{".spdx.json", "_spdx.json", ".cdx.json", ".json"} {
		if strings.HasSuffix(strings.ToLower(label), suffix) {
			label = label[:len(label)-len(suffix)]
			break
		}
	}
	if label == "." || label == "/" || NeedsFallback(label) {
		return ""
	}
	return label
}

func abbreviate(value string) string {
	if len(value) > 256 {
		return value[:256] + "..."
	}
	return value
}
