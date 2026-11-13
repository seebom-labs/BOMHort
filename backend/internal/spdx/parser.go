package spdx

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/imageid"
	"github.com/seebom-labs/bomhort/backend/internal/sbomname"
	"github.com/seebom-labs/bomhort/backend/internal/sourcerepo"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// goTempModuleRe matches Go temporary module directory names like "tmp.ej9m9OiO2V".
// These appear in SPDX data when Go SBOM tools capture the temp build directory as a package name.
var goTempModuleRe = regexp.MustCompile(`^tmp\.[a-zA-Z0-9]{6,}$`)

// fileArtifactNameRe matches names that look like plain source/build files rather than
// software packages (shell scripts, manifests, lock files). Used only as a fallback
// heuristic together with "no PURL, no version, no relationships" – see isFileArtifact.
var fileArtifactNameRe = regexp.MustCompile(
	`(?i)\.(sh|bash|zsh|bat|ps1|toml|txt|json|ya?ml|lock|mod|sum|xml|cfg|ini|md)$`)

// defaultDocumentSPDXID is the conventional SPDX identifier of the document itself.
const defaultDocumentSPDXID = "SPDXRef-DOCUMENT"

// SPDXDocument represents the top-level structure of an SPDX 2.3 JSON document.
// We only extract the fields we need for ingestion.
type SPDXDocument struct {
	SPDXID            string             `json:"SPDXID"`
	SPDXVersion       string             `json:"spdxVersion"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	DocumentDescribes []string           `json:"documentDescribes"`
	CreationInfo      SPDXCreationInfo   `json:"creationInfo"`
	Packages          []SPDXPackage      `json:"packages"`
	Relationships     []SPDXRelationship `json:"relationships"`
}

// SPDXCreationInfo holds creation metadata.
type SPDXCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// SPDXPackage represents a single package entry in SPDX.
type SPDXPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	DownloadLocation string            `json:"downloadLocation"`
	SourceInfo       string            `json:"sourceInfo"`
	ExternalRefs     []SPDXExternalRef `json:"externalRefs"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	Annotations      []SPDXAnnotation  `json:"annotations"`
	// Supplier/Originator ("Organization: ACME Corp", "Person: …",
	// NOASSERTION) name who ships/created the package. Read from the root
	// package only, as a parent grouping signal (internal/projectgroup).
	Supplier   spdxActor `json:"supplier"`
	Originator spdxActor `json:"originator"`
}

// spdxActor is an SPDX actor string. It tolerates any other JSON shape by
// yielding "" instead of failing the document: the field is read only as a
// grouping signal, and a document that parsed before must keep parsing.
type spdxActor string

// UnmarshalJSON implements json.Unmarshaler.
func (a *spdxActor) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*a = spdxActor(s)
	}
	return nil
}

// SPDXAnnotation holds a package-level annotation. Some generators (e.g. waybill)
// encode structured metadata as JSON inside the comment field.
type SPDXAnnotation struct {
	Annotator      string `json:"annotator"`
	AnnotationType string `json:"annotationType"`
	Comment        string `json:"comment"`
}

// SPDXExternalRef holds external reference data (e.g., purl).
type SPDXExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// SPDXRelationship represents a relationship between two SPDX elements.
type SPDXRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// ParseResult contains the extracted data from an SPDX document, ready for ClickHouse insertion.
type ParseResult struct {
	SBOM     models.SBOM
	Packages models.SBOMPackages
}

// ParseFile opens and parses an SPDX JSON file using high-performance streaming.
func ParseFile(path, sourceFile, sha256Hash string) (*ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open SPDX file %s: %w", path, err)
	}
	defer f.Close()

	return Parse(f, sourceFile, sha256Hash)
}

// cleanPackageName replaces Go temporary build directory names (e.g. "tmp.ej9m9OiO2V")
// with a meaningful name derived from the PURL or SPDX ID.
// These temp names are artifacts of Go CI/CD builds captured by SBOM generators.
func cleanPackageName(name, purl, spdxID string) string {
	if !goTempModuleRe.MatchString(name) {
		return name
	}

	// Try to derive a useful name from the PURL (e.g. "pkg:golang/github.com/foo/bar@v1.0" → "github.com/foo/bar").
	if purl != "" {
		// Strip "pkg:<type>/" prefix.
		if idx := strings.Index(purl, "/"); idx >= 0 {
			cleaned := purl[idx+1:]
			// Strip version suffix (@...).
			if atIdx := strings.LastIndex(cleaned, "@"); atIdx >= 0 {
				cleaned = cleaned[:atIdx]
			}
			if cleaned != "" {
				return cleaned
			}
		}
	}

	// Fall back to SPDX ID (e.g. "SPDXRef-Package-foo" → "foo").
	if strings.HasPrefix(spdxID, "SPDXRef-Package-") {
		return strings.TrimPrefix(spdxID, "SPDXRef-Package-")
	}
	if strings.HasPrefix(spdxID, "SPDXRef-") {
		return strings.TrimPrefix(spdxID, "SPDXRef-")
	}

	return name
}

// purlOf returns the first purl external reference of a package, or "".
func purlOf(pkg SPDXPackage) string {
	for _, ref := range pkg.ExternalRefs {
		if ref.ReferenceType == "purl" {
			return ref.ReferenceLocator
		}
	}
	return ""
}

// waybillAnnotation is the JSON payload waybill stores in annotation comments:
// {"schema":"waybill-annotation/v1","field":"waybill:component-tier","value":"file"}
type waybillAnnotation struct {
	Field string          `json:"field"`
	Value json.RawMessage `json:"value"`
}

// isFileArtifact reports whether an SPDX package entry actually describes a single
// source/build file (e.g. "test.sh", "Cargo.toml") rather than a software component.
// Generators such as waybill emit every file with a matching hash as its own package,
// which pollutes the package list and the NOASSERTION license bucket.
//
// Detection is explicit first (waybill "component-tier" == "file" annotation) and
// falls back to a conservative heuristic: no PURL, no version, not referenced by any
// relationship, and a name that looks like a file.
func isFileArtifact(pkg SPDXPackage, purl string, referenced bool) bool {
	for _, a := range pkg.Annotations {
		if !strings.Contains(a.Comment, "waybill:component-tier") {
			continue
		}
		var wa waybillAnnotation
		if err := json.Unmarshal([]byte(a.Comment), &wa); err != nil {
			continue
		}
		if wa.Field == "waybill:component-tier" && strings.Trim(string(wa.Value), `"`) == "file" {
			return true
		}
	}
	if purl != "" || referenced {
		return false
	}
	if v := pkg.VersionInfo; v != "" && v != "NOASSERTION" {
		return false
	}
	name := strings.TrimSpace(pkg.Name)
	return name != "" && !strings.ContainsAny(name, " \t") && fileArtifactNameRe.MatchString(name)
}

// describedRoots returns the set of SPDX IDs the document DESCRIBES – i.e. the
// product(s) the SBOM is about, as opposed to their dependencies.
func describedRoots(doc *SPDXDocument) map[string]bool {
	roots := make(map[string]bool)
	for _, id := range doc.DocumentDescribes {
		if id != "" {
			roots[id] = true
		}
	}
	docID := doc.SPDXID
	if docID == "" {
		docID = defaultDocumentSPDXID
	}
	for _, rel := range doc.Relationships {
		if rel.RelationshipType != "DESCRIBES" {
			continue
		}
		if rel.SPDXElementID == docID || rel.SPDXElementID == defaultDocumentSPDXID {
			roots[rel.RelatedSPDXElement] = true
		}
	}
	return roots
}

// extractDocumentVersion returns the version of the product the document
// DESCRIBES: the first described root package (document order) with a usable
// versionInfo. Dependencies are never consulted — their versions belong to
// them, not to the product. "" when no root states a version.
func extractDocumentVersion(doc *SPDXDocument) string {
	roots := describedRoots(doc)
	if len(roots) == 0 {
		return ""
	}
	for i := range doc.Packages {
		pkg := &doc.Packages[i]
		if !roots[pkg.SPDXID] {
			continue
		}
		if v := pkg.VersionInfo; v != "" && v != "NOASSERTION" {
			return v
		}
	}
	return ""
}

// inTotoStatement represents an in-toto attestation envelope.
// Some SBOM generators (e.g. buildkit, Anchore/Syft) wrap SPDX documents inside
// this format. The actual SPDX content lives under the "predicate" key.
type inTotoStatement struct {
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// Parse reads an SPDX JSON document from a reader and extracts models.
// Supports both plain SPDX JSON and in-toto attestation envelopes where the
// SPDX document is wrapped inside the "predicate" field.
//
// Parse is hardened against malformed input: the underlying goccy/go-json
// decoder can panic on adversarial byte sequences (out-of-range slice access
// inside its struct decoder). We recover from any panic and surface it as a
// regular error so callers — including the FuzzParse harness — observe
// deterministic, non-fatal failures.
func Parse(r io.Reader, sourceFile, sha256Hash string) (result *ParseResult, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			result = nil
			err = fmt.Errorf("panic while parsing SPDX JSON: %v", rec)
		}
	}()

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read SPDX data: %w", err)
	}

	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to decode SPDX JSON: %w", err)
	}

	// If spdxVersion is empty, the file may be an in-toto attestation envelope.
	// Try to unwrap the SPDX document from the "predicate" field.
	if doc.SPDXVersion == "" {
		var stmt inTotoStatement
		if err := json.Unmarshal(data, &stmt); err == nil &&
			len(stmt.Predicate) > 0 &&
			strings.Contains(stmt.PredicateType, "spdx") {
			if err := json.Unmarshal(stmt.Predicate, &doc); err != nil {
				return nil, fmt.Errorf("failed to decode SPDX from in-toto predicate: %w", err)
			}
		}
	}

	sbomID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(sha256Hash))
	now := time.Now()

	// Parse creation date.
	creationDate, err := time.Parse(time.RFC3339, doc.CreationInfo.Created)
	if err != nil {
		// Fall back to current time if creation date is malformed.
		creationDate = now
	}

	// Extract tools from creators (filter "Tool:" prefix).
	var tools []string
	for _, c := range doc.CreationInfo.Creators {
		tools = append(tools, c)
	}

	docName, err := sbomname.Resolve(data, doc.Name, sourceFile)
	if err != nil {
		return nil, err
	}

	sbom := models.SBOM{
		IngestedAt:        now,
		SBOMID:            sbomID,
		SourceFile:        sourceFile,
		SPDXVersion:       doc.SPDXVersion,
		DocumentName:      docName,
		DocumentNamespace: doc.DocumentNamespace,
		SHA256Hash:        sha256Hash,
		CreationDate:      creationDate,
		CreatorTools:      tools,
	}
	sbom.SourceRepo, sbom.SourceRef = extractSourceRepo(&doc)
	sbom.RootPURL, sbom.Supplier = extractGroupingSignals(&doc)
	sbom.ImageRef, sbom.ImageDigest = imageid.FromPURL(sbom.RootPURL)
	sbom.DocumentVersion = extractDocumentVersion(&doc)

	// SPDX IDs that participate in at least one relationship. Used by the
	// file-artifact heuristic: real components are usually wired into the
	// dependency graph, stray file entries are not.
	referenced := make(map[string]bool, len(doc.Relationships)*2)
	for _, rel := range doc.Relationships {
		referenced[rel.SPDXElementID] = true
		referenced[rel.RelatedSPDXElement] = true
	}
	roots := describedRoots(&doc)
	// Build parallel arrays from packages. Indices are assigned after filtering,
	// so relationship indices below always point at retained packages.
	spdxIDToIndex := make(map[string]uint32, len(doc.Packages))
	var (
		spdxIDs     []string
		names       []string
		versions    []string
		purls       []string
		licenses    []string
		rootIndices []uint32
	)
	for _, pkg := range doc.Packages {
		// Find PURL from external references (needed before name cleaning).
		purl := purlOf(pkg)
		// Drop entries that describe single files instead of components.
		// The described root is never dropped, even if it looks file-like.
		if !roots[pkg.SPDXID] && isFileArtifact(pkg, purl, referenced[pkg.SPDXID]) {
			continue
		}
		idx := uint32(len(spdxIDs))
		spdxIDToIndex[pkg.SPDXID] = idx
		if roots[pkg.SPDXID] {
			rootIndices = append(rootIndices, idx)
		}
		spdxIDs = append(spdxIDs, pkg.SPDXID)
		purls = append(purls, purl)
		// Clean up Go temp build directory names (e.g. "tmp.ej9m9OiO2V").
		name := cleanPackageName(pkg.Name, purl, pkg.SPDXID)
		names = append(names, name)
		versions = append(versions, pkg.VersionInfo)
		// Prefer declared license, fall back to concluded.
		lic := pkg.LicenseDeclared
		if lic == "" || lic == "NOASSERTION" {
			lic = pkg.LicenseConcluded
		}
		licenses = append(licenses, lic)
	}
	// Build relationship arrays.
	var (
		relSources []uint32
		relTargets []uint32
		relTypes   []string
	)

	for _, rel := range doc.Relationships {
		srcIdx, srcOK := spdxIDToIndex[rel.SPDXElementID]
		tgtIdx, tgtOK := spdxIDToIndex[rel.RelatedSPDXElement]
		if srcOK && tgtOK {
			relSources = append(relSources, srcIdx)
			relTargets = append(relTargets, tgtIdx)
			relTypes = append(relTypes, rel.RelationshipType)
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
		SBOM:     sbom,
		Packages: packages,
	}, nil
}

// extractSourceRepo derives (source_repo, source_ref) for #332 from the
// document's described root package(s). Only the roots are consulted: a
// dependency's downloadLocation names *that dependency's* repo, and storing it
// as the product's source would send triage tooling (VEXViper: clone, run
// govulncheck) to analyse the wrong codebase — worse than storing nothing.
//
// Priority within a root:
//  1. downloadLocation — the SPDX-native "where does this come from" field
//     (git+https://…@ref carries the ref inline).
//  2. an ExternalRef whose locator normalises to a repo URL, category
//     PACKAGE-MANAGER or OTHER (some generators stash vcs URLs there).
//
// Multiple roots (rare, e.g. multi-product documents): the first root that
// yields a repo wins — deterministic because packages are scanned in document
// order. Ambiguity is resolvable via the upload headers or PATCH.
//
// Next: the source the generator declares in creationInfo.creators. waybill,
// which produces the current CNCF corpus, writes the repository there rather
// than on the root package (whose downloadLocation is NOASSERTION) or in the
// namespace (https://waybill.kusari.dev/spdx/<id>):
//
//	Tool: waybill-0.2.0 source: git:https://github.com/argoproj/argo-cd.git#v3.4.7
//	Tool: waybill-0.2.0 source: repo:https://github.com/argoproj/argo-cd.git
//
// This is the tool stating what it scanned, so it outranks the namespace, but
// not a root's own locator, which is a statement about the product itself.
//
// Last resort (#355): documentNamespace. On the CNCF corpus surveyed then, 500
// of 500 SBOMs carried "https://github.com/org/repo/releases/tag/vX.Y.Z" there
// and *none* declared a root via DESCRIBES/documentDescribes, so without this
// branch the feature had 0 % coverage in practice. It stays last because a
// root's downloadLocation is a statement about the product while
// documentNamespace is only conventionally related to it;
// sourcerepo.NormalizeStrict accepts only URLs that are evidently a repository
// (forge host or forge path shape), so UUID-style namespaces (syft's
// https://anchore.com/syft/…, spdx.org/spdxdocs, urn:uuid:…, waybill's
// https://waybill.kusari.dev/spdx/…) yield "" and nothing is guessed from them.
// packages[0] is deliberately *not* treated as an implicit root — in the
// older documents it is a dependency.
//
// The document name ("argoproj/argo-cd v3.4.7") is deliberately not used: it
// names an owner and a repository but not the host, and a guessed host would
// send triage tooling to clone code that may not exist there.
func extractSourceRepo(doc *SPDXDocument) (repo, ref string) {
	if repo, ref = sourceRepoFromRoots(doc); repo != "" {
		return repo, ref
	}
	if repo, ref = sourceRepoFromCreators(doc.CreationInfo.Creators); repo != "" {
		return repo, ref
	}
	return sourcerepo.NormalizeStrict(doc.DocumentNamespace)
}

// sourceRepoFromCreators reads a "source: <kind>:<locator>" declaration from
// the creators list (see extractSourceRepo). The kind ("git", "repo", …) is
// dropped; the locator must still pass sourcerepo.NormalizeStrict, so a
// creator naming a directory, an image or an archive ("source: dir:/src",
// "source: image:ghcr.io/x/y") yields nothing.
//
// Several declarations may name the same repository with and without a ref;
// the first one that carries a ref wins, otherwise the first valid one.
func sourceRepoFromCreators(creators []string) (repo, ref string) {
	for _, c := range creators {
		locator, ok := creatorSourceLocator(c)
		if !ok {
			continue
		}
		r, rf := sourcerepo.NormalizeStrict(locator)
		if r == "" {
			continue
		}
		if rf != "" {
			return r, rf
		}
		if repo == "" {
			repo = r
		}
	}
	return repo, ""
}

// creatorSourceLocator extracts the locator from a creator entry of the form
// "Tool: <name> source: [<kind>:]<locator>". The kind prefix is recognised by
// what follows it: "git:https://…" has a kind, "https://…" and
// "git@github.com:x/y" (scp syntax) do not.
func creatorSourceLocator(creator string) (string, bool) {
	i := strings.Index(strings.ToLower(creator), "source:")
	if i < 0 {
		return "", false
	}
	rest := strings.TrimSpace(creator[i+len("source:"):])
	if rest == "" {
		return "", false
	}
	// Only the first whitespace-separated token is the locator.
	if sp := strings.IndexAny(rest, " \t"); sp > 0 {
		rest = rest[:sp]
	}
	if kind, loc, found := strings.Cut(rest, ":"); found && isCreatorSourceKind(kind) && strings.Contains(loc, "://") {
		rest = loc
	}
	return rest, true
}

// isCreatorSourceKind reports whether s looks like a "<kind>:" prefix (letters
// only), as opposed to a URL scheme followed by "//" or an scp user@host.
func isCreatorSourceKind(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

// sourceRepoFromRoots implements steps 1 and 2 of extractSourceRepo.
func sourceRepoFromRoots(doc *SPDXDocument) (repo, ref string) {
	roots := describedRoots(doc)
	if len(roots) == 0 {
		return "", ""
	}
	for i := range doc.Packages {
		pkg := &doc.Packages[i]
		if !roots[pkg.SPDXID] {
			continue
		}
		if r, rf := sourcerepo.Normalize(pkg.DownloadLocation); r != "" {
			return r, rf
		}
		for _, er := range pkg.ExternalRefs {
			switch er.ReferenceCategory {
			case "PACKAGE-MANAGER", "PACKAGE_MANAGER", "OTHER":
				// purls are handled by Normalize returning "" (a purl is a
				// package identity, not a clonable repo), so only genuine
				// vcs-style locators survive this.
				if r, rf := sourcerepo.Normalize(er.ReferenceLocator); r != "" {
					return r, rf
				}
			}
		}
	}
	return "", ""
}

// extractGroupingSignals returns the package URL and the supplier of the
// package the document DESCRIBES. Both feed the parent grouping of projects
// (internal/projectgroup) for products that have no repository URL. Only the
// described roots are consulted, for the same reason as extractSourceRepo:
// a dependency's purl or supplier says nothing about who ships the product.
//
// The first root (document order) with a purl provides it; the first root
// with a usable supplier, else originator, provides that.
func extractGroupingSignals(doc *SPDXDocument) (rootPURL, supplier string) {
	roots := describedRoots(doc)
	if len(roots) == 0 {
		return "", ""
	}
	for i := range doc.Packages {
		pkg := &doc.Packages[i]
		if !roots[pkg.SPDXID] {
			continue
		}
		if rootPURL == "" {
			rootPURL = purlOf(*pkg)
		}
		if supplier == "" {
			supplier = spdxActorName(string(pkg.Supplier))
		}
		if supplier == "" {
			supplier = spdxActorName(string(pkg.Originator))
		}
	}
	return rootPURL, supplier
}

// spdxActorName reduces an SPDX actor ("Organization: ACME Corp",
// "Person: Jane Doe (jane@example.com)", "NOASSERTION") to its name.
func spdxActorName(actor string) string {
	s := strings.TrimSpace(actor)
	switch strings.ToUpper(s) {
	case "", "NOASSERTION", "NONE":
		return ""
	}
	for _, prefix := range []string{"Organization:", "Person:", "Tool:"} {
		if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
			s = strings.TrimSpace(s[len(prefix):])
			break
		}
	}
	// Drop a trailing "(email)".
	if i := strings.LastIndex(s, " ("); i > 0 && strings.HasSuffix(s, ")") {
		s = strings.TrimSpace(s[:i])
	}
	return s
}
