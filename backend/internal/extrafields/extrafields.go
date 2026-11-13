// Package extrafields recognises operator-declared fields in uploaded SBOMs.
//
// BOMHort extracts a fixed set of document fields (source repository, document
// version, grouping signals). Anything else a producer writes into
// CycloneDX `properties` or `externalReferences` used to be dropped, even
// when it carried knowledge only the producer has, such as which team answers
// for a component. Instead of one parser change per field, a config file
// (EXTRA_FIELDS_FILE, default /data/config/extra-fields.json) declares which
// fields to recognise and where to read them from:
//
//	{
//	  "fields": [
//	    {
//	      "name": "owner_contact",
//	      "from": [
//	        {"cyclonedx": "metadata.component.properties", "property": "bomhort:owner:contact"},
//	        {"cyclonedx": "metadata.properties", "property": "bomhort:owner:contact"}
//	      ]
//	    }
//	  ]
//	}
//
// The sources are a fixed list of places, deliberately not a path language:
//
//   - metadata.component.properties          by property name
//   - metadata.properties                    by property name
//   - metadata.component.externalReferences  by reference type, value = url
//
// SPDX is out of scope: SPDX 2.3 has no name–value properties, so its mapping
// is a design of its own (follow-up).
//
// Extraction works on the raw document bytes, not on a parser's model, so it
// yields the same result with the built-in parsers and with USE_PROTOBOM.
//
// Values are untrusted producer input. Extract caps their length and count,
// strips control characters and drops invalid UTF-8; rendering them escaped
// and linking only http(s) URLs is the reader's job (UI).
package extrafields

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	json "github.com/goccy/go-json"
)

// Source locations a field can be read from. The set is closed on purpose:
// a general path language would turn every config file into a parser.
const (
	SourceComponentProperties = "metadata.component.properties"
	SourceMetadataProperties  = "metadata.properties"
	SourceComponentExtRefs    = "metadata.component.externalReferences"
)

// Limits. Generous for real metadata, low enough that a malformed or hostile
// document cannot balloon an sboms row.
const (
	// MaxFields caps how many fields a config may declare.
	MaxFields = 32
	// MaxSourcesPerField caps the from-list of one field.
	MaxSourcesPerField = 8
	// MaxValuesPerField caps how many values one field keeps per SBOM.
	MaxValuesPerField = 16
	// MaxValueLen caps a single value in bytes. Longer values are dropped,
	// not truncated: a cut-off URL or e-mail address would be a wrong value
	// that looks right.
	MaxValueLen = 1024
)

// namePattern is the shape of a field name: it is a map key in ClickHouse, a
// query parameter value and a UI label, so it stays a plain identifier.
var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// Config is the parsed extra-fields file. A nil *Config recognises nothing.
type Config struct {
	Version     string  `json:"version,omitempty"`
	Description string  `json:"description,omitempty"`
	Fields      []Field `json:"fields"`
}

// Field declares one recognised field and the places it is read from, in
// priority order: values from earlier sources come first.
type Field struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	From        []Source `json:"from"`
}

// Source is one place a field is read from. Property applies to the two
// properties sources, Type to externalReferences.
type Source struct {
	CycloneDX string `json:"cyclonedx"`
	Property  string `json:"property,omitempty"`
	Type      string `json:"type,omitempty"`
}

// Load reads and validates the config file at path. A missing file is not an
// error: the feature is opt-in and Load returns (nil, nil). A file that exists
// but is invalid is an error, so a typo in the operator's config fails loudly
// at startup instead of silently recognising nothing.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read extra-fields file %s: %w", path, err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("extra-fields file %s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes and validates an extra-fields document. Unknown keys are
// rejected, so {"spdx": …} or a misspelt "propery" is reported, not ignored.
// The document must be exactly one JSON value: Decode stops after the first,
// so a second value or trailing garbage is checked for explicitly.
func Parse(data []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid JSON: unexpected data after the top-level value")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks names, sources and limits.
func (c *Config) Validate() error {
	if len(c.Fields) > MaxFields {
		return fmt.Errorf("%d fields declared, at most %d allowed", len(c.Fields), MaxFields)
	}
	seen := make(map[string]bool, len(c.Fields))
	for i, f := range c.Fields {
		if !namePattern.MatchString(f.Name) {
			return fmt.Errorf("fields[%d]: name %q must match %s", i, f.Name, namePattern)
		}
		if seen[f.Name] {
			return fmt.Errorf("fields[%d]: duplicate name %q", i, f.Name)
		}
		seen[f.Name] = true
		if len(f.From) == 0 {
			return fmt.Errorf("field %q: from must list at least one source", f.Name)
		}
		if len(f.From) > MaxSourcesPerField {
			return fmt.Errorf("field %q: %d sources, at most %d allowed", f.Name, len(f.From), MaxSourcesPerField)
		}
		for j, s := range f.From {
			if err := s.validate(); err != nil {
				return fmt.Errorf("field %q: from[%d]: %w", f.Name, j, err)
			}
		}
	}
	return nil
}

func (s Source) validate() error {
	switch s.CycloneDX {
	case SourceComponentProperties, SourceMetadataProperties:
		if strings.TrimSpace(s.Property) == "" {
			return fmt.Errorf("%s needs \"property\"", s.CycloneDX)
		}
		if s.Type != "" {
			return fmt.Errorf("%s takes \"property\", not \"type\"", s.CycloneDX)
		}
	case SourceComponentExtRefs:
		if strings.TrimSpace(s.Type) == "" {
			return fmt.Errorf("%s needs \"type\"", s.CycloneDX)
		}
		if s.Property != "" {
			return fmt.Errorf("%s takes \"type\", not \"property\"", s.CycloneDX)
		}
	case "":
		return errors.New("\"cyclonedx\" source is required")
	default:
		return fmt.Errorf("unknown cyclonedx source %q (supported: %s, %s, %s)",
			s.CycloneDX, SourceComponentProperties, SourceMetadataProperties, SourceComponentExtRefs)
	}
	return nil
}

// ValidName reports whether s is a well-formed field name. The API uses it to
// validate ?extra_field= before the value reaches a query.
func ValidName(s string) bool { return namePattern.MatchString(s) }

// Names returns the declared field names in config order.
func (c *Config) Names() []string {
	if c == nil {
		return nil
	}
	out := make([]string, len(c.Fields))
	for i, f := range c.Fields {
		out[i] = f.Name
	}
	return out
}

// property and extRef are the two CycloneDX shapes read here. Each element is
// decoded on its own (see decodeList), so one odd entry does not hide the rest.
type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type extRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// metadata holds the raw pieces of a CycloneDX metadata object.
type metadata struct {
	Properties []property
	CompProps  []property
	CompRefs   []extRef
}

// Extract returns the configured fields found in raw, keyed by field name.
// Fields without a value are absent; no match at all returns nil. It never
// fails: a document that is not CycloneDX, or whose metadata has an
// unexpected shape, simply yields no fields — recognising an extra field must
// never be the reason an otherwise valid SBOM is rejected.
func Extract(raw []byte, cfg *Config) map[string][]string {
	if cfg == nil || len(cfg.Fields) == 0 {
		return nil
	}
	md, ok := readMetadata(raw)
	if !ok {
		return nil
	}

	var out map[string][]string
	for _, f := range cfg.Fields {
		var values []string
		seen := make(map[string]bool)
		add := func(v string) {
			v, ok := clean(v)
			if !ok || seen[v] || len(values) >= MaxValuesPerField {
				return
			}
			seen[v] = true
			values = append(values, v)
		}
		for _, s := range f.From {
			switch s.CycloneDX {
			case SourceComponentProperties:
				for _, p := range md.CompProps {
					if p.Name == s.Property {
						add(p.Value)
					}
				}
			case SourceMetadataProperties:
				for _, p := range md.Properties {
					if p.Name == s.Property {
						add(p.Value)
					}
				}
			case SourceComponentExtRefs:
				for _, r := range md.CompRefs {
					if strings.EqualFold(r.Type, s.Type) {
						add(r.URL)
					}
				}
			}
		}
		if len(values) > 0 {
			if out == nil {
				out = make(map[string][]string, len(cfg.Fields))
			}
			out[f.Name] = values
		}
	}
	return out
}

// readMetadata locates the CycloneDX metadata object, also inside an in-toto
// envelope whose predicate is a CycloneDX BOM. ok is false when raw is not a
// CycloneDX document.
func readMetadata(raw []byte) (metadata, bool) {
	var top struct {
		BomFormat string          `json:"bomFormat"`
		Metadata  json.RawMessage `json:"metadata"`
		Predicate json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return metadata{}, false
	}
	if top.BomFormat != "CycloneDX" && len(top.Predicate) > 0 {
		var pred struct {
			BomFormat string          `json:"bomFormat"`
			Metadata  json.RawMessage `json:"metadata"`
		}
		if err := json.Unmarshal(top.Predicate, &pred); err == nil {
			top.BomFormat, top.Metadata = pred.BomFormat, pred.Metadata
		}
	}
	if top.BomFormat != "CycloneDX" {
		return metadata{}, false
	}

	var md metadata
	var meta struct {
		Properties json.RawMessage `json:"properties"`
		Component  json.RawMessage `json:"component"`
	}
	if len(top.Metadata) == 0 || json.Unmarshal(top.Metadata, &meta) != nil {
		return md, true
	}
	md.Properties = decodeList[property](meta.Properties)
	var comp struct {
		Properties         json.RawMessage `json:"properties"`
		ExternalReferences json.RawMessage `json:"externalReferences"`
	}
	if len(meta.Component) > 0 && json.Unmarshal(meta.Component, &comp) == nil {
		md.CompProps = decodeList[property](comp.Properties)
		md.CompRefs = decodeList[extRef](comp.ExternalReferences)
	}
	return md, true
}

// decodeList decodes a JSON array element by element, skipping elements that
// do not fit T (e.g. a property whose value is a number).
func decodeList[T any](raw json.RawMessage) []T {
	if len(raw) == 0 {
		return nil
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil
	}
	out := make([]T, 0, len(items))
	for _, it := range items {
		var v T
		if json.Unmarshal(it, &v) == nil {
			out = append(out, v)
		}
	}
	return out
}

// clean makes an untrusted value storable: invalid UTF-8 and over-long values
// are dropped, control characters (newlines included) are removed, and
// surrounding whitespace is trimmed. ok is false when nothing usable remains.
func clean(v string) (string, bool) {
	if len(v) > MaxValueLen || !utf8.ValidString(v) {
		return "", false
	}
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, v)
	v = strings.TrimSpace(v)
	return v, v != ""
}
