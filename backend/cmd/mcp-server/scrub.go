package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// scrubMiddleware makes hidden characters in tool results visible.
func scrubMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		if r, ok := res.(*mcp.CallToolResult); ok && err == nil {
			if err := scrubResult(r); err != nil {
				log.Printf("ERROR: cannot sanitize MCP tool result: %s", sanitizeHeader(err.Error()))
				return &mcp.CallToolResult{
					IsError: true,
					Content: []mcp.Content{&mcp.TextContent{Text: "Unable to sanitize tool result."}},
				}, nil
			}
		}
		return res, err
	}
}

func scrubResult(r *mcp.CallToolResult) error {
	var original, cleaned []byte
	if r.StructuredContent != nil {
		var err error
		original, err = json.Marshal(r.StructuredContent)
		if err != nil {
			return err
		}
		cleaned, err = scrubJSON(original)
		if err != nil {
			return err
		}
		r.StructuredContent = json.RawMessage(cleaned)
	}
	for _, c := range r.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			switch {
			case original != nil && tc.Text == string(original):
				tc.Text = string(cleaned)
			case json.Valid([]byte(tc.Text)):
				raw, err := scrubJSON([]byte(tc.Text))
				if err != nil {
					return err
				}
				tc.Text = string(raw)
			default:
				tc.Text = scrubString(tc.Text)
			}
		}
	}
	return nil
}

// scrubJSON preserves numbers and escapes keys as well as values.
func scrubJSON(b []byte) (json.RawMessage, error) {
	if bytes.IndexFunc(b, func(r rune) bool { return r >= 0x7f || r == '\\' || r == '<' }) < 0 {
		return b, nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	return json.Marshal(scrubTree(tree))
}

func scrubTree(v any) any {
	switch t := v.(type) {
	case string:
		return scrubString(t)
	case []any:
		for i := range t {
			t[i] = scrubTree(t[i])
		}
		return t
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, val := range t {
			m[scrubString(k)] = scrubTree(val)
		}
		return m
	default:
		return v
	}
}

func hiddenRune(r rune) bool {
	return r != '\n' && r != '\t' && (!unicode.IsGraphic(r) ||
		unicode.Is(unicode.Co, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) ||
		(unicode.Is(unicode.Zs, r) && r != ' ') ||
		unicode.Is(unicode.Variation_Selector, r) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) ||
		r == '\u034f' || r == '\u2800')
}

// Escaping '<' makes the representation reversible and prevents key collisions.
func scrubString(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '<' || hiddenRune(r) {
			fmt.Fprintf(&b, "<U+%04X>", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var visibleRune = regexp.MustCompile(`<U\+[0-9A-F]{4,6}>`)

func restoreString(s string) string {
	return visibleRune.ReplaceAllStringFunc(s, func(marker string) string {
		n, err := strconv.ParseUint(marker[3:len(marker)-1], 16, 32)
		r := rune(n)
		if err != nil || n > unicode.MaxRune || (r != '<' && !hiddenRune(r)) || fmt.Sprintf("<U+%04X>", r) != marker {
			return marker
		}
		return string(r)
	})
}
