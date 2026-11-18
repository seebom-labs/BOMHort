package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// scrubMiddleware strips hidden characters from every tool result before it
// reaches the client (GHSA-c9hv-fhrv-j87v). Document names, suppliers,
// package names and advisory summaries are written by whoever uploads an SBOM
// or publishes an advisory; bidi overrides, zero-width characters and
// terminal escapes let such text carry instructions a model sees and a human
// reviewing the transcript does not. The strings stay uploader-controlled —
// instructions tells the model so — but at least they are visibly so.
func scrubMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		if r, ok := res.(*mcp.CallToolResult); ok && err == nil {
			scrubResult(r)
		}
		return res, err
	}
}

func scrubResult(r *mcp.CallToolResult) {
	if r.StructuredContent != nil {
		if raw, ok := scrubJSON(r.StructuredContent); ok {
			r.StructuredContent = raw
			// The SDK mirrors structured output into one TextContent for
			// pre-structured-content clients; rebuild it from the scrubbed JSON.
			if len(r.Content) == 1 {
				if _, isText := r.Content[0].(*mcp.TextContent); isText {
					r.Content[0] = &mcp.TextContent{Text: string(raw)}
					return
				}
			}
		}
	}
	for _, c := range r.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			tc.Text = scrubString(tc.Text)
		}
	}
}

// scrubJSON walks an arbitrary JSON value and scrubs every string in it,
// keys included. Numbers are kept verbatim via UseNumber.
func scrubJSON(v any) (json.RawMessage, bool) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, false
	}
	out, err := json.Marshal(scrubTree(tree))
	if err != nil {
		return nil, false
	}
	return out, true
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

// scrubString drops Unicode format characters (category Cf: bidi overrides,
// zero-width joiners and spaces, soft hyphens) and control characters other
// than newline and tab.
func scrubString(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
}
