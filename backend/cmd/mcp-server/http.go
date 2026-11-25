package main

import (
	"crypto/subtle"
	"log"
	"net/http"
	"strings"
)

// httpGuard wraps the MCP Streamable HTTP handler with the two checks the
// transport itself does not make.
//
// Why both are mandatory (enforced in main, not optional here): an MCP server
// is a tool-execution endpoint. CVE-2026-33252 was exactly this — a Streamable
// HTTP transport that accepted cross-site POSTs without validating Origin or
// Content-Type, so any page a victim visited could drive the server. The SDK
// fixed its side; the bearer check and the Origin allow-list are ours, because
// the SDK cannot know which origins an operator considers legitimate.
//
// Ordering matters: the Origin check runs before the token check, so a
// cross-site request never gets to compare a token it would have to guess.
func httpGuard(next http.Handler, token string, allowedOrigins []string) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[strings.ToLower(strings.TrimRight(strings.TrimSpace(o), "/"))] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A browser sends Origin on every cross-site request; a CLI MCP client
		// sends none. Absent is therefore allowed — it is not a browser — but
		// present-and-unknown is rejected outright.
		if origin := r.Header.Get("Origin"); origin != "" {
			key := strings.ToLower(strings.TrimRight(origin, "/"))
			if _, ok := allowed[key]; !ok {
				log.Printf("WARN: rejected MCP request from origin %s", sanitizeHeader(origin))
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
		}

		if !validBearer(r, token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="bomhort-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// validBearer accepts the token as Authorization: Bearer or X-API-Key, the
// same two spellings the API gateway accepts, and compares in constant time.
func validBearer(r *http.Request, token string) bool {
	if token == "" {
		return false
	}
	presented := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if presented == "" {
		presented = strings.TrimSpace(r.Header.Get("X-API-Key"))
	}
	if presented == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(token)) == 1
}

// sanitizeHeader makes hidden characters visible and prevents forged log lines.
func sanitizeHeader(v string) string {
	var b strings.Builder
	v = strings.NewReplacer("\n", "<U+000A>", "\t", "<U+0009>").Replace(scrubString(v))
	for _, r := range v {
		if b.Len()+len(string(r)) > 200 {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
