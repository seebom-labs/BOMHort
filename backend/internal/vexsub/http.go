package vexsub

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

const (
	// maxVEXDocumentBytes caps any downloaded or read VEX/CSAF/index payload at 10 MiB.
	maxVEXDocumentBytes int64 = 10 << 20
	// defaultUserAgent identifies BOMHort when polling public CSAF, OpenVEX, or OCI endpoints.
	defaultUserAgent = "BOMHort/1.0"
	// maxConcurrentFetches bounds parallel upstream HTTP pulls per source.
	maxConcurrentFetches = 8
	// defaultHTTPTimeout applies when callers pass a nil *http.Client.
	defaultHTTPTimeout = 30 * time.Second
)

type httpError struct {
	URL        string
	StatusCode int
	Headers    http.Header
}

func (e *httpError) Error() string {
	return fmt.Sprintf("HTTP %d from %s", e.StatusCode, e.URL)
}

func ensureHTTPClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return &http.Client{Timeout: defaultHTTPTimeout}
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("payload exceeds %d bytes", limit)
	}
	return data, nil
}

func fetchBytes(ctx context.Context, client *http.Client, rawURL string, headers map[string]string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating request for %s: %w", rawURL, err)
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := ensureHTTPClient(client).Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, resp.Header, &httpError{
			URL:        rawURL,
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
		}
	}

	data, err := readBounded(resp.Body, maxVEXDocumentBytes)
	if err != nil {
		return nil, resp.Header, fmt.Errorf("reading %s: %w", rawURL, err)
	}
	return data, resp.Header, nil
}

// resolveURL resolves ref against base according to RFC 3986.
func resolveURL(base, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return b.ResolveReference(r).String()
}

// joinBaseURL resolves rel relative to a directory-like base URL even if base
// lacks a trailing slash (unlike RFC 3986 file-relative resolution).
func joinBaseURL(base, rel string) string {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return ""
	}
	if strings.HasPrefix(rel, "http://") || strings.HasPrefix(rel, "https://") {
		return rel
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return resolveURL(base, strings.TrimLeft(rel, "/"))
}

// resolveLocalPath converts file:// URLs or bare filesystem paths to an OS path
// when the source does not use http:// or https://.
func resolveLocalPath(sourceURL string) (string, bool) {
	if strings.HasPrefix(sourceURL, "http://") || strings.HasPrefix(sourceURL, "https://") {
		return "", false
	}
	if strings.HasPrefix(sourceURL, "file://") {
		u, err := url.Parse(sourceURL)
		if err == nil {
			return u.Path, true
		}
	}
	if _, err := os.Stat(sourceURL); err == nil {
		return sourceURL, true
	}
	return sourceURL, true
}

func stampUpstream(stmt *models.VEXStatement, sourceURL string) {
	if stmt.Author == "" {
		stmt.Author = sourceURL
	}
	stmt.Role = models.VEXRoleUpstream
	stmt.Tooling = sourceURL
	if stmt.SourceFile == "" {
		stmt.SourceFile = sourceURL
	}
}
