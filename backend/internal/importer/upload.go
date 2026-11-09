package importer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	json "github.com/goccy/go-json"
)

// uploadPath is the push-model upload route (#135).
const uploadPath = "/api/v1/sboms/upload"

const (
	// maxRateLimitRetries bounds how often one upload waits out a 429.
	maxRateLimitRetries = 5
	// defaultRetryAfter is used when a 429 carries no usable Retry-After;
	// the gateway's rate-limit window is 10 seconds.
	defaultRetryAfter = 10 * time.Second
	// maxResponseSize bounds the response body read.
	maxResponseSize = 1 << 20
)

// Upload is one document to push.
type Upload struct {
	FileName string
	Data     []byte
	// Project and Tags become ?project= and ?tags=; empty means the
	// instance defaults.
	Project string
	Tags    []string
}

// UploadResult is the gateway's answer: status "pending" for a new document,
// "duplicate" for content it already has.
type UploadResult struct {
	Status string `json:"status"`
	JobID  string `json:"job_id"`
	SHA256 string `json:"sha256_hash"`
}

// Duplicate reports whether the instance already had the content.
func (r UploadResult) Duplicate() bool { return r.Status == "duplicate" }

// Uploader pushes documents to a BOMHort instance.
type Uploader interface {
	Upload(ctx context.Context, u Upload) (UploadResult, error)
}

// Client uploads through POST /api/v1/sboms/upload with an API key.
type Client struct {
	endpoint string
	apiKey   string
	http     *http.Client
	// wait sleeps for d or until ctx is done; replaced in tests.
	wait func(ctx context.Context, d time.Duration) error
}

// NewClient returns a client for the instance at baseURL (scheme and host,
// e.g. https://bomhort.example.com).
func NewClient(baseURL, apiKey string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(baseURL), "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid BOMHort URL %q: want http(s)://host", baseURL)
	}
	if apiKey == "" {
		return nil, errors.New("an API key is required: uploads need AUTH_ENABLED=true on the instance")
	}
	return &Client{
		endpoint: u.String() + uploadPath,
		apiKey:   apiKey,
		http:     &http.Client{Timeout: timeout},
		wait:     sleep,
	}, nil
}

// Upload sends one document. A 429 is retried after Retry-After, a bounded
// number of times; every other non-2xx status is an error carrying the
// gateway's message.
func (c *Client) Upload(ctx context.Context, u Upload) (UploadResult, error) {
	q := url.Values{}
	if u.Project != "" {
		q.Set("project", u.Project)
	}
	if len(u.Tags) > 0 {
		q.Set("tags", strings.Join(u.Tags, ","))
	}
	endpoint := c.endpoint
	if len(q) > 0 {
		endpoint += "?" + q.Encode()
	}

	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(u.Data))
		if err != nil {
			return UploadResult{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Filename", u.FileName)
		req.Header.Set("X-API-Key", c.apiKey)
		req.Header.Set("User-Agent", importTooling)

		resp, err := c.http.Do(req)
		if err != nil {
			return UploadResult{}, err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		_ = resp.Body.Close()
		if readErr != nil {
			return UploadResult{}, fmt.Errorf("read response: %w", readErr)
		}

		switch {
		case resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK:
			var res UploadResult
			if err := json.Unmarshal(body, &res); err != nil {
				return UploadResult{}, fmt.Errorf("unexpected response (%s): %w", resp.Status, err)
			}
			return res, nil
		case resp.StatusCode == http.StatusTooManyRequests && attempt < maxRateLimitRetries:
			if err := c.wait(ctx, retryAfter(resp.Header.Get("Retry-After"))); err != nil {
				return UploadResult{}, err
			}
		default:
			return UploadResult{}, fmt.Errorf("%s: %s", resp.Status, gatewayMessage(body))
		}
	}
}

// retryAfter reads a Retry-After header given in seconds.
func retryAfter(v string) time.Duration {
	if s, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && s > 0 && s <= 300 {
		return time.Duration(s) * time.Second
	}
	return defaultRetryAfter
}

// gatewayMessage extracts {"error": "..."} from an error response.
func gatewayMessage(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return e.Error
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return msg
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
