package s3

import (
	"context"
	"strings"
	"testing"
)

func TestClassifyKey(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"k3s-io/helm-controller/0.16.14/k3s-io_helm-controller_0_16_14_spdx.json", "sbom"},
		{"project/v1.0/foo.spdx.json", "sbom"},
		{"golang-common.openvex.json", "vex"},
		{"advisories/cve-2025.vex.json", "vex"},
		{"README.md", ""},
		{"data.json", ""},
		{"archive.tar.gz", ""},
		{"NESTED/PATH/deep.SPDX.JSON", "sbom"}, // case-insensitive
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := ClassifyKey(tt.key)
			if got != tt.want {
				t.Errorf("ClassifyKey(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestParseURI(t *testing.T) {
	tests := []struct {
		uri        string
		wantBucket string
		wantKey    string
		wantErr    bool
	}{
		{
			uri:        "s3://cncf-subproject-sboms/k3s-io/helm-controller/0.16.14/file.spdx.json",
			wantBucket: "cncf-subproject-sboms",
			wantKey:    "k3s-io/helm-controller/0.16.14/file.spdx.json",
		},
		{
			uri:        "s3://my-bucket/simple.spdx.json",
			wantBucket: "my-bucket",
			wantKey:    "simple.spdx.json",
		},
		{
			uri:     "not-s3://bucket/key",
			wantErr: true,
		},
		{
			uri:     "s3://bucket-only",
			wantErr: true,
		},
		{
			uri:     "/local/path/file.spdx.json",
			wantErr: true,
		},
		{
			uri:     "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			bucket, key, err := ParseURI(tt.uri)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseURI(%q) expected error, got bucket=%q key=%q", tt.uri, bucket, key)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseURI(%q) unexpected error: %v", tt.uri, err)
				return
			}
			if bucket != tt.wantBucket {
				t.Errorf("ParseURI(%q) bucket = %q, want %q", tt.uri, bucket, tt.wantBucket)
			}
			if key != tt.wantKey {
				t.Errorf("ParseURI(%q) key = %q, want %q", tt.uri, key, tt.wantKey)
			}
		})
	}
}

func TestBucketConfig_Defaults(t *testing.T) {
	cfg := BucketConfig{
		Name: "test-bucket",
	}

	if cfg.Endpoint != "" {
		t.Errorf("expected empty endpoint, got %q", cfg.Endpoint)
	}
	if cfg.UseSSL != nil {
		t.Error("expected UseSSL=nil by default (pointer zero value)")
	}
	if cfg.UsePathStyle {
		t.Error("expected UsePathStyle=false by default")
	}
}

func TestObjectInfo_URI(t *testing.T) {
	obj := ObjectInfo{
		Bucket: "my-bucket",
		Key:    "path/to/file.spdx.json",
		ETag:   "abc123",
	}
	want := "s3://my-bucket/path/to/file.spdx.json"
	if got := obj.URI(); got != want {
		t.Errorf("URI() = %q, want %q", got, want)
	}
}

func TestClient_ListObjects_SkipsSkipScanBuckets(t *testing.T) {
	// The skipScan check must run before any client lookup: a skipScan
	// bucket with no corresponding entry in c.clients (which would otherwise
	// surface as a "no client for bucket" error result) must be silently
	// skipped instead, proving the exclusion happens first.
	c := &Client{
		configs: []BucketConfig{
			{Name: "push-bucket", SkipScan: true},
		},
	}

	var results []ObjectResult
	for r := range c.ListObjects(context.Background()) {
		results = append(results, r)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results for a skipScan-only bucket, got %d: %+v", len(results), results)
	}
}

// PutObject/GetObject's success paths talk to a real S3 wire protocol and
// aren't unit-tested here, matching this file's existing convention (no test
// in this package exercises an actual minio network call — GetObject has no
// success-path test either). The uploadHandler tests in cmd/api-gateway
// exercise PutObject/RemoveObject success and failure behavior against a
// fake implementing the small uploadObjectStore interface instead.

func TestClient_PutObject_UnknownBucket(t *testing.T) {
	c := &Client{}
	err := c.PutObject(context.Background(), "nonexistent", "key.spdx.json", strings.NewReader("data"), 4)
	if err == nil {
		t.Fatal("expected error for unconfigured bucket")
	}
}

func TestClient_RemoveObject_UnknownBucket(t *testing.T) {
	c := &Client{}
	err := c.RemoveObject(context.Background(), "nonexistent", "key.spdx.json")
	if err == nil {
		t.Fatal("expected error for unconfigured bucket")
	}
}

func TestSanitizeETag(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`"d41d8cd98f00b204e9800998ecf8427e"`, "d41d8cd98f00b204e9800998ecf8427e"},
		{`"abc123-5"`, "abc123-5"}, // multipart ETag
		{"no-quotes", "no-quotes"},
		{`""`, ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeETag(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeETag(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
