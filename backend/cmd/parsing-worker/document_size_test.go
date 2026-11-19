package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/config"
)

func TestReadBounded(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		maxBytes   int64
		wantErr    bool
		errContain string
	}{
		{
			name:     "within limit",
			content:  "small content",
			maxBytes: 1024,
			wantErr:  false,
		},
		{
			name:     "exact limit",
			content:  "12345",
			maxBytes: 5,
			wantErr:  false,
		},
		{
			name:       "exceeds limit",
			content:    "123456",
			maxBytes:   5,
			wantErr:    true,
			errContain: "document exceeds maximum allowed size",
		},
		{
			name:     "unlimited when zero or negative",
			content:  "any content whatsoever",
			maxBytes: 0,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader([]byte(tt.content))
			data, err := readBounded(r, tt.maxBytes)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.errContain != "" && !strings.Contains(err.Error(), tt.errContain) {
					t.Fatalf("expected error to contain %q, got %q", tt.errContain, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if string(data) != tt.content {
					t.Fatalf("got %q, want %q", string(data), tt.content)
				}
			}
		})
	}
}

func TestMaxDocumentBytes(t *testing.T) {
	if got := maxDocumentBytes(nil); got != 0 {
		t.Fatalf("expected 0 for nil config, got %d", got)
	}
	cfg := &config.Config{MaxDocumentSizeMB: 0}
	if got := maxDocumentBytes(cfg); got != 0 {
		t.Fatalf("expected 0 for 0 MB, got %d", got)
	}
	cfg.MaxDocumentSizeMB = 10
	if got := maxDocumentBytes(cfg); got != 10*1024*1024 {
		t.Fatalf("expected 10MB in bytes, got %d", got)
	}
}
