package docstore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	s3client "github.com/seebom-labs/bomhort/backend/internal/s3"
)

func TestImmutableS3RequiresConditionalWrites(t *testing.T) {
	for _, supports := range []bool{true, false} {
		t.Run(fmt.Sprint(supports), func(t *testing.T) {
			objects := map[string][]byte{}
			var mu sync.Mutex
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPut || r.Header.Get("If-None-Match") != "*" {
					http.Error(w, "unexpected request", http.StatusBadRequest)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				if _, exists := objects[r.URL.Path]; exists && supports {
					w.Header().Set("Content-Type", "application/xml")
					w.WriteHeader(http.StatusPreconditionFailed)
					_, _ = io.WriteString(w, "<Error><Code>PreconditionFailed</Code></Error>")
					return
				}
				objects[r.URL.Path], _ = io.ReadAll(r.Body)
				w.Header().Set("ETag", `"12345678901234567890123456789012"`)
			}))
			defer server.Close()
			ssl := false
			client, err := s3client.NewClient([]s3client.BucketConfig{{
				Name: "test-bucket", Endpoint: strings.TrimPrefix(server.URL, "http://"),
				Region: "us-east-1", UseSSL: &ssl, UsePathStyle: true,
			}})
			if err != nil {
				t.Fatal(err)
			}
			store, err := NewS3Store(client, "test-bucket", "custom/tea/archive/")
			if err != nil {
				t.Fatal(err)
			}
			ref, err := ImmutableRef(store, "tea/release/1")
			if err != nil {
				t.Fatal(err)
			}
			created, err := PutIfAbsent(context.Background(), store, ref, []byte("first"))
			if supports {
				if err != nil || !created {
					t.Fatalf("create = %v, %v", created, err)
				}
				created, err = PutIfAbsent(context.Background(), store, ref, []byte("second"))
				if err != nil || created {
					t.Fatalf("overwrite = %v, %v", created, err)
				}
			} else if err == nil || created {
				t.Fatalf("unsupported backend accepted: created=%v err=%v", created, err)
			}
		})
	}
}
