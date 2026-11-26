package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestPutObjectIfAbsent(t *testing.T) {
	var mu sync.Mutex
	var object []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/test-bucket/tea/snapshot" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if r.Header.Get("If-None-Match") != "*" {
			http.Error(w, "missing precondition", http.StatusBadRequest)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if object != nil {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = io.WriteString(w, "<Error><Code>PreconditionFailed</Code><Message>exists</Message></Error>")
			return
		}
		object = data
		w.Header().Set("ETag", `"12345678901234567890123456789012"`)
	}))
	defer server.Close()
	useSSL := false
	client, err := NewClient([]BucketConfig{{
		Name: "test-bucket", Endpoint: strings.TrimPrefix(server.URL, "http://"),
		Region: "us-east-1", UseSSL: &useSSL, UsePathStyle: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	const writers = 16
	type result struct {
		value string
		wrote bool
		err   error
	}
	results := make(chan result, writers)
	for i := 0; i < writers; i++ {
		go func(i int) {
			value := fmt.Sprintf("payload-%d", i)
			wrote, err := client.PutObjectIfAbsent(context.Background(), "test-bucket", "tea/snapshot", bytes.NewBufferString(value), int64(len(value)))
			results <- result{value, wrote, err}
		}(i)
	}
	var winner string
	for i := 0; i < writers; i++ {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.wrote {
			if winner != "" {
				t.Fatal("more than one writer succeeded")
			}
			winner = r.value
		}
	}
	if winner == "" || string(object) != winner {
		t.Fatalf("winner %q, stored %q", winner, object)
	}
}
