package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// writeJSON must send the same bytes json.Encoder did, so no response
// changes for a value that encodes.
func TestWriteJSON_SameBytesAsEncoder(t *testing.T) {
	v := map[string]any{"total": 3, "html": "<b>&</b>", "list": []string{"a"}, "score": 87.5}
	var want bytes.Buffer
	if err := json.NewEncoder(&want).Encode(v); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusCreated, v)
	if rec.Code != http.StatusCreated || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status %d, content type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if !bytes.Equal(rec.Body.Bytes(), want.Bytes()) {
		t.Errorf("body = %q, want %q", rec.Body.Bytes(), want.Bytes())
	}
}

// A value that cannot be encoded used to produce the given status with an
// empty body; the client now gets a 500 with an error it can parse.
func TestWriteJSON_UnencodableValueIs500(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, dto.DashboardStats{AverageQualityScore: math.NaN()})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] == "" {
		t.Errorf("body %q is not an error document (%v)", rec.Body.Bytes(), err)
	}
}

// discardResponseWriter counts the body instead of keeping it, so an
// allocation measurement sees only what writeJSON itself allocates.
type discardResponseWriter struct {
	header http.Header
	status int
	n      int
	err    error
}

func (d *discardResponseWriter) Header() http.Header {
	if d.header == nil {
		d.header = http.Header{}
	}
	return d.header
}
func (d *discardResponseWriter) WriteHeader(status int) { d.status = status }
func (d *discardResponseWriter) Write(p []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	d.n += len(p)
	return len(p), nil
}

// The license-compliance summary runs to megabytes; writing it must not
// cost a second full copy of the response per request. Measured like a
// benchmark: the encoder's pooled buffer is allocated once and reused, so
// a warmed call allocates far less than the body (the json.Marshal version
// allocated ~8.6 MB per 8 MiB response, the encoder ~0.2 MB amortised).
func TestWriteJSON_LargeResponseIsNotCopied(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector makes sync.Pool drop the encoder's buffer at random")
	}
	payload := map[string]string{"data": strings.Repeat("x", 8<<20)}
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		w := &discardResponseWriter{}
		for i := 0; i < b.N; i++ {
			writeJSON(w, http.StatusOK, payload)
		}
		if w.status != http.StatusOK || w.n < b.N*(8<<20) {
			b.Fatalf("status %d, %d bytes written", w.status, w.n)
		}
	})
	if perCall := res.AllocedBytesPerOp(); perCall > 1<<20 {
		t.Errorf("writeJSON allocated %d bytes per call for an 8 MiB response; want no copy of the body", perCall)
	}
}

// Once the status is out a failed write cannot be answered any more, but it
// must still be logged.
func TestWriteJSON_LogsWriteErrors(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	w := &discardResponseWriter{err: errors.New("connection failed")}
	writeJSON(w, http.StatusOK, map[string]int{"total": 1})
	if w.status != http.StatusOK {
		t.Errorf("status = %d, want the given 200", w.status)
	}
	if !strings.Contains(logs.String(), "connection failed") {
		t.Errorf("write error not logged; log = %q", logs.String())
	}
}
