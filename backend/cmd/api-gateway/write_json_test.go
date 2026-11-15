package main

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
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
