package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	cases := []struct {
		name, remote, xff, real, want string
	}{
		{"remote addr without port", "203.0.113.9:4711", "", "", "203.0.113.9"},
		{"last XFF entry wins over spoofed first", "127.0.0.1:1", "1.2.3.4, 5.6.7.8", "", "5.6.7.8"},
		{"X-Real-IP beats XFF", "127.0.0.1:1", "1.2.3.4", "9.9.9.9", "9.9.9.9"},
		{"private peer (in-cluster proxy) is trusted", "10.244.1.7:1", "1.2.3.4", "", "1.2.3.4"},
		{"public peer: headers ignored", "203.0.113.9:1", "1.2.3.4", "9.9.9.9", "203.0.113.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.real != "" {
				r.Header.Set("X-Real-IP", tc.real)
			}
			if got := clientIP(r); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// Spoofing the first X-Forwarded-For entry must not open a fresh rate-limit bucket.
func TestRateLimitIgnoresSpoofedForwardedFor(t *testing.T) {
	h := rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	var last int
	for i := 0; i < 101; i++ {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "127.0.0.1:1"
		r.Header.Set("X-Forwarded-For", "10.0.0."+string(rune('0'+i%10))+", 5.6.7.8")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		last = w.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("request 101 got %d, want 429", last)
	}
}
