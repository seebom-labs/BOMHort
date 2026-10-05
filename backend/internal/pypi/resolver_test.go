package pypi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractPyPIPackage(t *testing.T) {
	tests := []struct {
		purl, name, version string
		ok                  bool
	}{
		{"pkg:pypi/requests@2.31.0", "requests", "2.31.0", true},
		{"pkg:pypi/Typing_Extensions@4.0.0", "typing-extensions", "4.0.0", true},
		{"pkg:pypi/zope.interface@6.0", "zope-interface", "6.0", true},
		{"pkg:pypi/requests", "requests", "", true},
		{"pkg:pypi/requests@unknown", "requests", "", true},
		{"pkg:pypi/requests@${version}", "", "", false},
		{"pkg:pypi/a/b@1.0", "", "", false},
		{"pkg:npm/requests@1.0", "", "", false},
	}
	for _, tc := range tests {
		name, version, ok := ExtractPyPIPackage(tc.purl)
		if name != tc.name || version != tc.version || ok != tc.ok {
			t.Errorf("ExtractPyPIPackage(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.purl, name, version, ok, tc.name, tc.version, tc.ok)
		}
	}
}

func TestExpression(t *testing.T) {
	tests := []struct {
		name        string
		expr, field string
		classifiers []string
		want        string
	}{
		{"PEP 639 expression wins", "MIT OR Apache-2.0", "BSD", nil, "MIT OR Apache-2.0"},
		{"short license field", "", "Apache 2.0", []string{"License :: OSI Approved :: Apache Software License"}, "Apache-2.0"},
		{"free-text field normalised", "", "PSF license", nil, "PSF-2.0"},
		{"classifier when field is empty", "", "", []string{"License :: OSI Approved :: MIT License"}, "MIT"},
		{"classifier when field is UNKNOWN", "", "UNKNOWN", []string{"License :: OSI Approved :: MIT License"}, "MIT"},
		{"classifier beats unmappable field", "", "BSD", []string{"License :: OSI Approved :: BSD License", "License :: OSI Approved :: MIT License"}, "MIT"},
		{"several mapped classifiers are joined with AND", "", "", []string{
			"License :: OSI Approved :: MIT License",
			"License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
		}, "MIT AND MPL-2.0"},
		{"pasted license text is ignored", "", "Copyright (c) 2020\nPermission is hereby granted", []string{"License :: OSI Approved :: MIT License"}, "MIT"},
		{"unversioned field is kept, not guessed", "", "BSD", nil, "BSD"},
		{"unversioned classifier is not guessed", "", "", []string{"License :: OSI Approved :: BSD License"}, "LicenseRef-BSD-License"},
		{"GPL classifier keeps its version semantics", "", "", []string{"License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)"}, "GPL-2.0-or-later"},
		{"unmappable classifier kept as LicenseRef", "", "", []string{"License :: Public Domain"}, "LicenseRef-Public-Domain"},
		{"proprietary classifier", "", "", []string{"License :: Other/Proprietary License"}, "LicenseRef-proprietary"},
		{"category-only classifier names no license", "", "", []string{"License :: OSI Approved"}, ""},
		{"nothing declared", "", "", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Expression(tc.expr, tc.field, tc.classifiers); got != tc.want {
				t.Errorf("Expression() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Path {
		case "/typing-extensions/4.0.0/json":
			_, _ = w.Write([]byte(`{"info":{"license":"PSF","classifiers":["License :: OSI Approved :: Python Software Foundation License"]}}`))
		case "/requests/json":
			_, _ = w.Write([]byte(`{"info":{"license":"Apache-2.0"}}`))
		case "/nolicense/1.0/json":
			_, _ = w.Write([]byte(`{"info":{"license":"UNKNOWN","classifiers":[]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	r := NewResolverWithBaseURL(srv.URL)
	ctx := context.Background()
	tests := []struct {
		purl, want, reason string
		latest             bool
	}{
		{"pkg:pypi/Typing_Extensions@4.0.0", "PSF-2.0", "", false},
		{"pkg:pypi/requests@unknown", "Apache-2.0", "", true},
		{"pkg:pypi/nolicense@1.0", "", "no-license-upstream", false},
		{"pkg:pypi/internal-tool@0.1.0", "", "not-published", false},
	}
	for _, tc := range tests {
		if got := r.Resolve(ctx, tc.purl); got != tc.want {
			t.Errorf("Resolve(%s) = %q, want %q", tc.purl, got, tc.want)
		}
		handled, reason, latest := r.Explain(tc.purl)
		if !handled || reason != tc.reason || latest != tc.latest {
			t.Errorf("Explain(%s) = (%v, %q, %v), want (true, %q, %v)", tc.purl, handled, reason, latest, tc.reason, tc.latest)
		}
	}
	before := calls
	for _, tc := range tests {
		r.Resolve(ctx, tc.purl)
	}
	if calls != before {
		t.Errorf("expected cache hits, got %d extra calls", calls-before)
	}
}
