package imagedigest

import "testing"

func TestNormalizeDigest(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"sha256:abcd", "sha256:abcd"},
		{"SHA256:ABCD", "sha256:abcd"},
		{"sha256%3Aabcd", "sha256:abcd"},
		{"sha256%3aabcd", "sha256:abcd"},
		// Bare 64-char hex string defaults to sha256:
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		// Other algorithms
		{"sha512:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "sha512:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},
	}

	for _, tc := range tests {
		got := NormalizeDigest(tc.in)
		if got != tc.want {
			t.Errorf("NormalizeDigest(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsValidDigest(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"not-a-digest", false},
		{"sha256", false},
		{"sha256:", false},
		{"sha256:123", false}, // too short hex
		{"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true},
		{"SHA256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", true},
		{"sha256%3Ae3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true},
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true},
	}

	for _, tc := range tests {
		got := IsValidDigest(tc.in)
		if got != tc.want {
			t.Errorf("IsValidDigest(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestExtractFromPURL(t *testing.T) {
	tests := []struct {
		name       string
		purl       string
		wantRef    string
		wantDigest string
	}{
		{
			name:       "empty",
			purl:       "",
			wantRef:    "",
			wantDigest: "",
		},
		{
			name:       "non-oci",
			purl:       "pkg:npm/%40angular/core@17.0.0",
			wantRef:    "",
			wantDigest: "",
		},
		{
			name:       "oci with tag and repository_url and version digest",
			purl:       "pkg:oci/debian@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855?repository_url=docker.io/library/debian&tag=12",
			wantRef:    "docker.io/library/debian:12",
			wantDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:       "oci with tag only",
			purl:       "pkg:oci/nginx@1.25.0?repository_url=docker.io/library/nginx",
			wantRef:    "docker.io/library/nginx:1.25.0",
			wantDigest: "",
		},
		{
			name:       "oci with digest qualifier",
			purl:       "pkg:oci/ubuntu?repository_url=docker.io/library/ubuntu&digest=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantRef:    "docker.io/library/ubuntu@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:       "oci no repository_url qualifier, uses path",
			purl:       "pkg:oci/my-org/my-image@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantRef:    "my-org/my-image@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ref, dig := ExtractFromPURL(tc.purl)
			if ref != tc.wantRef {
				t.Errorf("ref = %q, want %q", ref, tc.wantRef)
			}
			if dig != tc.wantDigest {
				t.Errorf("dig = %q, want %q", dig, tc.wantDigest)
			}
		})
	}
}
