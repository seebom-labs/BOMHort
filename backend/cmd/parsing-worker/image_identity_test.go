package main

import (
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func TestResolveImageIdentity(t *testing.T) {
	t.Run("explicit_from_job", func(t *testing.T) {
		job := models.IngestionJob{
			ImageRef:    "ghcr.io/org/app:v1",
			ImageDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		}
		ref, dig := resolveImageIdentity(job, nil, "")
		if ref != "ghcr.io/org/app:v1" {
			t.Errorf("ref = %q, want ghcr.io/org/app:v1", ref)
		}
		if dig != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
			t.Errorf("dig = %q", dig)
		}
	})

	t.Run("split_ref_from_job", func(t *testing.T) {
		job := models.IngestionJob{
			ImageRef: "nginx@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		}
		ref, dig := resolveImageIdentity(job, nil, "")
		if ref != "nginx" {
			t.Errorf("ref = %q, want nginx", ref)
		}
		if dig != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
			t.Errorf("dig = %q", dig)
		}
	})

	t.Run("from_pkg_oci_purl", func(t *testing.T) {
		job := models.IngestionJob{}
		pkgs := &models.SBOMPackages{
			PackagePURLs: []string{
				"pkg:golang/github.com/gin-gonic/gin@v1.9.0",
				"pkg:oci/debian@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855?repository_url=docker.io/library/debian",
			},
		}
		ref, dig := resolveImageIdentity(job, pkgs, "")
		if ref != "docker.io/library/debian@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
			t.Errorf("ref = %q", ref)
		}
		if dig != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
			t.Errorf("dig = %q", dig)
		}
	})

	t.Run("from_document_name", func(t *testing.T) {
		job := models.IngestionJob{}
		ref, dig := resolveImageIdentity(job, nil, "my-app@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		if ref != "my-app" {
			t.Errorf("ref = %q, want my-app", ref)
		}
		if dig != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
			t.Errorf("dig = %q", dig)
		}
	})
}
