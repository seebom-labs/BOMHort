package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/docstore"
	s3client "github.com/seebom-labs/bomhort/backend/internal/s3"
	"github.com/seebom-labs/bomhort/backend/internal/tea"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// teaStoreAdapter connects ClickHouse, docstore, and S3 clients to tea.Store (#534).
type teaStoreAdapter struct {
	ch       *clickhouse.Client
	docStore docstore.Store
	s3c      *s3client.Client
	sbomDir  string
}

func newTEAStore(ch *clickhouse.Client, ds docstore.Store, s3c *s3client.Client, sbomDir string) tea.Store {
	return &teaStoreAdapter{
		ch:       ch,
		docStore: ds,
		s3c:      s3c,
		sbomDir:  sbomDir,
	}
}

func (a *teaStoreAdapter) QueryProducts(ctx context.Context, page, pageSize uint64) ([]tea.ProductSummary, uint64, error) {
	sums, total, err := a.ch.QueryTEAProducts(ctx, page, pageSize)
	if err != nil {
		return nil, 0, err
	}
	out := make([]tea.ProductSummary, len(sums))
	for i, s := range sums {
		out[i] = tea.ProductSummary{
			ProjectName:     s.ProjectName,
			Parent:          s.Parent,
			RootPURL:        s.RootPURL,
			ReleaseCount:    s.ReleaseCount,
			LatestVersion:   s.LatestVersion,
			LatestTimestamp: s.LatestTimestamp,
			LatestSBOMID:    s.LatestSBOMID,
		}
	}
	return out, total, nil
}

func (a *teaStoreAdapter) QueryProductByName(ctx context.Context, projectName string) (*tea.ProductSummary, error) {
	s, err := a.ch.QueryTEAProductByName(ctx, projectName)
	if err != nil {
		return nil, err
	}
	return &tea.ProductSummary{
		ProjectName:     s.ProjectName,
		Parent:          s.Parent,
		RootPURL:        s.RootPURL,
		ReleaseCount:    s.ReleaseCount,
		LatestVersion:   s.LatestVersion,
		LatestTimestamp: s.LatestTimestamp,
		LatestSBOMID:    s.LatestSBOMID,
	}, nil
}

func (a *teaStoreAdapter) QueryAllReleases(ctx context.Context, page, pageSize uint64) ([]models.SBOM, uint64, error) {
	return a.ch.QueryTEAAllReleases(ctx, page, pageSize)
}

func (a *teaStoreAdapter) QueryReleasesByProject(ctx context.Context, projectName string, page, pageSize uint64) ([]models.SBOM, uint64, error) {
	return a.ch.QueryTEAReleasesByProject(ctx, projectName, page, pageSize)
}

func (a *teaStoreAdapter) QueryReleaseBySBOMID(ctx context.Context, sbomID string) (*models.SBOM, error) {
	return a.ch.QueryTEAReleaseBySBOMID(ctx, sbomID)
}

func (a *teaStoreAdapter) QueryReleasesByPURL(ctx context.Context, purl string) ([]models.SBOM, error) {
	return a.ch.QueryTEAReleasesByPURL(ctx, purl)
}

func (a *teaStoreAdapter) QueryVEXStatementsCount(ctx context.Context, sbomID string) (int, error) {
	return a.ch.QueryTEAVEXStatementsCount(ctx, sbomID)
}

func (a *teaStoreAdapter) QueryVEXStatements(ctx context.Context, sbomID string) ([]models.VEXStatement, error) {
	items, err := a.ch.QuerySBOMVEXStatements(ctx, sbomID)
	if err != nil {
		return nil, err
	}
	out := make([]models.VEXStatement, len(items))
	for i, item := range items {
		parsedVEXID, _ := uuid.Parse(item.VEXID)
		out[i] = models.VEXStatement{
			VEXID:           parsedVEXID,
			DocumentID:      item.DocumentID,
			SourceFile:      item.SourceFile,
			SBOMID:          item.SBOMID,
			ProductPURL:     item.ProductPURL,
			VulnID:          item.VulnID,
			Status:          item.Status,
			Justification:   item.Justification,
			ImpactStatement: item.ImpactStatement,
			ActionStatement: item.ActionStatement,
			Author:          item.Author,
			Role:            item.Role,
			Tooling:         item.Tooling,
			StatusNotes:     item.StatusNotes,
		}
	}
	return out, nil
}

func (a *teaStoreAdapter) GetArtifactData(ctx context.Context, sbomID string) (*tea.ArtifactData, error) {
	// 1. Try document store first (Tier-2 capture, exact producer bytes #256)
	if a.docStore != nil {
		doc, err := a.ch.QueryStoredDocument(ctx, sbomID)
		if err == nil && doc != nil {
			rc, err := a.docStore.Get(ctx, doc.StorageRef)
			if err == nil {
				filename := filepath.Base(doc.SourceFile)
				if filename == "" || filename == "." || filename == "/" {
					filename = sbomID + ".json"
				}
				ct := doc.ContentType
				if ct == "" {
					ct = tea.MediaTypeSPDXJSON
				}
				return &tea.ArtifactData{
					Filename:    filename,
					ContentType: ct,
					SHA256Hash:  doc.SHA256Hash,
					SizeBytes:   doc.SizeBytes,
					Body:        rc,
				}, nil
			}
		}
	}

	// 2. Fall back to source file from S3 or filesystem
	sourceFile, err := a.ch.QuerySBOMSourceFile(ctx, sbomID)
	if err != nil || sourceFile == "" {
		return nil, tea.ErrNotFound
	}

	rel, rErr := a.ch.QueryTEAReleaseBySBOMID(ctx, sbomID)
	var shaHex string
	if rErr == nil && rel != nil {
		shaHex = rel.SHA256Hash
	}

	var rc io.ReadCloser
	if strings.HasPrefix(sourceFile, "s3://") {
		if a.s3c == nil {
			return nil, fmt.Errorf("s3 client not available")
		}
		bucket, key, parseErr := s3client.ParseURI(sourceFile)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid s3 source URI: %w", parseErr)
		}
		rc, err = a.s3c.GetObject(ctx, bucket, key)
		if err != nil {
			return nil, err
		}
	} else {
		// Open local file
		absPath := filepath.Join(a.sbomDir, sourceFile)
		f, openErr := os.Open(absPath)
		if openErr != nil {
			return nil, openErr
		}
		rc = f
	}

	filename := filepath.Base(sourceFile)
	if filename == "" || filename == "." || filename == "/" {
		filename = sbomID + ".json"
	}

	ct := tea.MediaTypeSPDXJSON
	if strings.HasSuffix(strings.ToLower(filename), ".cdx.json") {
		ct = tea.MediaTypeCycloneDXJSON
	}

	return &tea.ArtifactData{
		Filename:    filename,
		ContentType: ct,
		SHA256Hash:  shaHex,
		Body:        rc,
	}, nil
}
