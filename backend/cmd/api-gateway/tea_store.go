package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
	return a.ch.QueryTEAVEXStatements(ctx, sbomID)
}

func (a *teaStoreAdapter) QueryStoredDocumentInfo(ctx context.Context, sbomID string) (*tea.StoredDocumentInfo, error) {
	// 1. Try document store first (real 64-char sha256 captured at ingest #256)
	if a.docStore != nil {
		doc, err := a.ch.QueryStoredDocument(ctx, sbomID)
		if err != nil && !errors.Is(err, clickhouse.ErrDocumentNotStored) {
			return nil, err
		}
		if doc != nil {
			if _, err := hex.DecodeString(doc.SHA256Hash); err != nil || len(doc.SHA256Hash) != 64 {
				return nil, fmt.Errorf("invalid stored document SHA-256 for %s", sbomID)
			}
			rc, err := a.docStore.Get(ctx, doc.StorageRef)
			if err != nil {
				return nil, fmt.Errorf("read stored document for TEA: %w", err)
			}
			defer rc.Close()
			buf := make([]byte, 4096)
			n, err := io.ReadFull(rc, buf)
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, fmt.Errorf("read stored document for TEA: %w", err)
			}
			mediaType, isInToto := tea.ProbeFormat(buf[:n], doc.SourceFile)
			filename := filepath.Base(doc.SourceFile)
			if filename == "" || filename == "." || filename == "/" {
				filename = sbomID + ".json"
			}
			return &tea.StoredDocumentInfo{
				SHA256Hash:  doc.SHA256Hash,
				ContentType: mediaType,
				IsInToto:    isInToto,
				Filename:    filename,
				SizeBytes:   doc.SizeBytes,
			}, nil
		}
	}

	// 2. Fall back to reading source file from S3 or local directory
	sourceFile, err := a.ch.QuerySBOMSourceFile(ctx, sbomID)
	if err != nil {
		return nil, err
	}
	if sourceFile == "" {
		return nil, fmt.Errorf("no source file for TEA document %s", sbomID)
	}

	rel, rErr := a.ch.QueryTEAReleaseBySBOMID(ctx, sbomID)
	if rErr != nil {
		return nil, rErr
	}
	if rel == nil {
		return nil, tea.ErrNotFound
	}

	raw, err := a.readSourceBytes(ctx, sourceFile)
	if err != nil {
		return nil, fmt.Errorf("read TEA source document: %w", err)
	}
	computedHash, err := verifiedSourceHash(rel.SHA256Hash, raw)
	if err != nil {
		return nil, fmt.Errorf("verify TEA source document: %w", err)
	}

	mediaType, isInToto := tea.ProbeFormat(raw, sourceFile)
	filename := filepath.Base(sourceFile)
	if filename == "" || filename == "." || filename == "/" {
		filename = sbomID + ".json"
	}

	return &tea.StoredDocumentInfo{
		SHA256Hash:  computedHash,
		ContentType: mediaType,
		IsInToto:    isInToto,
		Filename:    filename,
		SizeBytes:   uint64(len(raw)),
	}, nil
}

func (a *teaStoreAdapter) GetArtifactData(ctx context.Context, sbomID string) (*tea.ArtifactData, error) {
	// 1. Try document store first (Tier-2 capture, exact producer bytes #256)
	if a.docStore != nil {
		doc, err := a.ch.QueryStoredDocument(ctx, sbomID)
		if err != nil && !errors.Is(err, clickhouse.ErrDocumentNotStored) {
			return nil, err
		}
		if doc != nil {
			if _, err := hex.DecodeString(doc.SHA256Hash); err != nil || len(doc.SHA256Hash) != 64 {
				return nil, fmt.Errorf("invalid stored document SHA-256 for %s", sbomID)
			}
			rc, err := a.docStore.Get(ctx, doc.StorageRef)
			if err != nil {
				return nil, fmt.Errorf("read stored document for TEA: %w", err)
			}
			buf := make([]byte, 4096)
			n, err := io.ReadFull(rc, buf)
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				_ = rc.Close()
				return nil, fmt.Errorf("read stored document for TEA: %w", err)
			}
			mediaType, _ := tea.ProbeFormat(buf[:n], doc.SourceFile)
			filename := filepath.Base(doc.SourceFile)
			if filename == "" || filename == "." || filename == "/" {
				filename = sbomID + ".json"
			}
			combined := io.MultiReader(bytes.NewReader(buf[:n]), rc)
			return &tea.ArtifactData{
				Filename:    filename,
				ContentType: mediaType,
				SHA256Hash:  doc.SHA256Hash,
				SizeBytes:   doc.SizeBytes,
				Body: struct {
					io.Reader
					io.Closer
				}{combined, rc},
			}, nil
		}
	}

	// 2. Fall back to source file from S3 or filesystem
	sourceFile, err := a.ch.QuerySBOMSourceFile(ctx, sbomID)
	if err != nil {
		return nil, err
	}
	if sourceFile == "" {
		return nil, fmt.Errorf("no source file for TEA document %s", sbomID)
	}

	rel, rErr := a.ch.QueryTEAReleaseBySBOMID(ctx, sbomID)
	if rErr != nil {
		return nil, rErr
	}
	if rel == nil {
		return nil, tea.ErrNotFound
	}

	raw, err := a.readSourceBytes(ctx, sourceFile)
	if err != nil {
		return nil, err
	}

	computedHash, err := verifiedSourceHash(rel.SHA256Hash, raw)
	if err != nil {
		return nil, fmt.Errorf("verify TEA source document: %w", err)
	}

	mediaType, _ := tea.ProbeFormat(raw, sourceFile)
	filename := filepath.Base(sourceFile)
	if filename == "" || filename == "." || filename == "/" {
		filename = sbomID + ".json"
	}

	return &tea.ArtifactData{
		Filename:    filename,
		ContentType: mediaType,
		SHA256Hash:  computedHash,
		SizeBytes:   uint64(len(raw)),
		Body:        io.NopCloser(bytes.NewReader(raw)),
	}, nil
}

func verifiedSourceHash(expected string, raw []byte) (string, error) {
	if decoded, err := hex.DecodeString(expected); err != nil || len(decoded) != sha256.Size {
		return "", errors.New("source has no recorded SHA-256; capture the original document")
	}
	sum := sha256.Sum256(raw)
	computed := hex.EncodeToString(sum[:])
	if !strings.EqualFold(computed, expected) {
		return "", errors.New("source document SHA-256 mismatch")
	}
	return computed, nil
}

func (a *teaStoreAdapter) readSourceBytes(ctx context.Context, sourceFile string) ([]byte, error) {
	if strings.HasPrefix(sourceFile, "s3://") {
		if a.s3c == nil {
			return nil, fmt.Errorf("s3 client not available")
		}
		bucket, key, parseErr := s3client.ParseURI(sourceFile)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid s3 source URI: %w", parseErr)
		}
		rc, err := a.s3c.GetObject(ctx, bucket, key)
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}

	absPath, pathErr := safeLocalSBOMPath(a.sbomDir, sourceFile)
	if pathErr != nil {
		return nil, fmt.Errorf("invalid local source file path: %w", pathErr)
	}
	return os.ReadFile(absPath)
}
