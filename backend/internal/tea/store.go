package tea

import (
	"context"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// ProductSummary holds project-level metadata for TEA product listing.
type ProductSummary struct {
	ProjectName     string
	Parent          string
	RootPURL        string
	ReleaseCount    uint64
	LatestVersion   string
	LatestTimestamp time.Time
	LatestSBOMID    uuid.UUID
}

// ArtifactData represents stored or generated artifact payload.
type ArtifactData struct {
	Filename    string
	ContentType string
	SHA256Hash  string
	SizeBytes   uint64
	Body        io.ReadCloser
}

// Store defines the read-only data operations required by the TEA service.
type Store interface {
	QueryProducts(ctx context.Context, page, pageSize uint64) ([]ProductSummary, uint64, error)
	QueryProductByName(ctx context.Context, projectName string) (*ProductSummary, error)
	QueryAllReleases(ctx context.Context, page, pageSize uint64) ([]models.SBOM, uint64, error)
	QueryReleasesByProject(ctx context.Context, projectName string, page, pageSize uint64) ([]models.SBOM, uint64, error)
	QueryReleaseBySBOMID(ctx context.Context, sbomID string) (*models.SBOM, error)
	QueryReleasesByPURL(ctx context.Context, purl string) ([]models.SBOM, error)
	QueryVEXStatementsCount(ctx context.Context, sbomID string) (int, error)
	QueryVEXStatements(ctx context.Context, sbomID string) ([]models.VEXStatement, error)
	GetArtifactData(ctx context.Context, sbomID string) (*ArtifactData, error)
}
