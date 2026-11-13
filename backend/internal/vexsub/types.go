package vexsub

import (
	"context"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// Supported upstream VEX subscription source types (#538).
const (
	SourceTypeOpenVEXHub   = "openvex-hub"
	SourceTypeCSAFProvider = "csaf-provider"
	SourceTypeOCIReferrers = "oci-referrers"
)

// Provenance constants.
const (
	RoleUpstream   = "upstream"
	AuthorUpstream = "upstream"
)

// SourceResult holds the statements fetched from a single source and whether
// the snapshot was complete (not capped by limits or missing documents) (#538).
type SourceResult struct {
	Statements []models.VEXStatement
	Complete   bool
}

// PullResult represents the aggregated result of an upstream VEX pull (#538).
type PullResult struct {
	Statements []models.VEXStatement
	Complete   bool
}

// SubscriptionSource fetches upstream VEX statements matching known package PURLs.
type SubscriptionSource interface {
	Fetch(ctx context.Context, knownPURLs []string) (SourceResult, error)
}
