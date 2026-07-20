package clickhouse

import (
	"context"
	"fmt"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/seebom-labs/bomhort/backend/internal/config"
)

// Client wraps the ClickHouse connection.
type Client struct {
	Conn driver.Conn
}

// NewClient creates a new ClickHouse client from config.
func NewClient(cfg *config.Config) (*Client, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", cfg.ClickHouseHost, cfg.ClickHousePort)},
		Auth: clickhouse.Auth{
			Database: cfg.ClickHouseDatabase,
			Username: cfg.ClickHouseUser,
			Password: cfg.ClickHousePassword,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ClickHouse: %w", err)
	}

	if err := conn.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ping ClickHouse: %w", err)
	}

	return &Client{Conn: conn}, nil
}

// Close closes the ClickHouse connection.
func (c *Client) Close() error {
	return c.Conn.Close()
}

// HashExists checks if a SHA256 hash already exists in the ingestion queue.
// This covers both SBOM and VEX files and prevents re-enqueueing.
func (c *Client) HashExists(ctx context.Context, hash string) (bool, error) {
	var count uint64
	err := c.Conn.QueryRow(ctx,
		"SELECT count() FROM ingestion_queue FINAL WHERE sha256_hash = ? AND status != 'failed'", hash).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check hash existence: %w", err)
	}
	return count > 0, nil
}

// SBOMExists checks if an SBOM with the given ID already exists.
func (c *Client) SBOMExists(ctx context.Context, sbomID interface{}) (bool, error) {
	var count uint64
	err := c.Conn.QueryRow(ctx,
		"SELECT count() FROM sboms FINAL WHERE sbom_id = ?", sbomID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check sbom existence: %w", err)
	}
	return count > 0, nil
}

// VEXDocumentExists checks if a VEX document has already been ingested.
func (c *Client) VEXDocumentExists(ctx context.Context, documentID string) (bool, error) {
	var count uint64
	err := c.Conn.QueryRow(ctx,
		"SELECT count() FROM vex_statements FINAL WHERE document_id = ? LIMIT 1", documentID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check vex document existence: %w", err)
	}
	return count > 0, nil
}
