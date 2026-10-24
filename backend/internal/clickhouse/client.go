package clickhouse

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/seebom-labs/bomhort/backend/internal/config"
)

// Client wraps the ClickHouse connection.
type Client struct {
	Conn driver.Conn

	archivedMu    sync.Mutex
	archivedCount uint64
	archivedAt    time.Time
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
		Settings: querySettings(cfg),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ClickHouse: %w", err)
	}

	if err := conn.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ping ClickHouse: %w", err)
	}

	return &Client{Conn: conn}, nil
}

// querySettings turns the configured per-query limits (#344-I) into session
// settings sent with every query. Unset (0) limits are omitted rather than
// sent as 0, so the server or user profile keeps deciding for them.
func querySettings(cfg *config.Config) clickhouse.Settings {
	settings := clickhouse.Settings{}
	if cfg.ClickHouseMaxExecutionTime > 0 {
		settings["max_execution_time"] = cfg.ClickHouseMaxExecutionTime
	}
	if cfg.ClickHouseMaxMemoryUsage > 0 {
		settings["max_memory_usage"] = cfg.ClickHouseMaxMemoryUsage
		// Spill GROUP BY / ORDER BY to disk at half the cap instead of failing:
		// package-wide aggregations over a large corpus otherwise abort
		// mid-stream and a page renders empty.
		settings["max_bytes_before_external_group_by"] = cfg.ClickHouseMaxMemoryUsage / 2
		settings["max_bytes_before_external_sort"] = cfg.ClickHouseMaxMemoryUsage / 2
	}
	if cfg.ClickHouseMaxThreads > 0 {
		settings["max_threads"] = cfg.ClickHouseMaxThreads
	}
	if len(settings) == 0 {
		return nil
	}
	return settings
}

// Close closes the ClickHouse connection.
func (c *Client) Close() error {
	return c.Conn.Close()
}

// HashExists reports whether the queue has a non-failed job for this content
// hash, judged on the job's latest status (see latestJobs). A failed job does
// not count, so its file is picked up again.
func (c *Client) HashExists(ctx context.Context, hash string) (bool, error) {
	var count uint64
	err := c.Conn.QueryRow(ctx,
		"SELECT count() FROM ("+latestJobs("WHERE job_id IN (SELECT job_id FROM ingestion_queue WHERE sha256_hash = ?)")+") WHERE latest_status != 'failed'", hash).Scan(&count)
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
