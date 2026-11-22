package clickhouse

import (
	"context"
	"fmt"
	"strings"
)

// QueryLookalikeCache loads all cached package lookalike mappings from lookalike_cache.
func (c *Client) QueryLookalikeCache(ctx context.Context) (map[string][]string, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT system, package, lookalikes
		FROM lookalike_cache FINAL
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query lookalike cache: %w", err)
	}
	defer rows.Close()

	cache := make(map[string][]string)
	for rows.Next() {
		var system, pkg string
		var lookalikes []string
		if err := rows.Scan(&system, &pkg, &lookalikes); err != nil {
			return nil, fmt.Errorf("failed to scan lookalike cache row: %w", err)
		}
		if lookalikes == nil {
			lookalikes = []string{}
		}
		cache[system+":"+pkg] = lookalikes
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return cache, nil
}

// InsertLookalikeCache batch-inserts resolved package lookalikes into the cache.
func (c *Client) InsertLookalikeCache(ctx context.Context, entries map[string][]string) error {
	if len(entries) == 0 {
		return nil
	}

	batch, err := c.Conn.PrepareBatch(ctx,
		`INSERT INTO lookalike_cache (system, package, lookalikes)`)
	if err != nil {
		return fmt.Errorf("failed to prepare lookalike cache batch: %w", err)
	}

	for key, lookalikes := range entries {
		colon := strings.IndexByte(key, ':')
		if colon <= 0 || colon == len(key)-1 {
			continue
		}
		system := key[:colon]
		pkg := key[colon+1:]
		if lookalikes == nil {
			lookalikes = []string{}
		}
		if err := batch.Append(system, pkg, lookalikes); err != nil {
			return fmt.Errorf("failed to append lookalike cache entry %s: %w", key, err)
		}
	}

	return batch.Send()
}
