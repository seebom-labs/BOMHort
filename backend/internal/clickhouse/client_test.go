package clickhouse

// This file contains integration test notes for the ClickHouse client.
//
// Running integration tests requires a running ClickHouse instance.
// Use docker compose to start one:
//
//   docker compose up -d clickhouse
//
// Then run the tests:
//
//   CLICKHOUSE_HOST=localhost CLICKHOUSE_PORT=9000 CLICKHOUSE_DATABASE=bomhort \
//     go test -v -tags=integration ./internal/clickhouse/
//
// Integration tests are tagged with //go:build integration
// and are NOT run during normal `go test ./...`
