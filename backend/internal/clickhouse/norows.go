package clickhouse

import (
	"database/sql"
	"errors"
)

// isNoRows reports whether err means "the query matched nothing".
//
// clickhouse-go returns database/sql's ErrNoRows from Row.Scan, so errors.Is is
// the reliable test. The string comparison is kept as a fallback because the
// driver wraps the sentinel in some paths, and a missed detection here turns a
// perfectly normal 404 into a 500 plus an ERROR log line — see the SBOM detail
// endpoint, which reported "Failed to fetch SBOM detail" for every unknown id.
func isNoRows(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sql.ErrNoRows) {
		return true
	}
	return err.Error() == "sql: no rows in result set"
}
