#!/bin/bash
# init-db.sh – Run on ClickHouse first start.
# Creates the bomhort database and runs all migrations.
set -e

echo "⏳ Creating bomhort database..."
clickhouse-client --query "CREATE DATABASE IF NOT EXISTS bomhort"

echo "⏳ Running migrations..."
for f in /docker-entrypoint-initdb.d/migrations/*.sql; do
  echo "  → $f"
  clickhouse-client --database=bomhort --multiquery < "$f"
done

echo "✅ Database initialized."

