#!/bin/sh
# Applies migrations/*.sql in order, once each, in one transaction per file. Runs as the database owner.
set -eu
rd() { eval "v=\${$1:-}"; [ -n "$v" ] && { printf '%s' "$v"; return; }; eval "f=\${$1_FILE:-}"; [ -n "$f" ] && cat "$f"; }
PGPASSWORD="$(rd PGPASSWORD)"; export PGPASSWORD
APP_PW="$(rd USM_APP_DB_PASSWORD)"
: "${PGHOST:?}" "${PGUSER:?}" "${PGDATABASE:?}" "${PGPASSWORD:?}" "${APP_PW:?USM_APP_DB_PASSWORD(_FILE) required}"

until pg_isready -q; do echo "waiting for postgres..."; sleep 2; done

psql -v ON_ERROR_STOP=1 -q -c "CREATE TABLE IF NOT EXISTS schema_migrations (
  version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())"

for f in /migrations/*.sql; do
  v=$(basename "$f" .sql)
  sum=$(sha256sum "$f" | cut -d' ' -f1)
  have=$(psql -tAq -c "SELECT checksum FROM schema_migrations WHERE version = '$v'")
  if [ -n "$have" ]; then
    [ "$have" = "$sum" ] || { echo "ERROR: $v changed after it was applied - add a new migration instead"; exit 1; }
    continue
  fi
  echo "applying $v"
  psql -v ON_ERROR_STOP=1 -q -1 -v app_password="$APP_PW" -v dbname="$PGDATABASE" -f "$f" \
       -c "INSERT INTO schema_migrations (version, checksum) VALUES ('$v', '$sum')"
done
# keep the app role password in sync with the secret (rotation = change the secret, re-run migrate)
echo "ALTER ROLE usm_app PASSWORD :'app_password';" | psql -v ON_ERROR_STOP=1 -q -v app_password="$APP_PW" -f -
echo "migrations up to date"
