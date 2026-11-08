#!/bin/sh
# Deletes audit_log rows older than USM_AUDIT_RETENTION_DAYS (default 365) and records the purge in the audit log.
# Runs as the database owner (the app role cannot delete audit rows). Schedule it daily on the docker host.
set -eu
cd "$(dirname "$0")/.."
DAYS="${USM_AUDIT_RETENTION_DAYS:-365}"
case "$DAYS" in ''|*[!0-9]*) echo "USM_AUDIT_RETENTION_DAYS must be a number of days"; exit 1;; esac
docker compose exec -T db psql -U usm -d usm -v ON_ERROR_STOP=1 -v days="$DAYS" -qtA <<'SQL'
WITH d AS (DELETE FROM audit_log WHERE ts < now() - make_interval(days => :days) RETURNING 1),
     c AS (SELECT count(*) AS n FROM d)
INSERT INTO audit_log (actor, action, ok, detail)
SELECT 'system', 'audit_retention', true, jsonb_build_object('deleted', n, 'retention_days', :days) FROM c
RETURNING 'audit retention: deleted ' || (detail->>'deleted') || ' rows older than ' || (detail->>'retention_days') || ' days';
SQL
