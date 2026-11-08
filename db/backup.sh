#!/bin/sh
# Daily dump of users + audit log (no secret values are stored in the database).
# Usage on the docker host: ./db/backup.sh /path/to/backups   (keeps 30 days)
set -eu
DEST="${1:?backup directory}"
mkdir -p "$DEST"
docker compose exec -T db pg_dump -U usm -d usm --no-owner | gzip > "$DEST/usm-$(date +%Y%m%d-%H%M).sql.gz"
find "$DEST" -name 'usm-*.sql.gz' -mtime +30 -delete
