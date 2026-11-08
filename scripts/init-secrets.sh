#!/bin/sh
# Creates ./secrets with random DB/session secrets (once). Fill google_client_secret and vault_credentials yourself.
set -eu
cd "$(dirname "$0")/.."
umask 077
mkdir -p secrets
chmod 700 secrets            # only the owner can enter the directory
gen() { [ -s "secrets/$1" ] || head -c 48 /dev/urandom | base64 | tr -d '/+=\n' | head -c 40 > "secrets/$1"; }
gen db_owner_password
gen app_db_password
gen session_key
[ -s secrets/database_url ] || printf 'postgresql://usm_app:%s@db:5432/usm' "$(cat secrets/app_db_password)" > secrets/database_url
touch secrets/google_client_secret secrets/vault_credentials
chmod 644 secrets/*          # readable by the non-root container users; protected by the 0700 directory
echo "secrets/ ready. Put the Google OAuth client secret in secrets/google_client_secret"
echo "and the vault credentials (e.g. GCP service-account JSON) in secrets/vault_credentials."
