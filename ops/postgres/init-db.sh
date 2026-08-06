#!/bin/sh
# SecureRAG demo DB bootstrap (runs once via docker-entrypoint-initdb.d):
# 1. create the runtime roles + extensions (the committed bootstrap migration),
# 2. assign demo passwords to the runtime roles (never stored in SQL),
# 3. create the Keycloak application role + database.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -f /bootstrap/0001_roles_and_extensions.sql

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v migration_pw="$SECURERAG_MIGRATION_PASSWORD" \
  -v api_pw="$SECURERAG_API_PASSWORD" \
  -v worker_pw="$SECURERAG_WORKER_PASSWORD" \
  -v audit_pw="$SECURERAG_AUDIT_RETENTION_PASSWORD" \
  -v purge_pw="$SECURERAG_PURGE_PASSWORD" \
  -v keycloak_pw="$KEYCLOAK_DB_PASSWORD" <<'SQL'
ALTER ROLE securerag_migration LOGIN PASSWORD :'migration_pw';
ALTER ROLE securerag_api LOGIN PASSWORD :'api_pw';
ALTER ROLE securerag_worker LOGIN PASSWORD :'worker_pw';
ALTER ROLE securerag_audit_retention LOGIN PASSWORD :'audit_pw';
ALTER ROLE securerag_purge LOGIN PASSWORD :'purge_pw';
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'keycloak') THEN
    CREATE ROLE keycloak LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END
$$;
ALTER ROLE keycloak LOGIN PASSWORD :'keycloak_pw';
SELECT 'CREATE DATABASE keycloak OWNER keycloak'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'keycloak')
\gexec
SQL

echo "securerag demo db bootstrap complete"
