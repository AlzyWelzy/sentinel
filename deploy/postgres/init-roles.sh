#!/bin/sh
# Creates the two login roles Sentinel services connect as. Runs once, on an
# empty data directory. Table grants and RLS policies live in the migrations.
#
#   sentinel          owner  — migrations only; owns tables, so RLS doesn't apply to it
#   sentinel_app      api    — every customer request; RLS always applies
#   sentinel_service  ingest + internal routes — BYPASSRLS, works across tenants
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE sentinel_app LOGIN PASSWORD '${SENTINEL_APP_PASSWORD}' NOBYPASSRLS;
CREATE ROLE sentinel_service LOGIN PASSWORD '${SENTINEL_SERVICE_PASSWORD}' BYPASSRLS;
GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO sentinel_app, sentinel_service;
GRANT USAGE ON SCHEMA public TO sentinel_app, sentinel_service;
SQL
