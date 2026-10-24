#!/bin/sh
# Creates the two login roles Pulsegrid services connect as. Runs once, on an
# empty data directory. Table grants and RLS policies live in the migrations.
#
#   pulsegrid          owner  — migrations only; owns tables, so RLS doesn't apply to it
#   pulsegrid_app      api    — every customer request; RLS always applies
#   pulsegrid_service  ingest + internal routes — BYPASSRLS, works across tenants
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE pulsegrid_app LOGIN PASSWORD '${PULSEGRID_APP_PASSWORD}' NOBYPASSRLS;
CREATE ROLE pulsegrid_service LOGIN PASSWORD '${PULSEGRID_SERVICE_PASSWORD}' BYPASSRLS;
GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO pulsegrid_app, pulsegrid_service;
GRANT USAGE ON SCHEMA public TO pulsegrid_app, pulsegrid_service;
SQL
