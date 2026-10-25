# Build context is the repo root: the image carries the agent binaries
# (served at <PUBLIC_DOWNLOAD_URL>/agent/<version>/), so a deployment needs no
# separate download hosting. AGENT_VERSION is agent/VERSION, not the release:
# a server-only release ships the same agent.
#
# PREVIOUS_AGENTS (the last API image) carries the versions it served, so
# rollbacks and pinned accounts can still download them; the newest
# KEEP_AGENT_VERSIONS are kept.
ARG AGENT_VERSION=dev
ARG PREVIOUS_AGENTS=no-previous-agents
ARG KEEP_AGENT_VERSIONS=6

FROM busybox:1.37 AS no-previous-agents
RUN mkdir -p /app/dist

FROM ${PREVIOUS_AGENTS} AS previous

# Agent binaries don't depend on the image's architecture: build them
# natively on the build machine.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS agents
ARG AGENT_VERSION
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY scripts/build-agents.sh ./scripts/
COPY proto ./proto
COPY agent ./agent
RUN sh scripts/build-agents.sh "$AGENT_VERSION" "/dist/$AGENT_VERSION"

FROM busybox:1.37 AS dist
ARG AGENT_VERSION
ARG KEEP_AGENT_VERSIONS
COPY --from=previous /app/dist /dist
COPY --from=agents /dist /dist
# Newest first by version number; drop the rest (never the one just built).
RUN cd /dist && ls -1 | grep -E '^[0-9]+\.[0-9]+\.[0-9]+' | sort -t. -k1,1nr -k2,2nr -k3,3nr \
      | tail -n +$((KEEP_AGENT_VERSIONS + 1)) | grep -vx "$AGENT_VERSION" | xargs -r rm -rf

FROM python:3.13-slim
ARG AGENT_VERSION

COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    AGENT_VERSION=$AGENT_VERSION

WORKDIR /app

COPY api/pyproject.toml api/uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

COPY api/ .
RUN uv sync --locked --no-dev
COPY --from=dist /dist ./dist

RUN useradd --system pulsegrid
USER pulsegrid

EXPOSE 8000
CMD ["fastapi", "run", "app/main.py", "--host", "0.0.0.0", "--port", "8000"]
