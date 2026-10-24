# Build context is the repo root: the image carries the agent binaries for
# its own release (served at <PUBLIC_DOWNLOAD_URL>/agent/<version>/), so a
# deployment needs no separate download hosting.
ARG AGENT_VERSION=dev

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
COPY --from=agents /dist ./dist

RUN useradd --system pulsegrid
USER pulsegrid

EXPOSE 8000
CMD ["fastapi", "run", "app/main.py", "--host", "0.0.0.0", "--port", "8000"]
