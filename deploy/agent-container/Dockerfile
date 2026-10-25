# The agent as a container that keeps itself current: the entrypoint (root)
# runs `pulsegrid-agent update` at start and every hour, installing whatever
# version the rollout offers this server, and restarts the agent (which runs
# unprivileged) on the new binary. Build from the repo root:
#
#   docker build -f deploy/agent-container/Dockerfile \
#     --build-arg AGENT_VERSION=$(cat agent/VERSION) -t pulsegrid-agent .
#
# Run (first start registers, the volume keeps the identity):
#
#   docker run -d --name pulsegrid-agent --restart unless-stopped \
#     -e PULSEGRID_URL=https://<console>/pulsegrid/ingest -e PULSEGRID_KEY=pg_... \
#     -v pulsegrid-agent:/var/lib/pulsegrid pulsegrid-agent
ARG AGENT_VERSION=dev

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG AGENT_VERSION
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY proto ./proto
COPY agent ./agent
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags="-s -w -X main.version=$AGENT_VERSION" -o /pulsegrid-agent ./agent

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata su-exec \
 && adduser -D -H -s /sbin/nologin pulsegrid \
 && mkdir -p /var/lib/pulsegrid && chown pulsegrid /var/lib/pulsegrid
COPY --from=build /pulsegrid-agent /usr/local/bin/pulsegrid-agent
COPY deploy/agent-container/entrypoint.sh /entrypoint.sh
VOLUME /var/lib/pulsegrid
ENTRYPOINT ["/entrypoint.sh"]
