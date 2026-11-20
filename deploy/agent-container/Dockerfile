# The agent as a container that keeps itself current: the entrypoint (root)
# runs `sentinel-agent update` at start and every hour, installing whatever
# version the rollout offers this server, and restarts the agent (which runs
# unprivileged) on the new binary. Build from the repo root:
#
#   docker build -f deploy/agent-container/Dockerfile \
#     --build-arg AGENT_VERSION=$(cat agent/VERSION) -t sentinel-agent .
#
# Run (first start registers, the volume keeps the identity):
#
#   docker run -d --name sentinel-agent --restart unless-stopped \
#     -e SENTINEL_URL=https://<console>/sentinel/ingest -e SENTINEL_KEY=pg_... \
#     -v sentinel-agent:/var/lib/sentinel sentinel-agent
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
COPY netmon ./netmon
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags="-s -w -X main.version=$AGENT_VERSION" -o /sentinel-agent ./agent

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata su-exec \
 && adduser -D -H -s /sbin/nologin sentinel \
 && mkdir -p /var/lib/sentinel && chown sentinel /var/lib/sentinel
COPY --from=build /sentinel-agent /usr/local/bin/sentinel-agent
COPY deploy/agent-container/entrypoint.sh /entrypoint.sh
VOLUME /var/lib/sentinel
ENTRYPOINT ["/entrypoint.sh"]
