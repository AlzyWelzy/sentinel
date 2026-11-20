# Build context is the repo root (the ingest service imports ./proto).
# Cross-compile on the build machine's own architecture (no emulation).
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY proto ./proto
COPY netmon/traps ./netmon/traps
COPY ingest ./ingest
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/ingest ./ingest

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ingest /ingest
EXPOSE 8080
ENTRYPOINT ["/ingest"]
