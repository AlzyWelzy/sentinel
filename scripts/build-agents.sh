#!/bin/sh
# Builds the agent for every released platform, with a .sha256 next to each
# binary (install.sh, install.ps1 and `pulsegrid-agent update` verify them).
# Used by `make agent`, the API image build and the release workflow.
#
#   scripts/build-agents.sh <version> <output dir>
set -eu

VERSION=${1:?usage: build-agents.sh <version> <output dir>}
OUT=${2:?usage: build-agents.sh <version> <output dir>}
TARGETS="linux/amd64 linux/arm64 freebsd/amd64 freebsd/arm64 openbsd/amd64 netbsd/amd64 windows/amd64 windows/arm64"

if command -v sha256sum >/dev/null 2>&1; then sha256=sha256sum; else sha256="shasum -a 256"; fi

mkdir -p "$OUT"
for target in $TARGETS; do
    os=${target%/*}
    arch=${target#*/}
    ext=""
    [ "$os" = windows ] && ext=.exe
    name="pulsegrid-agent-$os-$arch$ext"
    echo "building $name"
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
        -ldflags="-s -w -X main.version=$VERSION" -o "$OUT/$name" ./agent
    (cd "$OUT" && $sha256 "$name" >"$name.sha256")
done
