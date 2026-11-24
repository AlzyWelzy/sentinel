# The web app (Next.js, standalone output). Build from the repo root:
#   docker build -f web/Dockerfile -t sentinel-web .
# The build runs once, on the builder's own architecture: its output is
# plain JavaScript (no native modules, no next/image), and building under
# arm64 emulation crashes Next's page generation (SIGILL). Only the final
# stage is per-platform.
FROM --platform=$BUILDPLATFORM node:24.22.1-alpine AS deps
WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM --platform=$BUILDPLATFORM node:24.22.1-alpine AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY web/ .
RUN npm run build

FROM node:24.22.1-alpine
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel
COPY --from=build --chown=sentinel:sentinel /app/.next/standalone ./
COPY --from=build --chown=sentinel:sentinel /app/.next/static ./.next/static
COPY --from=build --chown=sentinel:sentinel /app/public ./public
USER sentinel
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=5s CMD wget -qO- http://127.0.0.1:3000/login >/dev/null || exit 1
CMD ["node", "server.js"]
