VERSION ?= dev
COMPOSE := docker compose -f deploy/docker-compose.yml
DIST := api/dist/$(VERSION)

.PHONY: up down logs agent test test-go test-api e2e lint

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f api ingest

# Builds agent binaries plus .sha256 files where the dev API serves them
# (/agent/<version>/...), which is what the installers download.
agent:
	sh scripts/build-agents.sh $(VERSION) $(DIST)

test: test-go test-api

test-go:
	go test ./...

# Needs Postgres and Redis from `make up` (migrated).
test-api:
	cd api && uv run pytest

# The browser journey (sign-up to outage and recovery, ~10 minutes), the
# extras, and the API access matrix. Needs `make up` and the web app on
# :3000 (cd web && npm run dev). Clears sign-up rate limits first.
e2e:
	cd e2e && npm ci --silent && npx playwright install chromium
	docker exec beyond-dev-redis-1 sh -c "redis-cli --scan --pattern 'pg:rl:*' | xargs -r redis-cli del" >/dev/null
	cd e2e && node journey.mjs && node extras.mjs && npm run --silent api

lint:
	gofmt -l $$(git ls-files '*.go') | (! grep .) && go vet ./...
	cd api && uv run ruff format --check . && uv run ruff check . && uv run ty check
	cd web && npm run format:check && npm run lint && npm run typecheck
