# Pulsegrid

Multi-tenant server monitoring: a lightweight agent pushes host metrics to Pulsegrid, which stores them, evaluates alerts, and serves them to dashboards.

## Components

- `agent/` — Go agent installed on monitored servers
- `ingest/` — Go service receiving agent metrics
- `alerter/` — Go alert evaluation and notifications
- `api/` — FastAPI control plane (tenants, hosts, keys, rules, metrics queries)
- `proto/` — shared metric payload schema
- `deploy/` — compose/swarm stacks and install scripts
