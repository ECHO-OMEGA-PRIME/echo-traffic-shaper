# Operations

This runbook covers the live FastAPI deployment on FORGE. It intentionally excludes literal credentials and client traffic.

## Service inventory

| Item | Value |
|---|---|
| Unit | `echo-traffic-shaper.service` |
| Working directory | `/home/forge/echo-traffic-shaper` |
| Internal port | `8194` |
| Health route | `GET /health` |
| Database schema | `traffic_shaper` |
| Runtime owner | `forge` |

## Safe read-only checks

```bash
ssh forge "systemctl is-active echo-traffic-shaper.service"
ssh forge "systemctl show echo-traffic-shaper.service -p MainPID -p ActiveEnterTimestamp -p WorkingDirectory --no-pager"
ssh forge "curl --fail --silent http://127.0.0.1:8194/health"
ssh forge "journalctl -u echo-traffic-shaper.service -n 100 --no-pager"
```

Healthy means all of the following:

- systemd reports `active`;
- the health request returns HTTP 200;
- the JSON body has `status: ok`;
- `db_connected` is `true`;
- the timestamp and uptime advance normally.

## Configuration

Production configuration is injected through the managed service environment. Relevant variable names are:

| Variable | Purpose |
|---|---|
| `PGHOST` | PostgreSQL host |
| `PGUSER` | PostgreSQL role |
| `PGPASSWORD` | PostgreSQL credential; never print or commit it |
| `PGDATABASE` | PostgreSQL database |
| `PORT` | HTTP listen port |
| `VERSION` | Version returned by metadata routes |
| `ECHO_API_KEY` | Optional Commander bypass key |
| `BRAIN_INGEST_URL` | Optional block-notification target |
| `SWARM_MOLT_URL` | Optional swarm-notification target |
| `ALERT_ROUTER_URL` | Optional alert-notification target |

Inspect names and unit wiring without dumping values. Do not run `systemctl show ... Environment` or print the process environment into logs.

Worker policy is managed through the SDK capabilities or the `/config` endpoints. Block policy is managed through `echo.traffic_shaper.block` and read through `echo.traffic_shaper.blocked`.

## Test layers

The deployed Python source includes five pytest modules and a live smoke script.

```bash
ssh forge "cd /home/forge/echo-traffic-shaper && python3 -m pytest tests -q"
ssh forge "cd /home/forge/echo-traffic-shaper && python3 smoke_test.py"
```

The unit/integration suite covers helpers, happy paths, edge cases, failure handling, request models, notifications, CORS, rate denials, auto-block behavior, and database fail-open behavior. The current smoke test exercises the real HTTP service with stable synthetic records. It may upsert those test records and append audit rows; run it only in an authorized environment and inspect the synthetic state afterward.

For the retained Worker source in this repository:

```bash
npm ci
npx tsc --noEmit
```

Do not run `npm run deploy`; the Worker is not the production deployment.
The legacy dependency tree currently reports audit findings. They are additional evidence that this Worker must remain non-production until a dedicated dependency-remediation build updates and regression-tests it; a documentation task must not apply an unreviewed forced upgrade.

## Observability

Use these signals together:

- `/health` for liveness and PostgreSQL connectivity;
- `/stats` for short- and long-window traffic totals;
- `/analytics` for worker, IP, latency, and denial-reason breakdowns;
- systemd state for crash/restart behavior;
- journald for startup, database, notification, and unhandled-request errors;
- `traffic_shaper.traffic_log` for audited decisions.

Avoid copying raw IP histories or configuration rows into reports. Aggregate counts are sufficient for normal operations.

## Incident triage

### Service inactive or port closed

1. Read `systemctl status` and the last 100 journal lines.
2. Confirm the unit's working directory exists and the Python module compiles.
3. Check whether another process owns port 8194.
4. Boot the candidate code on a staging port and run its live smoke suite.
5. Promote only after the staging suite is green; health-check production and roll back on red.

### Health degraded

1. Confirm PostgreSQL itself is healthy through the SDK or service-local connectivity check.
2. Inspect only connection metadata, never credential values.
3. Review recent database errors in journald.
4. Keep the process running if liveness is intact; the degraded body is designed to expose dependency failure without a crash loop.

### Unexpected rate denials

1. Read the worker's current configuration.
2. Check active IP and API-key blocks.
3. Inspect aggregated denial reasons and the `Retry-After` value.
4. Remember that process restarts clear in-memory windows; do not restart solely to evade a configured policy.
5. Adjust policy through the tiered SDK surface and verify with a synthetic documentation-range IP.

### Fail-open responses

`reason: error_passthrough` indicates the critical decision path encountered an internal failure. This keeps dependent fleet services available but is an operational alert, not a healthy decision. Inspect the journal and database state immediately, then verify ordinary `allowed` and deliberate 429 responses after remediation.

## Change and deploy discipline

This repository currently documents but does not contain the authoritative production Python runtime. Therefore:

1. Never deploy `src/index.ts` to replace the live service.
2. Never overwrite the live working directory from this repository.
3. Reconcile the exact live Python source into version control in a dedicated runtime build.
4. Preserve the deployed source hash and take a recoverable backup before reconciliation.
5. Add syntax checks, the full pytest suite, a staging-port boot, live smoke, promotion health check, and automatic rollback.
6. Restart production only after the staging gate passes.

Documentation-only changes do not require a service restart. They may be copied to the live working directory after merge, with the previous document retained as a recoverable backup.

## Post-change acceptance

- `systemctl is-active` is green.
- `/health` reports `status: ok` and `db_connected: true`.
- the full deployed pytest suite passes.
- the live smoke suite passes.
- SDK health, stats, and one synthetic `/check` decision work.
- no secrets or client data appear in the diff or test logs.
- build queue progress, build registry, and durable context are updated.
