# Migration status

## Authoritative state

Echo Traffic Shaper was migrated from a Cloudflare Worker to a FastAPI service on FORGE. The live production runtime is `/home/forge/echo-traffic-shaper/app.py`, managed by `echo-traffic-shaper.service` on port 8194.

This GitHub repository still contains the earlier Hono/TypeScript Worker and did not contain the deployed Python source when this documentation recovery began. That drift is material:

- the repository is useful as migration provenance;
- the repository is not currently a deployable source of production truth;
- `npm run deploy` must not be used for production;
- copying this repository over the live service would be destructive;
- reconciling runtime source belongs in a separate engineering change with production deployment gates.

## Platform mapping

| Cloudflare-era component | Production replacement |
|---|---|
| Hono Worker | FastAPI application under systemd |
| D1 database | PostgreSQL schema `traffic_shaper` |
| KV rate windows | Locked in-memory window store |
| Worker service bindings | Optional best-effort HTTP notification targets |
| Cron trigger | In-process 60-second expired-counter pruner |
| Worker Analytics Engine | PostgreSQL traffic-log aggregations |
| Wrangler deployment | Staging-first systemd promotion on FORGE |

## Contract differences

The common control surface—health, stats, config, check, block, and analytics—was preserved. Known differences that consumers must account for:

- production adds `POST /entry` and `GET /about/me`;
- the retained Worker has `GET /analytics/:worker`, while production exposes only the aggregate `/analytics` route;
- production window counters reset on process restart;
- production health exposes PostgreSQL connectivity;
- fleet integrations use registered `echo.traffic_shaper.*` capabilities rather than direct Worker bindings;
- production lifecycle and rollback are controlled by systemd and the staging smoke gate.

## Evidence snapshot

The documentation was grounded against the live runtime on 2026-07-26:

- service state: active;
- internal health: HTTP 200, `status: ok`, database connected;
- live route inventory: 13 HTTP endpoints;
- registered SDK inventory: 11 capabilities;
- live Python function inventory: 25 top-level functions;
- retained Worker inventory: 12 named helpers plus inline Hono handlers.
- retained Worker type-check: green; dependency audit reports known findings that require a separate tested remediation.

Hashes are operational evidence, not release identity. Capture and compare the deployed source hash immediately before a future reconciliation rather than relying on a value frozen in documentation.

## Runtime reconciliation gate

A dedicated follow-up build may make this repository authoritative only if it performs all of the following:

1. Capture the exact deployed source, unit, capability registration, smoke script, and tests without modifying production.
2. Secret-scan and redact configuration before committing.
3. Preserve the legacy Worker under an explicit archive path or tag.
4. Add reproducible Python dependency metadata and a works-after-clone development path.
5. Add syntax, lint, unit, integration, and live-contract checks to CI.
6. Boot the candidate build on a staging port with production-equivalent non-secret configuration.
7. Run the full live smoke suite, including allow, deliberate rate denial, block lifecycle, configuration lifecycle, security headers, and degraded dependency behavior.
8. Promote only after green staging results; health-check production and automatically restore the previous build on failure.
9. Commit and push the exact production artifact, then record its commit SHA in the service release metadata.

Until that gate is complete, documentation changes may merge here, but runtime releases must continue from the controlled live source with recoverable backups and staging-first verification.
