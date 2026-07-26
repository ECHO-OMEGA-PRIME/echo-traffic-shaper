# Echo Traffic Shaper

Echo Traffic Shaper is the fleet's central rate-decision, entity-blocking, and traffic-observability service. It gives callers a consistent decision contract before they admit work and preserves an auditable record of allowed and denied traffic.

## Deployment status

The production service is a FastAPI application on FORGE:

- systemd unit: `echo-traffic-shaper.service`
- working directory: `/home/forge/echo-traffic-shaper`
- internal address: `http://127.0.0.1:8194`
- persistence: PostgreSQL schema `traffic_shaper`
- fleet access: 11 `echo.traffic_shaper.*` SDK capabilities

The TypeScript/Hono Worker in [`src/index.ts`](src/index.ts) is the retained Cloudflare-era implementation. It is migration provenance, not the production deployment. The production Python source has not yet been reconciled into this repository; [Migration status](docs/MIGRATION_STATUS.md) records that boundary explicitly so an operator cannot deploy the wrong runtime by accident.

## What it does

`POST /check` evaluates a request in this order:

1. Match an active IP or API-key block.
2. Apply the Commander or per-worker priority bypass.
3. Load the worker's configured minute, hour, and burst limits.
4. Increment bounded in-memory counters.
5. Return an allow or deny decision with remaining quota and retry timing.
6. Write a traffic audit row and count repeated denials toward automatic blocking.

Ten rate-limit denials from one IP in ten minutes trigger a one-hour automatic block. Persistent configuration, block records, and traffic history live in PostgreSQL; the active rate windows are intentionally ephemeral and reset when the process restarts.

## Start here

Operators:

```bash
ssh forge "systemctl is-active echo-traffic-shaper.service"
ssh forge "curl --fail --silent http://127.0.0.1:8194/health"
```

SDK consumers should call the registered capability rather than addressing the port directly:

```json
{
  "envelope_version": 1,
  "capability": "echo.traffic_shaper.check",
  "params": {
    "command": "check",
    "ip": "203.0.113.10",
    "worker_name": "example-worker"
  }
}
```

Do not place credentials in source, shell history, examples, or logs. The SDK gate resolves fleet authentication; service secrets are supplied through the managed systemd environment.

## Documentation map

- [Production API](docs/PRODUCTION_API.md) — endpoints, request models, responses, decision semantics, and SDK mapping
- [Operations](docs/OPERATIONS.md) — health checks, tests, observability, configuration, incident triage, and safe deployment rules
- [Function reference](docs/FUNCTION_REFERENCE.md) — every function in the live FastAPI runtime and retained Worker
- [Migration status](docs/MIGRATION_STATUS.md) — authoritative runtime boundary, platform mapping, and reconciliation gate

## Repository layout

```text
.
├── src/index.ts              # retained Cloudflare Worker implementation
├── wrangler.toml             # legacy Worker bindings and schedule
├── package.json              # legacy TypeScript toolchain
├── README.md                 # operator entry point
└── docs/
    ├── FUNCTION_REFERENCE.md
    ├── MIGRATION_STATUS.md
    ├── OPERATIONS.md
    └── PRODUCTION_API.md
```

## Verification contract

A documentation change is ready to merge only when all of these are true:

- every documented production endpoint matches the live route table;
- every top-level live Python function appears in the function reference;
- every retained Worker helper and route appears in the function reference;
- internal Markdown links resolve;
- the legacy TypeScript source still type-checks;
- the live service reports `status: ok` and `db_connected: true`;
- the live Python unit suite and smoke test pass without a runtime edit.

The documentation-only workflow does not restart production. Runtime changes require a separate source-reconciliation build, staging boot, live smoke suite, promotion, and rollback gate.

## Security and privacy

- API keys are never stored in full in the traffic log; the service records only a short SHA-256 fingerprint.
- Management operations are exposed through tiered SDK capabilities. Tier-2 calls require the gate's administrative context.
- CORS is allowlisted and security headers are applied to every production response.
- Examples use reserved documentation IP ranges and synthetic worker names.
- Production credentials, client traffic, and private configuration are intentionally absent from this repository.

## License

Private ECHO OMEGA PRIME infrastructure. All rights reserved.
