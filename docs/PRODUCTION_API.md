# Production API

This document describes the live FastAPI service on FORGE port 8194. The retained Worker has one additional historical route, `GET /analytics/:worker`; see [Migration status](MIGRATION_STATUS.md) before using or changing legacy code.

## Common behavior

- Content type is JSON unless otherwise noted.
- Invalid Pydantic request bodies return HTTP 422.
- Rate denials return HTTP 429 and a `Retry-After` header.
- Database failures on the critical `/check` path preserve the legacy fail-open behavior and return `reason: error_passthrough`.
- The health endpoint stays HTTP 200 when a dependency is degraded; callers must inspect `status` and `db_connected`.
- CORS and the service security-header policy are applied by middleware.

## Request models

### CheckBody

| Field | Type | Required | Meaning |
|---|---|---:|---|
| `ip` | string | yes | Client address used for IP blocks and counters |
| `api_key` | string or null | no | Optional caller key used for key blocks and independent rate tracking |
| `worker_name` | string | yes | Fleet worker whose rate configuration applies |

### ConfigBody

| Field | Type | Default | Meaning |
|---|---|---:|---|
| `worker_name` | string | required | Unique fleet worker identifier |
| `requests_per_minute` | integer | 60 | Per-IP minute limit |
| `requests_per_hour` | integer | 1000 | Per-IP hour limit |
| `burst_limit` | integer | 20 | Per-IP five-second burst limit |
| `priority_bypass` | integer | 0 | `1` bypasses rate windows for this worker |
| `enabled` | integer | 1 | `0` ignores the stored config and uses global defaults |

### BlockBody

| Field | Type | Default | Meaning |
|---|---|---:|---|
| `entity_type` | `ip` or `api_key` | required | Entity class to block |
| `entity_value` | string | required | Exact value to block |
| `reason` | string or null | `manual` | Operator-visible reason |
| `expires_in_hours` | integer or null | null | Relative TTL; null creates a permanent block |

## Routes

### GET /health

Liveness and database-connectivity probe. A healthy response contains:

```json
{
  "status": "ok",
  "service": "echo-traffic-shaper",
  "version": "1.0.0",
  "uptime_s": 3600,
  "db_connected": true,
  "timestamp": "2026-07-26T23:00:00+00:00"
}
```

Treat `status: degraded` or `db_connected: false` as a dependency incident even though the HTTP status remains 200.

### GET /

Small fleet-discovery response with the service name, status, and health-document pointer.

### GET /about/me

Returns service identity, version, uptime, purpose, and migration provenance. It is safe for fleet introspection and contains no secrets.

### GET /stats

Returns uptime, last-hour and last-24-hour totals, allowed and blocked counts, plus current rate-configuration and active-block counts.

### GET /analytics?range=hour|day

Returns per-worker traffic totals, average latency, unique IP counts, top IPs, and top denial reasons for the selected period. Any value other than `day` currently selects the one-hour window; callers should pass only `hour` or `day`.

### GET /config

Lists all per-worker rate configurations ordered by worker name.

### POST /config

Creates a worker configuration from `ConfigBody`. A duplicate `worker_name` returns HTTP 409; update an existing record with `PUT /config/{worker}`.

### PUT /config/{worker}

Updates an existing worker configuration. The live implementation merges omitted fields with the stored row and returns HTTP 404 when the worker does not exist.

### GET /blocked?active=true

Lists block records. The default returns permanent or unexpired entries. Pass `active=false` to include expired history.

### POST /block

Upserts an IP or API-key block from `BlockBody`. Repeating a request for the same `(entity_type, entity_value)` updates its reason and expiry, making the operation idempotent at the entity level. A configured brain notification is best-effort and never determines the HTTP result.

### DELETE /block/{block_id}

Deletes a block by PostgreSQL row ID. The operation returns success even when no row matched, so callers that need confirmation should re-read `/blocked`.

### POST /check

The critical rate-decision route. Example request:

```json
{
  "ip": "203.0.113.10",
  "worker_name": "example-worker"
}
```

Allowed response:

```json
{
  "allowed": true,
  "remaining_minute": 59,
  "remaining_hour": 999,
  "retry_after_s": 0,
  "blocked": false,
  "reason": "allowed"
}
```

Denied response, HTTP 429:

```json
{
  "allowed": false,
  "remaining_minute": 0,
  "remaining_hour": 0,
  "retry_after_s": 45,
  "blocked": false,
  "reason": "rate_limit_minute"
}
```

Decision reasons:

| Reason | Meaning |
|---|---|
| `allowed` | All applicable checks passed |
| `commander_priority_bypass` | The configured Commander key matched in constant time |
| `priority_bypass` | The worker configuration bypasses rate windows |
| `blocked:<reason>` | An active entity block matched |
| `rate_limit_minute` | Per-IP minute window exhausted |
| `rate_limit_hour` | Per-IP hour window exhausted |
| `burst_limit` | Per-IP five-second burst window exhausted |
| `api_key_rate_limit` | Optional API-key minute window exhausted |
| `error_passthrough` | Internal failure triggered legacy fail-open behavior |

### POST /entry

Writes an allowed audit row for non-check paths. It accepts a JSON object containing `ip` and `worker_name`; malformed or absent JSON degrades to an empty object and still returns `{ "ok": true }` after the best-effort log call.

## SDK capability map

Prefer these gate capabilities over direct port access:

| Capability | Tier | Route |
|---|---:|---|
| `echo.traffic_shaper.health` | 0 | `GET /health` |
| `echo.traffic_shaper.about` | 0 | `GET /about/me` |
| `echo.traffic_shaper.stats` | 0 | `GET /stats` |
| `echo.traffic_shaper.analytics` | 0 | `GET /analytics` |
| `echo.traffic_shaper.config.get` | 1 | `GET /config` |
| `echo.traffic_shaper.blocked` | 1 | `GET /blocked` |
| `echo.traffic_shaper.check` | 1 | `POST /check` |
| `echo.traffic_shaper.entry` | 1 | `POST /entry` |
| `echo.traffic_shaper.config.create` | 2 | `POST /config` |
| `echo.traffic_shaper.config.update` | 2 | `PUT /config/{worker}` |
| `echo.traffic_shaper.block` | 2 | `POST /block` |

All SDK envelopes require `params.command`. Tier-2 operations additionally require an administrative bypass reason that satisfies the gate policy. Secret material belongs in the gate or managed service environment, never inside source examples.

## Storage contract

| Table | Purpose | Important behavior |
|---|---|---|
| `traffic_shaper.rate_configs` | Worker limits and bypass flags | `worker_name` is unique |
| `traffic_shaper.blocked_entities` | Persistent IP and API-key blocks | `(entity_type, entity_value)` is unique |
| `traffic_shaper.traffic_log` | Immutable decision/audit history | Stores only an API-key fingerprint |
| `traffic_shaper.analytics_hourly` | Reserved hourly rollups | Live analytics currently query `traffic_log` |

The in-process rate-window store is not durable. A restart clears minute, hour, burst, and strike counters but does not remove PostgreSQL blocks or configuration.
