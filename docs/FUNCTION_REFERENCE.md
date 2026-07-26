# Function reference

Coverage is derived from the live FORGE FastAPI source and the retained `src/index.ts` Worker. This document supplies a searchable contract for every named helper, lifecycle handler, and HTTP handler without changing runtime logic.

## Live FastAPI runtime

The production module has 25 top-level functions. All 25 are covered below.

### Infrastructure and lifecycle

| Function | Contract |
|---|---|
| `_db()` | Opens a PostgreSQL connection, commits on normal exit, and always closes it. Callers create their own cursors. |
| `_ensure_schema()` | Idempotently creates the `traffic_shaper` schema, four tables, and supporting indexes at startup. |
| `_notify_brain(kind, payload)` | Sends a best-effort asynchronous notification to the configured brain, swarm, or alert target. Missing targets and delivery failures never block the request path. |
| `_startup()` | Synchronous startup hook that ensures the database schema and prunes expired in-memory counters. |
| `_cors_and_security(request, call_next)` | HTTP middleware that calls the downstream handler, applies allowlisted CORS behavior, and sets the service security headers. |
| `_start_pruner()` | Asynchronous startup hook that launches a background loop to prune expired counter entries every 60 seconds. |

### Rate and audit helpers

| Function | Contract |
|---|---|
| `_hash_key(key)` | Returns the first 16 hexadecimal characters of a SHA-256 digest so API keys are never stored in full. |
| `_timing_safe_compare(a, b)` | Compares strings with a constant-time digest comparison for the Commander bypass check. |
| `_kv_increment(key, window_ms, limit)` | Updates a locked in-memory sliding-window record and returns count, allow state, remaining quota, and retry timing. |
| `_prune_kv()` | Removes expired entries from the in-process counter store under its lock. |
| `_log_traffic(db, ip, api_key, worker_name, allowed, reason, latency_ms)` | Writes one traffic-audit row with a key fingerprint. Logging errors are recorded but not raised into the caller. |
| `_check_auto_block(db, ip, worker_name)` | Counts rate-limit strikes and upserts a one-hour IP block after ten strikes in ten minutes. |

### HTTP handlers

| Function | Route | Contract |
|---|---|---|
| `health()` | `GET /health` | Returns liveness metadata and PostgreSQL connectivity. Uses a degraded body rather than crashing when the database probe fails. |
| `root()` | `GET /` | Returns the minimal service identity and status response. |
| `stats()` | `GET /stats` | Aggregates last-hour and last-24-hour decisions and reports configuration and active-block counts. |
| `analytics(range)` | `GET /analytics` | Aggregates traffic by worker, top IPs, and denial reasons for an hour or day. |
| `get_config()` | `GET /config` | Lists all worker rate configurations in stable worker-name order. |
| `create_config(b)` | `POST /config` | Inserts a new `ConfigBody`; maps uniqueness failure to HTTP 409. |
| `update_config(worker, b)` | `PUT /config/{worker}` | Merges supplied fields into an existing row and returns HTTP 404 when no row exists. |
| `get_blocked(active)` | `GET /blocked` | Lists active blocks by default or all block history when `active=false`. |
| `create_block(b)` | `POST /block` | Upserts an IP or API-key block, computes optional expiry, and emits a best-effort notification. |
| `delete_block(block_id)` | `DELETE /block/{block_id}` | Deletes a block row by ID and returns the requested ID. |
| `check_traffic(b, request)` | `POST /check` | Executes the block, bypass, and minute/hour/burst decision pipeline; audits the result; returns 429 on denial; and fails open on internal error. |
| `entry(request)` | `POST /entry` | Parses a lightweight audit event, tolerates missing JSON, and writes an allowed entry record. |
| `about_me()` | `GET /about/me` | Returns service identity, purpose, uptime, version, and migration provenance. |

### Request models

The live module also defines three Pydantic model classes:

- `CheckBody` — IP, optional API key, and worker name.
- `BlockBody` — entity type/value, reason, and optional expiry hours.
- `ConfigBody` — worker name, minute/hour/burst limits, priority-bypass flag, and enabled flag.

## Retained Cloudflare Worker

The TypeScript source is archival migration provenance. Its named helpers and scheduled handler are covered here; inline Hono route handlers are covered in the following table.

### Named helpers

| Function | Contract |
|---|---|
| `log(level, message, meta)` | Emits structured JSON diagnostics with timestamp, service, level, message, and metadata. |
| `json(data, status)` | Constructs a JSON `Response` with the requested status and content type. |
| `hourBucket(date)` | Formats a date into the Worker's UTC hour-bucket key. |
| `minuteBucket()` | Formats the current UTC minute into a counter key. |
| `ensureSchema(db)` | Creates the legacy D1 tables and indexes if absent. |
| `kvIncrement(kv, key, windowSeconds, limit)` | Reads and increments a legacy KV window counter with TTL and returns allow/remaining data. |
| `detectSpike(kv, currentCount)` | Updates exponential moving-average state and reports statistically unusual volume. |
| `authMiddleware(env)` | Creates the Hono middleware that validates configured management keys. |
| `hashKey(key)` | Produces the legacy SHA-256 key fingerprint. |
| `logTraffic(db, ip, apiKey, workerName, allowed, reason, latencyMs)` | Persists a legacy D1 traffic-audit row. |
| `checkAutoBlock(db, kv, ip, workerName)` | Tracks denial strikes and writes the legacy automatic IP block. |
| `handleScheduled(event, env)` | Runs the five-minute scheduled maintenance and analytics work for the Worker deployment. |

### Inline middleware and routes

| Handler | Contract |
|---|---|
| `app.use('*', ...)` | Applies request diagnostics, CORS, management authentication, error handling, and common response headers. |
| `GET /health` | Probes Worker bindings and reports service health. |
| `GET /` | Returns minimal Worker identity and status. |
| `GET /stats` | Aggregates legacy D1 traffic and configuration counts. |
| `GET /config` | Lists legacy D1 rate configurations. |
| `POST /config` | Creates a legacy rate configuration. |
| `PUT /config/:worker` | Updates a legacy rate configuration. |
| `POST /check` | Executes the Worker-era D1/KV rate decision pipeline. |
| `GET /blocked` | Lists Worker-era block records. |
| `POST /block` | Upserts a Worker-era block record. |
| `DELETE /block/:id` | Deletes a Worker-era block by ID. |
| `GET /analytics` | Returns Worker-wide traffic analytics. |
| `GET /analytics/:worker` | Returns analytics scoped to one worker; this route is not present in the live FastAPI runtime. |
| `app.onError(...)` | Converts uncaught Worker errors to a hardened JSON response. |
| `app.notFound(...)` | Returns the Worker JSON 404 response. |
| exported `fetch` | Delegates HTTP requests to the Hono application. |
| exported `scheduled` | Delegates cron events to `handleScheduled`. |

## Coverage acceptance

The documentation check extracts top-level Python function names and named TypeScript functions, then requires each name to appear in this file. Route decorators are separately compared with the production API document. At the time of this recovery, coverage is 25/25 live functions and 12/12 named Worker helpers, plus every inline Worker route and exported handler.
