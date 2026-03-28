/**
 * echo-traffic-shaper v1.0.0
 * Traffic shaping and rate limiting gateway for the ECHO fleet.
 *
 * Features:
 *  - Per-Worker configurable rate limits (req/min, req/hr, burst)
 *  - Per-IP sliding-window rate limiting via KV
 *  - Per-API-key rate limiting
 *  - Priority lanes (Commander traffic bypasses all limits)
 *  - DDoS spike detection using exponential moving average
 *  - Automatic + manual IP/key blocking
 *  - Traffic analytics (per-hour aggregation, top IPs, error rates)
 *  - 429 with Retry-After header for queuing semantics
 *
 * Cron: every 5 min — counter cleanup + spike detection
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Env {
  DB: D1Database;
  TRAFFIC_CACHE: KVNamespace;
  SHARED_BRAIN: Fetcher;
  SWARM_BRAIN: Fetcher;
  ALERT_ROUTER: Fetcher;
  ECHO_API_KEY: string;
  VERSION: string;
}

interface RateConfig {
  id: number;
  worker_name: string;
  requests_per_minute: number;
  requests_per_hour: number;
  burst_limit: number;
  priority_bypass: number;
  enabled: number;
  created_at: string;
  updated_at: string;
}

interface BlockedEntity {
  id: number;
  entity_type: string;
  entity_value: string;
  reason: string;
  blocked_by: string;
  expires_at: string | null;
  created_at: string;
}

interface CheckRequest {
  ip: string;
  api_key?: string;
  worker_name: string;
}

interface CheckResponse {
  allowed: boolean;
  remaining_minute: number;
  remaining_hour: number;
  retry_after_s: number;
  blocked: boolean;
  reason: string;
}

interface AnalyticsRow {
  hour_bucket: string;
  worker_name: string;
  total_requests: number;
  allowed_requests: number;
  blocked_requests: number;
  unique_ips: number;
  avg_latency_ms: number;
  error_count: number;
}

// ---------------------------------------------------------------------------
// Globals / helpers
// ---------------------------------------------------------------------------

const BOOT_TIME = Date.now();
const COMMANDER_KEYS = new Set<string>();

/** Structured JSON logger */
function log(level: string, message: string, meta: Record<string, unknown> = {}): void {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    service: 'echo-traffic-shaper',
    message,
    ...meta,
  };
  if (level === 'error' || level === 'fatal') {
    console.error(JSON.stringify(entry));
  } else {
    console.log(JSON.stringify(entry));
  }
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}

function hourBucket(date?: Date): string {
  const d = date ?? new Date();
  return d.toISOString().slice(0, 13) + ':00:00Z';
}

function minuteBucket(): string {
  const d = new Date();
  return d.toISOString().slice(0, 16) + ':00Z';
}

// ---------------------------------------------------------------------------
// D1 Schema bootstrap
// ---------------------------------------------------------------------------

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS rate_configs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  worker_name TEXT NOT NULL UNIQUE,
  requests_per_minute INTEGER NOT NULL DEFAULT 60,
  requests_per_hour INTEGER NOT NULL DEFAULT 1000,
  burst_limit INTEGER NOT NULL DEFAULT 20,
  priority_bypass INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS blocked_entities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_type TEXT NOT NULL,
  entity_value TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT 'manual',
  blocked_by TEXT NOT NULL DEFAULT 'system',
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(entity_type, entity_value)
);

CREATE TABLE IF NOT EXISTS traffic_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  api_key_hash TEXT,
  worker_name TEXT NOT NULL,
  allowed INTEGER NOT NULL DEFAULT 1,
  reason TEXT,
  latency_ms INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_traffic_log_created ON traffic_log(created_at);
CREATE INDEX IF NOT EXISTS idx_traffic_log_worker ON traffic_log(worker_name, created_at);
CREATE INDEX IF NOT EXISTS idx_traffic_log_ip ON traffic_log(ip, created_at);

CREATE TABLE IF NOT EXISTS analytics_hourly (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hour_bucket TEXT NOT NULL,
  worker_name TEXT NOT NULL DEFAULT '_global',
  total_requests INTEGER NOT NULL DEFAULT 0,
  allowed_requests INTEGER NOT NULL DEFAULT 0,
  blocked_requests INTEGER NOT NULL DEFAULT 0,
  unique_ips INTEGER NOT NULL DEFAULT 0,
  avg_latency_ms REAL NOT NULL DEFAULT 0,
  error_count INTEGER NOT NULL DEFAULT 0,
  top_ips TEXT DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(hour_bucket, worker_name)
);
CREATE INDEX IF NOT EXISTS idx_analytics_hourly_bucket ON analytics_hourly(hour_bucket);
`;

async function ensureSchema(db: D1Database): Promise<void> {
  const statements = SCHEMA_SQL.split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  for (const stmt of statements) {
    try {
      await db.prepare(stmt).run();
    } catch {
      // table/index already exists — fine
    }
  }
}

// ---------------------------------------------------------------------------
// KV sliding window helpers
// ---------------------------------------------------------------------------

interface WindowCounter {
  count: number;
  window_start: number;
}

async function kvIncrement(
  kv: KVNamespace,
  key: string,
  windowMs: number,
  limit: number,
): Promise<{ count: number; allowed: boolean; remaining: number; retryAfterS: number }> {
  const raw = await kv.get(key, 'json') as WindowCounter | null;
  const now = Date.now();
  // Cloudflare KV minimum TTL is 60 seconds
  const minTtl = 60;

  if (!raw || now - raw.window_start >= windowMs) {
    // New window
    const ttl = Math.max(minTtl, Math.ceil(windowMs / 1000) + 10);
    await kv.put(key, JSON.stringify({ count: 1, window_start: now } satisfies WindowCounter), {
      expirationTtl: ttl,
    });
    return { count: 1, allowed: true, remaining: limit - 1, retryAfterS: 0 };
  }

  const newCount = raw.count + 1;
  const elapsed = now - raw.window_start;
  const windowRemaining = Math.max(0, Math.ceil((windowMs - elapsed) / 1000));

  if (newCount > limit) {
    return { count: raw.count, allowed: false, remaining: 0, retryAfterS: Math.max(windowRemaining, 1) };
  }

  const remainTtl = Math.max(minTtl, Math.ceil((windowMs - elapsed) / 1000) + 10);
  await kv.put(key, JSON.stringify({ count: newCount, window_start: raw.window_start } satisfies WindowCounter), {
    expirationTtl: remainTtl,
  });
  return { count: newCount, allowed: true, remaining: limit - newCount, retryAfterS: 0 };
}

// ---------------------------------------------------------------------------
// Spike detection (EMA-based)
// ---------------------------------------------------------------------------

interface SpikeState {
  ema: number;
  variance: number;
  last_count: number;
  updated_at: number;
}

const SPIKE_ALPHA = 0.3;
const SPIKE_THRESHOLD_SIGMA = 3.0;

async function detectSpike(kv: KVNamespace, currentCount: number): Promise<{ spike: boolean; ema: number; threshold: number }> {
  const key = 'spike:global:state';
  const raw = await kv.get(key, 'json') as SpikeState | null;

  if (!raw) {
    const state: SpikeState = { ema: currentCount, variance: 0, last_count: currentCount, updated_at: Date.now() };
    await kv.put(key, JSON.stringify(state), { expirationTtl: 86400 });
    return { spike: false, ema: currentCount, threshold: currentCount * 3 };
  }

  const newEma = SPIKE_ALPHA * currentCount + (1 - SPIKE_ALPHA) * raw.ema;
  const diff = currentCount - newEma;
  const newVariance = SPIKE_ALPHA * diff * diff + (1 - SPIKE_ALPHA) * raw.variance;
  const stddev = Math.sqrt(newVariance);
  const threshold = newEma + SPIKE_THRESHOLD_SIGMA * stddev;
  const spike = currentCount > threshold && currentCount > 10;

  const state: SpikeState = { ema: newEma, variance: newVariance, last_count: currentCount, updated_at: Date.now() };
  await kv.put(key, JSON.stringify(state), { expirationTtl: 86400 });

  return { spike, ema: newEma, threshold };
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

function authMiddleware(env: Env) {
  return async (c: any, next: () => Promise<void>) => {
    const path = new URL(c.req.url).pathname;
    if (path === '/health' || path === '/') {
      return next();
    }

    const apiKey = c.req.header('X-Echo-API-Key') ?? c.req.header('x-echo-api-key') ?? '';
    if (!apiKey || apiKey !== env.ECHO_API_KEY) {
      log('warn', 'Auth rejected', { path, ip: c.req.header('CF-Connecting-IP') });
      return json({ error: 'Unauthorized', message: 'Invalid or missing X-Echo-API-Key header' }, 401);
    }

    // Track Commander keys for priority bypass
    if (apiKey === env.ECHO_API_KEY) {
      COMMANDER_KEYS.add(apiKey);
    }

    return next();
  };
}

// ---------------------------------------------------------------------------
// Hono App
// ---------------------------------------------------------------------------

const app = new Hono<{ Bindings: Env }>();

app.use('*', cors({ origin: '*', allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'] }));

// Security headers middleware
app.use('*', async (c, next) => {
  await next();
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('X-XSS-Protection', '1; mode=block');
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
});

// Auth on all non-health routes
app.use('*', async (c, next) => {
  const path = new URL(c.req.url).pathname;
  if (path === '/health' || path === '/') return next();

  const apiKey = c.req.header('X-Echo-API-Key') ?? c.req.header('x-echo-api-key') ?? '';
  if (!apiKey || apiKey !== c.env.ECHO_API_KEY) {
    log('warn', 'Auth rejected', { path, ip: c.req.header('CF-Connecting-IP') ?? 'unknown' });
    return json({ error: 'Unauthorized', message: 'Invalid or missing X-Echo-API-Key header' }, 401);
  }
  return next();
});

// ---- Health ----
app.get('/health', async (c) => {
  let dbOk = false;
  try {
    await ensureSchema(c.env.DB);
    const r = await c.env.DB.prepare('SELECT 1 as ok').first();
    dbOk = r?.ok === 1;
  } catch (e: any) {
    log('error', 'DB health check failed', { error: e.message });
  }

  return json({
    status: dbOk ? 'ok' : 'degraded',
    version: c.env.VERSION || '1.0.0',
    service: 'echo-traffic-shaper',
    uptime_s: Math.floor((Date.now() - BOOT_TIME) / 1000),
    db_connected: dbOk,
    timestamp: new Date().toISOString(),
  });
});

app.get('/', (c) => json({ service: 'echo-traffic-shaper', status: 'ok', docs: '/health' }));

// ---- Stats ----
app.get('/stats', async (c) => {
  const db = c.env.DB;
  await ensureSchema(db);

  const now = new Date();
  const hourAgo = new Date(now.getTime() - 3600000).toISOString();
  const dayAgo = new Date(now.getTime() - 86400000).toISOString();

  const [hourStats, dayStats, configCount, blockedCount] = await Promise.all([
    db.prepare('SELECT COUNT(*) as cnt, SUM(CASE WHEN allowed=1 THEN 1 ELSE 0 END) as allowed, SUM(CASE WHEN allowed=0 THEN 1 ELSE 0 END) as blocked FROM traffic_log WHERE created_at >= ?').bind(hourAgo).first(),
    db.prepare('SELECT COUNT(*) as cnt, SUM(CASE WHEN allowed=1 THEN 1 ELSE 0 END) as allowed, SUM(CASE WHEN allowed=0 THEN 1 ELSE 0 END) as blocked FROM traffic_log WHERE created_at >= ?').bind(dayAgo).first(),
    db.prepare('SELECT COUNT(*) as cnt FROM rate_configs').first(),
    db.prepare("SELECT COUNT(*) as cnt FROM blocked_entities WHERE expires_at IS NULL OR expires_at > datetime('now')").first(),
  ]);

  return json({
    service: 'echo-traffic-shaper',
    version: c.env.VERSION || '1.0.0',
    uptime_s: Math.floor((Date.now() - BOOT_TIME) / 1000),
    last_hour: {
      total: hourStats?.cnt ?? 0,
      allowed: hourStats?.allowed ?? 0,
      blocked: hourStats?.blocked ?? 0,
    },
    last_24h: {
      total: dayStats?.cnt ?? 0,
      allowed: dayStats?.allowed ?? 0,
      blocked: dayStats?.blocked ?? 0,
    },
    rate_configs: configCount?.cnt ?? 0,
    active_blocks: blockedCount?.cnt ?? 0,
    timestamp: new Date().toISOString(),
  });
});

// ---- Rate Config CRUD ----
app.get('/config', async (c) => {
  const db = c.env.DB;
  await ensureSchema(db);
  const rows = await db.prepare('SELECT * FROM rate_configs ORDER BY worker_name').all();
  return json({ configs: rows.results, count: rows.results.length });
});

app.post('/config', async (c) => {
  const db = c.env.DB;
  await ensureSchema(db);

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }

  const { worker_name, requests_per_minute, requests_per_hour, burst_limit, priority_bypass } = body;
  if (!worker_name) {
    return json({ error: 'worker_name is required' }, 400);
  }

  const rpm = requests_per_minute ?? 60;
  const rph = requests_per_hour ?? 1000;
  const burst = burst_limit ?? 20;
  const prio = priority_bypass ?? 0;

  try {
    await db
      .prepare(
        `INSERT INTO rate_configs (worker_name, requests_per_minute, requests_per_hour, burst_limit, priority_bypass)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(worker_name, rpm, rph, burst, prio)
      .run();

    log('info', 'Rate config created', { worker_name, rpm, rph, burst });
    return json({ success: true, worker_name, requests_per_minute: rpm, requests_per_hour: rph, burst_limit: burst }, 201);
  } catch (e: any) {
    if (e.message?.includes('UNIQUE')) {
      return json({ error: `Config for worker '${worker_name}' already exists. Use PUT to update.` }, 409);
    }
    log('error', 'Failed to create config', { error: e.message });
    return json({ error: 'Database error', detail: e.message }, 500);
  }
});

app.put('/config/:worker', async (c) => {
  const db = c.env.DB;
  await ensureSchema(db);
  const workerName = c.req.param('worker');

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }

  const existing = await db.prepare('SELECT * FROM rate_configs WHERE worker_name = ?').bind(workerName).first() as RateConfig | null;
  if (!existing) {
    return json({ error: `Config for worker '${workerName}' not found` }, 404);
  }

  const rpm = body.requests_per_minute ?? existing.requests_per_minute;
  const rph = body.requests_per_hour ?? existing.requests_per_hour;
  const burst = body.burst_limit ?? existing.burst_limit;
  const prio = body.priority_bypass ?? existing.priority_bypass;
  const enabled = body.enabled ?? existing.enabled;

  await db
    .prepare(
      `UPDATE rate_configs SET requests_per_minute=?, requests_per_hour=?, burst_limit=?, priority_bypass=?, enabled=?, updated_at=datetime('now') WHERE worker_name=?`,
    )
    .bind(rpm, rph, burst, prio, enabled, workerName)
    .run();

  log('info', 'Rate config updated', { worker_name: workerName, rpm, rph, burst });
  return json({ success: true, worker_name: workerName, requests_per_minute: rpm, requests_per_hour: rph, burst_limit: burst, enabled });
});

// ---- Rate Limit Check (core feature) ----
app.post('/check', async (c) => {
  try {
  const db = c.env.DB;
  const kv = c.env.TRAFFIC_CACHE;
  await ensureSchema(db);

  let body: CheckRequest;
  try {
    body = await c.req.json() as CheckRequest;
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }

  const { ip, api_key, worker_name } = body;
  if (!ip || !worker_name) {
    return json({ error: 'ip and worker_name are required' }, 400);
  }

  const startMs = Date.now();

  // 1. Check if IP or key is blocked
  let blocked: BlockedEntity | null = null;
  if (api_key) {
    blocked = await db
      .prepare(
        "SELECT * FROM blocked_entities WHERE entity_value IN (?, ?) AND (expires_at IS NULL OR expires_at > datetime('now')) LIMIT 1",
      )
      .bind(ip, api_key)
      .first() as BlockedEntity | null;
  } else {
    blocked = await db
      .prepare(
        "SELECT * FROM blocked_entities WHERE entity_value = ? AND (expires_at IS NULL OR expires_at > datetime('now')) LIMIT 1",
      )
      .bind(ip)
      .first() as BlockedEntity | null;
  }

  if (blocked) {
    await logTraffic(db, ip, api_key, worker_name, false, `blocked:${blocked.reason}`, Date.now() - startMs);
    const resp: CheckResponse = {
      allowed: false,
      remaining_minute: 0,
      remaining_hour: 0,
      retry_after_s: 300,
      blocked: true,
      reason: `Entity blocked: ${blocked.reason}`,
    };
    return json(resp, 429);
  }

  // 2. Commander priority bypass
  if (api_key && api_key === c.env.ECHO_API_KEY) {
    await logTraffic(db, ip, api_key, worker_name, true, 'commander_bypass', Date.now() - startMs);
    const resp: CheckResponse = {
      allowed: true,
      remaining_minute: 9999,
      remaining_hour: 99999,
      retry_after_s: 0,
      blocked: false,
      reason: 'commander_priority_bypass',
    };
    return json(resp);
  }

  // 3. Load worker config (or use defaults)
  const config = await db
    .prepare('SELECT * FROM rate_configs WHERE worker_name = ? AND enabled = 1')
    .bind(worker_name)
    .first() as RateConfig | null;

  const rpm = config?.requests_per_minute ?? 60;
  const rph = config?.requests_per_hour ?? 1000;
  const burstLimit = config?.burst_limit ?? 20;

  // 4. Per-IP sliding window check (minute)
  const minuteKey = `rl:ip:min:${ip}:${worker_name}`;
  const minuteResult = await kvIncrement(kv, minuteKey, 60_000, rpm);

  // 5. Per-IP sliding window check (hour)
  const hourKey = `rl:ip:hr:${ip}:${worker_name}`;
  const hourResult = await kvIncrement(kv, hourKey, 3_600_000, rph);

  // 6. Burst detection (last 5 seconds)
  const burstKey = `rl:burst:${ip}:${worker_name}`;
  const burstResult = await kvIncrement(kv, burstKey, 5_000, burstLimit);

  // 7. Per-API-key rate limit (if provided)
  let keyAllowed = true;
  let keyRemaining = 9999;
  if (api_key) {
    const keyHash = await hashKey(api_key);
    const keyMinuteKey = `rl:key:min:${keyHash}:${worker_name}`;
    const keyResult = await kvIncrement(kv, keyMinuteKey, 60_000, rpm * 2);
    keyAllowed = keyResult.allowed;
    keyRemaining = keyResult.remaining;
  }

  const allowed = minuteResult.allowed && hourResult.allowed && burstResult.allowed && keyAllowed;
  const retryAfter = Math.max(minuteResult.retryAfterS, hourResult.retryAfterS, burstResult.allowed ? 0 : 5);

  let reason = 'allowed';
  if (!allowed) {
    if (!minuteResult.allowed) reason = 'rate_limit_minute';
    else if (!hourResult.allowed) reason = 'rate_limit_hour';
    else if (!burstResult.allowed) reason = 'burst_limit';
    else if (!keyAllowed) reason = 'api_key_rate_limit';
  }

  await logTraffic(db, ip, api_key, worker_name, allowed, reason, Date.now() - startMs);

  // 8. Auto-block if repeatedly hitting limits
  if (!allowed) {
    await checkAutoBlock(db, kv, ip, worker_name);
  }

  const resp: CheckResponse = {
    allowed,
    remaining_minute: minuteResult.remaining,
    remaining_hour: hourResult.remaining,
    retry_after_s: retryAfter,
    blocked: false,
    reason,
  };

  const status = allowed ? 200 : 429;
  const headers: Record<string, string> = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' };
  if (!allowed) {
    headers['Retry-After'] = String(retryAfter);
  }

  return new Response(JSON.stringify(resp), { status, headers });

  } catch (e: any) {
    log('error', 'Check endpoint failed', { error: e.message, stack: e.stack });
    return json({ error: 'Internal error', detail: e.message, allowed: true, remaining_minute: 0, remaining_hour: 0, retry_after_s: 0, blocked: false, reason: 'error_passthrough' }, 500);
  }
});

// ---- Blocked entities ----
app.get('/blocked', async (c) => {
  const db = c.env.DB;
  await ensureSchema(db);

  const active = c.req.query('active') !== 'false';
  let query = 'SELECT * FROM blocked_entities';
  if (active) {
    query += " WHERE expires_at IS NULL OR expires_at > datetime('now')";
  }
  query += ' ORDER BY created_at DESC LIMIT 200';

  const rows = await db.prepare(query).all();
  return json({ blocked: rows.results, count: rows.results.length });
});

app.post('/block', async (c) => {
  const db = c.env.DB;
  await ensureSchema(db);

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }

  const { entity_type, entity_value, reason, expires_in_hours } = body;
  if (!entity_type || !entity_value) {
    return json({ error: 'entity_type (ip|api_key) and entity_value are required' }, 400);
  }

  if (!['ip', 'api_key'].includes(entity_type)) {
    return json({ error: "entity_type must be 'ip' or 'api_key'" }, 400);
  }

  const expiresAt = expires_in_hours
    ? new Date(Date.now() + expires_in_hours * 3600000).toISOString()
    : null;

  try {
    await db
      .prepare(
        'INSERT OR REPLACE INTO blocked_entities (entity_type, entity_value, reason, blocked_by, expires_at) VALUES (?, ?, ?, ?, ?)',
      )
      .bind(entity_type, entity_value, reason ?? 'manual', 'commander', expiresAt)
      .run();

    // Also set in KV for fast lookup
    await c.env.TRAFFIC_CACHE.put(
      `block:${entity_type}:${entity_value}`,
      JSON.stringify({ reason: reason ?? 'manual', expires_at: expiresAt }),
      { expirationTtl: expires_in_hours ? expires_in_hours * 3600 : 86400 * 365 },
    );

    log('info', 'Entity blocked', { entity_type, entity_value, reason });

    // Notify Shared Brain
    try {
      await c.env.SHARED_BRAIN.fetch('https://brain/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          instance_id: 'echo-traffic-shaper',
          role: 'system',
          content: `SECURITY: Blocked ${entity_type} ${entity_value} — reason: ${reason ?? 'manual'}`,
          importance: 8,
          tags: ['security', 'block', 'traffic-shaper'],
        }),
      });
    } catch {
      // Best effort
    }

    return json({ success: true, entity_type, entity_value, expires_at: expiresAt }, 201);
  } catch (e: any) {
    log('error', 'Failed to block entity', { error: e.message });
    return json({ error: 'Database error', detail: e.message }, 500);
  }
});

app.delete('/block/:id', async (c) => {
  const db = c.env.DB;
  await ensureSchema(db);
  const id = parseInt(c.req.param('id'), 10);

  if (isNaN(id)) {
    return json({ error: 'Invalid block ID' }, 400);
  }

  const existing = await db.prepare('SELECT * FROM blocked_entities WHERE id = ?').bind(id).first() as BlockedEntity | null;
  if (!existing) {
    return json({ error: 'Block entry not found' }, 404);
  }

  await db.prepare('DELETE FROM blocked_entities WHERE id = ?').bind(id).run();

  // Remove from KV
  await c.env.TRAFFIC_CACHE.delete(`block:${existing.entity_type}:${existing.entity_value}`);

  log('info', 'Entity unblocked', { id, entity_type: existing.entity_type, entity_value: existing.entity_value });
  return json({ success: true, unblocked: existing.entity_value });
});

// ---- Analytics ----
app.get('/analytics', async (c) => {
  const db = c.env.DB;
  await ensureSchema(db);

  const range = c.req.query('range') ?? 'hour';
  const since = range === 'day'
    ? new Date(Date.now() - 86400000).toISOString()
    : new Date(Date.now() - 3600000).toISOString();

  // Aggregate from traffic_log
  const summary = await db
    .prepare(
      `SELECT
        worker_name,
        COUNT(*) as total,
        SUM(CASE WHEN allowed=1 THEN 1 ELSE 0 END) as allowed,
        SUM(CASE WHEN allowed=0 THEN 1 ELSE 0 END) as blocked,
        AVG(latency_ms) as avg_latency_ms,
        COUNT(DISTINCT ip) as unique_ips
       FROM traffic_log
       WHERE created_at >= ?
       GROUP BY worker_name
       ORDER BY total DESC`,
    )
    .bind(since)
    .all();

  // Top IPs
  const topIps = await db
    .prepare(
      `SELECT ip, COUNT(*) as cnt, SUM(CASE WHEN allowed=0 THEN 1 ELSE 0 END) as blocked_cnt
       FROM traffic_log
       WHERE created_at >= ?
       GROUP BY ip
       ORDER BY cnt DESC
       LIMIT 20`,
    )
    .bind(since)
    .all();

  // Top blocked reasons
  const topReasons = await db
    .prepare(
      `SELECT reason, COUNT(*) as cnt
       FROM traffic_log
       WHERE created_at >= ? AND allowed = 0
       GROUP BY reason
       ORDER BY cnt DESC
       LIMIT 10`,
    )
    .bind(since)
    .all();

  // Hourly breakdown
  const hourly = await db
    .prepare(
      `SELECT * FROM analytics_hourly
       WHERE hour_bucket >= ?
       ORDER BY hour_bucket DESC
       LIMIT 48`,
    )
    .bind(since.slice(0, 13) + ':00:00Z')
    .all();

  return json({
    range,
    since,
    by_worker: summary.results,
    top_ips: topIps.results,
    top_blocked_reasons: topReasons.results,
    hourly: hourly.results,
    generated_at: new Date().toISOString(),
  });
});

app.get('/analytics/:worker', async (c) => {
  const db = c.env.DB;
  await ensureSchema(db);
  const workerName = c.req.param('worker');

  const range = c.req.query('range') ?? 'hour';
  const since = range === 'day'
    ? new Date(Date.now() - 86400000).toISOString()
    : new Date(Date.now() - 3600000).toISOString();

  const [stats, topIps, recentBlocked] = await Promise.all([
    db
      .prepare(
        `SELECT
          COUNT(*) as total,
          SUM(CASE WHEN allowed=1 THEN 1 ELSE 0 END) as allowed,
          SUM(CASE WHEN allowed=0 THEN 1 ELSE 0 END) as blocked,
          AVG(latency_ms) as avg_latency_ms,
          COUNT(DISTINCT ip) as unique_ips
         FROM traffic_log
         WHERE worker_name = ? AND created_at >= ?`,
      )
      .bind(workerName, since)
      .first(),
    db
      .prepare(
        `SELECT ip, COUNT(*) as cnt
         FROM traffic_log
         WHERE worker_name = ? AND created_at >= ?
         GROUP BY ip ORDER BY cnt DESC LIMIT 10`,
      )
      .bind(workerName, since)
      .all(),
    db
      .prepare(
        `SELECT ip, reason, created_at
         FROM traffic_log
         WHERE worker_name = ? AND allowed = 0 AND created_at >= ?
         ORDER BY created_at DESC LIMIT 20`,
      )
      .bind(workerName, since)
      .all(),
  ]);

  return json({
    worker_name: workerName,
    range,
    since,
    stats,
    top_ips: topIps.results,
    recent_blocked: recentBlocked.results,
    generated_at: new Date().toISOString(),
  });
});

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

async function hashKey(key: string): Promise<string> {
  const encoded = new TextEncoder().encode(key);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  const hashArray = new Uint8Array(hashBuffer);
  return Array.from(hashArray.slice(0, 8))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function logTraffic(
  db: D1Database,
  ip: string,
  apiKey: string | undefined,
  workerName: string,
  allowed: boolean,
  reason: string,
  latencyMs: number,
): Promise<void> {
  try {
    const keyHash = apiKey ? await hashKey(apiKey) : null;
    await db
      .prepare('INSERT INTO traffic_log (ip, api_key_hash, worker_name, allowed, reason, latency_ms) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(ip, keyHash, workerName, allowed ? 1 : 0, reason, latencyMs)
      .run();
  } catch (e: any) {
    log('error', 'Failed to log traffic', { error: e.message });
  }
}

async function checkAutoBlock(db: D1Database, kv: KVNamespace, ip: string, workerName: string): Promise<void> {
  const counterKey = `autoblock:strikes:${ip}`;
  const raw = await kv.get(counterKey, 'json') as { count: number; first_strike: number } | null;
  const now = Date.now();

  if (!raw) {
    await kv.put(counterKey, JSON.stringify({ count: 1, first_strike: now }), { expirationTtl: 600 });
    return;
  }

  const newCount = raw.count + 1;

  // 10 strikes in 10 minutes = auto-block for 1 hour
  if (newCount >= 10 && now - raw.first_strike <= 600_000) {
    const expiresAt = new Date(now + 3600_000).toISOString();
    try {
      await db
        .prepare(
          'INSERT OR REPLACE INTO blocked_entities (entity_type, entity_value, reason, blocked_by, expires_at) VALUES (?, ?, ?, ?, ?)',
        )
        .bind('ip', ip, `auto_block:${newCount}_strikes_in_10min:${workerName}`, 'system', expiresAt)
        .run();

      await kv.put(`block:ip:${ip}`, JSON.stringify({ reason: 'auto_block', expires_at: expiresAt }), {
        expirationTtl: 3600,
      });

      log('warn', 'Auto-blocked IP', { ip, strikes: newCount, worker_name: workerName, expires_at: expiresAt });

      // Reset strike counter
      await kv.delete(counterKey);
    } catch (e: any) {
      log('error', 'Auto-block failed', { error: e.message, ip });
    }
  } else {
    await kv.put(counterKey, JSON.stringify({ count: newCount, first_strike: raw.first_strike }), { expirationTtl: 600 });
  }
}

// ---------------------------------------------------------------------------
// Cron handler — every 5 minutes
// ---------------------------------------------------------------------------

async function handleScheduled(event: ScheduledEvent, env: Env): Promise<void> {
  log('info', 'Cron triggered', { cron: event.cron, scheduledTime: new Date(event.scheduledTime).toISOString() });

  try {
    await ensureSchema(env.DB);

    // 1. Aggregate hourly analytics
    const bucket = hourBucket();
    const prevBucket = hourBucket(new Date(Date.now() - 3600000));

    const stats = await env.DB
      .prepare(
        `SELECT
          worker_name,
          COUNT(*) as total,
          SUM(CASE WHEN allowed=1 THEN 1 ELSE 0 END) as allowed,
          SUM(CASE WHEN allowed=0 THEN 1 ELSE 0 END) as blocked,
          COUNT(DISTINCT ip) as unique_ips,
          AVG(latency_ms) as avg_latency
         FROM traffic_log
         WHERE created_at >= ?
         GROUP BY worker_name`,
      )
      .bind(prevBucket)
      .all();

    for (const row of stats.results as any[]) {
      await env.DB
        .prepare(
          `INSERT OR REPLACE INTO analytics_hourly
           (hour_bucket, worker_name, total_requests, allowed_requests, blocked_requests, unique_ips, avg_latency_ms, error_count)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(bucket, row.worker_name, row.total, row.allowed, row.blocked, row.unique_ips, row.avg_latency ?? 0, row.blocked)
        .run();
    }

    // Also store global aggregate
    const global = await env.DB
      .prepare(
        `SELECT COUNT(*) as total FROM traffic_log WHERE created_at >= ?`,
      )
      .bind(new Date(Date.now() - 300_000).toISOString())
      .first();

    const recentCount = (global?.total as number) ?? 0;

    // 2. Spike detection
    const spikeResult = await detectSpike(env.TRAFFIC_CACHE, recentCount);
    if (spikeResult.spike) {
      log('warn', 'SPIKE DETECTED', {
        current_5min: recentCount,
        ema: Math.round(spikeResult.ema),
        threshold: Math.round(spikeResult.threshold),
      });

      // Notify via Shared Brain
      try {
        await env.SHARED_BRAIN.fetch('https://brain/ingest', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            instance_id: 'echo-traffic-shaper',
            role: 'system',
            content: `ALERT: Traffic spike detected — ${recentCount} requests in 5min (EMA: ${Math.round(spikeResult.ema)}, threshold: ${Math.round(spikeResult.threshold)})`,
            importance: 9,
            tags: ['alert', 'ddos', 'spike', 'traffic-shaper'],
          }),
        });
      } catch {
        // Best effort
      }

      // MoltBook post
      try {
        await env.SWARM_BRAIN.fetch('https://swarm/moltbook/post', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            author_id: 'echo-traffic-shaper',
            author_name: 'Traffic Shaper',
            author_type: 'worker',
            content: `SPIKE ALERT: ${recentCount} reqs/5min detected (normal: ~${Math.round(spikeResult.ema)}). Monitoring.`,
            mood: 'alert',
            tags: ['security', 'ddos', 'spike'],
          }),
        });
      } catch {
        // Best effort
      }
    }

    // 3. Expire old blocks
    await env.DB
      .prepare("DELETE FROM blocked_entities WHERE expires_at IS NOT NULL AND expires_at < datetime('now')")
      .run();

    // 4. Prune old traffic logs (keep 48 hours)
    const pruneDate = new Date(Date.now() - 48 * 3600000).toISOString();
    await env.DB.prepare('DELETE FROM traffic_log WHERE created_at < ?').bind(pruneDate).run();

    // 5. Prune old analytics (keep 30 days)
    const analyticsPrune = new Date(Date.now() - 30 * 86400000).toISOString();
    await env.DB.prepare('DELETE FROM analytics_hourly WHERE hour_bucket < ?').bind(analyticsPrune).run();

    log('info', 'Cron complete', {
      analytics_rows: stats.results.length,
      spike: spikeResult.spike,
      recent_5min: recentCount,
    });
  } catch (e: any) {
    log('error', 'Cron failed', { error: e.message, stack: e.stack });
  }
}

// ---------------------------------------------------------------------------
// Worker export
// ---------------------------------------------------------------------------


app.onError((err, c) => {
  if (err.message?.includes('JSON')) {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  console.error(`[echo-traffic-shaper] ${err.message}`);
  return c.json({ error: 'Internal server error' }, 500);
});

app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

export default {
  fetch: app.fetch,
  scheduled: handleScheduled,
};
