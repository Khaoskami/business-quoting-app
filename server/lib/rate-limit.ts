import type { Context, MiddlewareHandler } from 'hono';

// Lightweight sliding-window rate limiter for the general /api/* chain.
// better-auth already rate-limits /api/auth/*; this covers everything else.
//
// State is in-memory and per-process: it does NOT hold across multiple
// replicas or survive restarts. If the app ever scales past a single
// replica, this needs a shared store (e.g. Redis) instead.

const WINDOW_MS = 60_000;
const GENERAL_MAX = 300;      // requests per key per window across /api/*
const PROFILE_WRITE_MAX = 20; // profile writes carry a ~1.6MB base64 logo body

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH']);

const buckets = new Map<string, number[]>();

// Periodically drop idle keys so the Map can't grow unbounded.
let lastSweep = 0;
function sweep(now: number) {
  if (now - lastSweep < WINDOW_MS) return;
  lastSweep = now;
  for (const [key, ts] of buckets) {
    while (ts.length && ts[0] <= now - WINDOW_MS) ts.shift();
    if (ts.length === 0) buckets.delete(key);
  }
}

/** Records a hit against `key`; returns false when the window is full. */
function hit(key: string, max: number, now: number): boolean {
  let ts = buckets.get(key);
  if (!ts) { ts = []; buckets.set(key, ts); }
  while (ts.length && ts[0] <= now - WINDOW_MS) ts.shift();
  if (ts.length >= max) return false;
  ts.push(now);
  return true;
}

// Per-user when a session resolved; per-IP otherwise (health, ITN post-backs).
// x-forwarded-for is set by the hosting proxy (Railway); a direct-to-origin
// client could spoof it, which is acceptable for an abuse throttle.
function clientKey(c: Context): string {
  const userId = c.get('userId') as string | undefined;
  if (userId) return `u:${userId}`;
  const fwd = c.req.header('x-forwarded-for');
  const ip = fwd?.split(',')[0]?.trim() || c.req.header('x-real-ip') || 'unknown';
  return `ip:${ip}`;
}

function tooMany(c: Context) {
  c.header('Retry-After', String(WINDOW_MS / 1000));
  return c.json({ error: 'Too many requests. Please slow down.' }, 429);
}

export const rateLimit: MiddlewareHandler<any> = async (c, next) => {
  const now = Date.now();
  sweep(now);
  const key = clientKey(c);
  if (!hit(`g:${key}`, GENERAL_MAX, now)) return tooMany(c);
  if (c.req.path === '/api/profile' && WRITE_METHODS.has(c.req.method)) {
    if (!hit(`p:${key}`, PROFILE_WRITE_MAX, now)) return tooMany(c);
  }
  await next();
};

// Test hooks — not used by production code.
export const _internals = { hit, buckets, WINDOW_MS, GENERAL_MAX, PROFILE_WRITE_MAX };
export function _resetRateLimitState() { buckets.clear(); lastSweep = 0; }
