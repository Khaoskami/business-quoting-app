import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { serveStatic } from 'hono/bun';
import { auth } from './auth';
import { quotesRouter, publicQuotesRouter } from './routes/quotes';
import { clientsRouter } from './routes/clients';
import { catalogRouter } from './routes/catalog';
import { profileRouter } from './routes/profile';
import { billingRouter } from './routes/billing';
import { adminRouter } from './routes/admin';
import { invoicesRouter, publicInvoicesRouter } from './routes/invoices';
import { rateLimit } from './lib/rate-limit';
import { validateEnvironment } from './lib/env';
import { processEmailJobs, resetStuckEmailJobs } from './lib/email-outbox';
import { scheduleInvoiceReminderJobs } from './lib/billing-jobs';
import type { AppEnv } from './lib/hono-env';

validateEnvironment();

const app = new Hono<AppEnv>();
app.use('*', logger());

const MAX_BODY_BYTES = 256 * 1024;
const MAX_PROFILE_BYTES = 1_600 * 1024;
app.use('*', async (c, next) => {
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('Referrer-Policy', 'no-referrer');
  c.header('X-Frame-Options', 'DENY');
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  c.header('Cross-Origin-Opener-Policy', 'same-origin');
  if (process.env.NODE_ENV === 'production') c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  if (c.req.path.startsWith('/api/')) c.header('Cache-Control', 'no-store');
  await next();
});

app.use('*', async (c, next) => {
  if (['POST', 'PUT', 'PATCH'].includes(c.req.method)) {
    const limit = c.req.path === '/api/profile' ? MAX_PROFILE_BYTES : MAX_BODY_BYTES;
    const len = Number(c.req.header('content-length') ?? 0);
    if (len > limit) return c.json({ error: 'Request body too large' }, 413);
  }
  await next();
});

app.use('/api/*', cors({
  origin: process.env.CLIENT_URL!,
  credentials: true,
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Idempotency-Key'],
}));

// Same-origin protection for browser-authenticated mutations. Public capability
// URLs and PayFast ITNs intentionally bypass this because they are not cookie-authenticated.
app.use('/api/*', async (c, next) => {
  const publicRoute = c.req.path === '/api/health' || c.req.path === '/api/ready' || c.req.path === '/api/billing/notify' || c.req.path.startsWith('/api/public/') || c.req.path.startsWith('/api/auth/');
  if (!publicRoute && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(c.req.method)) {
    const origin = c.req.header('origin');
    const referer = c.req.header('referer');
    const expected = new URL(process.env.CLIENT_URL!).origin;
    let refererOrigin: string | null = null;
    if (referer) { try { refererOrigin = new URL(referer).origin; } catch { refererOrigin = null; } }
    if ((origin && origin !== expected) || (!origin && referer && refererOrigin !== expected)) {
      return c.json({ error: 'Cross-origin request rejected.' }, 403);
    }
  }
  await next();
});

app.get('/api/health', (c) => c.json({ ok: true }));
app.get('/api/ready', async (c) => {
  try {
    const { db } = await import('./db');
    await db.execute((await import('drizzle-orm')).sql`select 1`);
    return c.json({ ok: true });
  } catch {
    return c.json({ ok: false }, 503);
  }
});

app.on(['GET', 'POST'], '/api/auth/*', (c) => auth.handler(c.req.raw));

app.use('/api/*', async (c, next) => {
  if (c.req.path === '/api/health' || c.req.path === '/api/ready' || c.req.path === '/api/billing/notify' || c.req.path.startsWith('/api/public/') || c.req.path.startsWith('/api/auth/')) return next();
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session?.user) return c.json({ error: 'Unauthorized' }, 401);
  c.set('userId', session.user.id as string);
  c.set('userEmail', session.user.email as string);
  c.set('isAdmin', Boolean((session.user as any).isAdmin));
  await next();
});
app.use('/api/*', rateLimit);

app.route('/api/quotes', quotesRouter);
app.route('/api/public/quotes', publicQuotesRouter);
app.route('/api/clients', clientsRouter);
app.route('/api/catalog', catalogRouter);
app.route('/api/profile', profileRouter);
app.route('/api/billing', billingRouter);
app.route('/api/admin', adminRouter);
app.route('/api/invoices', invoicesRouter);
app.route('/api/public/invoices', publicInvoicesRouter);

app.onError((err, c) => {
  console.error('[request-error]', { path: c.req.path, method: c.req.method, message: err.message });
  return c.json({ error: 'Unexpected server error.' }, 500);
});

app.use('/*', serveStatic({ root: './dist/public' }));
app.get('/*', serveStatic({ path: './dist/public/index.html' }));

const port = Number(process.env.PORT ?? 3000);
console.log(`Server running on port ${port}`);

// Database-backed email jobs are safe across multiple replicas because workers
// claim rows with FOR UPDATE SKIP LOCKED. Each replica can run the loop.
if (process.env.NODE_ENV !== 'test') {
  setTimeout(() => {
    void resetStuckEmailJobs().catch(() => {});
    void scheduleInvoiceReminderJobs().catch(() => {});
    void processEmailJobs().catch(() => {});
  }, 2_000);
  setInterval(() => {
    void resetStuckEmailJobs().catch(() => {});
    void scheduleInvoiceReminderJobs().catch(() => {});
    void processEmailJobs().catch(() => {});
  }, 60_000);
}

export default { port, fetch: app.fetch };
