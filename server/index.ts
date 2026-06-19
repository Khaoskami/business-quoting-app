import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { serveStatic } from 'hono/bun';
import { auth } from './auth';
import { quotesRouter } from './routes/quotes';
import { clientsRouter } from './routes/clients';
import { catalogRouter } from './routes/catalog';
import { profileRouter } from './routes/profile';
import { billingRouter } from './routes/billing';
import { adminRouter } from './routes/admin';
import { invoicesRouter } from './routes/invoices';
import type { AppEnv } from './lib/hono-env';

if (!process.env.BETTER_AUTH_URL) {
  console.warn('[payfast] BETTER_AUTH_URL is not set — PayFast ITNs will not reach this server.');
}

const app = new Hono<AppEnv>();

app.use('*', logger());

// Reject oversized request bodies before they hit any handler.
const MAX_BODY_BYTES = 256 * 1024; // 256KB
const MAX_PROFILE_BYTES = 1_600 * 1024; // 1.6MB — profile carries a base64 logo
app.use('*', async (c, next) => {
  if (c.req.method === 'POST' || c.req.method === 'PUT' || c.req.method === 'PATCH') {
    const limit = c.req.path === '/api/profile' ? MAX_PROFILE_BYTES : MAX_BODY_BYTES;
    const len = Number(c.req.header('content-length') ?? 0);
    if (len > limit) {
      return c.json({ error: 'Request body too large' }, 413);
    }
  }
  await next();
});

app.use('/api/*', cors({
  origin: process.env.CLIENT_URL ?? 'http://localhost:5173',
  credentials: true,
}));

app.get('/api/health', (c) => c.json({ ok: true }));

// Better Auth handler
app.on(['GET', 'POST'], '/api/auth/*', (c) => auth.handler(c.req.raw));

// Auth middleware for /api routes
app.use('/api/*', async (c, next) => {
  // Public endpoints that bypass session auth.
  if (c.req.path === '/api/health') return next();
  if (c.req.path === '/api/billing/notify') return next(); // PayFast ITN; verified by signature + post-back
  if (c.req.path.startsWith('/api/auth/')) return next(); // Better Auth handles its own auth flow.

  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session?.user) return c.json({ error: 'Unauthorized' }, 401);

  c.set('userId', session.user.id as string);
  c.set('userEmail', session.user.email as string);
  c.set('isAdmin', Boolean((session.user as any).isAdmin));
  await next();
});

app.route('/api/quotes',  quotesRouter);
app.route('/api/clients', clientsRouter);
app.route('/api/catalog', catalogRouter);
app.route('/api/profile', profileRouter);
app.route('/api/billing', billingRouter);
app.route('/api/admin',   adminRouter);
app.route('/api/invoices', invoicesRouter);

// Serve built client. SPA fallback to index.html for unmatched routes.
app.use('/*', serveStatic({ root: './dist/public' }));
app.get('/*', serveStatic({ path: './dist/public/index.html' }));

const port = Number(process.env.PORT ?? 3000);
console.log(`Server running on port ${port}`);
export default { port, fetch: app.fetch };
