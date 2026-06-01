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

const app = new Hono();

app.use('*', logger());
app.use('/api/*', cors({
  origin: process.env.CLIENT_URL ?? 'http://localhost:5173',
  credentials: true,
}));

app.get('/api/health', (c) => c.json({ ok: true }));

// Better Auth handler
app.on(['GET', 'POST'], '/auth/*', (c) => auth.handler(c.req.raw));

// Auth middleware for /api routes
app.use('/api/*', async (c, next) => {
  // Public endpoints that bypass session auth.
  if (c.req.path === '/api/health') return next();
  if (c.req.path === '/api/billing/webhook') return next(); // Verified by Stripe signature instead.

  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session?.user) return c.json({ error: 'Unauthorized' }, 401);

  c.set('userId', session.user.id);
  c.set('userEmail', session.user.email);
  c.set('isAdmin', (session.user as any).isAdmin ?? false);
  await next();
});

app.route('/api/quotes',  quotesRouter);
app.route('/api/clients', clientsRouter);
app.route('/api/catalog', catalogRouter);
app.route('/api/profile', profileRouter);
app.route('/api/billing', billingRouter);
app.route('/api/admin',   adminRouter);

// Serve built client. SPA fallback to index.html for unmatched routes.
app.use('/*', serveStatic({ root: './dist/public' }));
app.get('/*', serveStatic({ path: './dist/public/index.html' }));

const port = Number(process.env.PORT ?? 3000);
console.log(`Server running on port ${port}`);
export default { port, fetch: app.fetch };
