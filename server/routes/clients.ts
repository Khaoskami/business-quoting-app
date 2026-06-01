import { Hono } from 'hono';
import type { AppEnv } from '../lib/hono-env';
import { db } from '../db';
import { clients } from '../db/schema';
import { eq, and, count } from 'drizzle-orm';
import { withTier, TIER_LIMITS, type Tier } from '../lib/tier';

export const clientsRouter = new Hono<AppEnv>();
clientsRouter.use('*', withTier);

clientsRouter.get('/', async (c) => {
  const userId = c.get('userId') as string;
  const rows = await db.query.clients.findMany({ where: eq(clients.userId, userId) });
  return c.json(rows.map(r => ({ id: r.id, ...(r.data as object) })));
});

clientsRouter.post('/', async (c) => {
  const userId = c.get('userId') as string;
  const tier = c.get('tier') as Tier;
  const limits = TIER_LIMITS[tier];
  if (limits.maxClients !== Infinity) {
    const [{ value }] = await db.select({ value: count() }).from(clients).where(eq(clients.userId, userId));
    if (value >= limits.maxClients) return c.json({ error: 'Client limit reached.' }, 403);
  }
  const data = await c.req.json();
  const [row] = await db.insert(clients).values({ userId, data }).returning();
  return c.json({ id: row.id, ...(row.data as object) }, 201);
});

clientsRouter.put('/:id', async (c) => {
  const userId = c.get('userId') as string;
  const { id } = c.req.param();
  const data = await c.req.json();
  const [row] = await db.update(clients).set({ data, updatedAt: new Date() })
    .where(and(eq(clients.id, id), eq(clients.userId, userId))).returning();
  if (!row) return c.json({ error: 'Not found' }, 404);
  return c.json({ id: row.id, ...(row.data as object) });
});

clientsRouter.delete('/:id', async (c) => {
  const userId = c.get('userId') as string;
  const { id } = c.req.param();
  await db.delete(clients).where(and(eq(clients.id, id), eq(clients.userId, userId)));
  return c.json({ ok: true });
});
