import { Hono } from 'hono';
import type { AppEnv } from '../lib/hono-env';
import { db } from '../db';
import { catalogItems } from '../db/schema';
import { eq, and, count } from 'drizzle-orm';
import { withTier, TIER_LIMITS, type Tier } from '../lib/tier';
import { catalogItemSchema } from '../lib/schemas';

export const catalogRouter = new Hono<AppEnv>();
catalogRouter.use('*', withTier);

catalogRouter.get('/', async (c) => {
  const userId = c.get('userId') as string;
  const rows = await db.query.catalogItems.findMany({ where: eq(catalogItems.userId, userId) });
  return c.json(rows.map(r => ({ id: r.id, ...(r.data as object) })));
});

catalogRouter.post('/', async (c) => {
  const userId = c.get('userId') as string;
  const tier = c.get('tier') as Tier;
  const limits = TIER_LIMITS[tier];
  if (limits.maxCatalog !== Infinity) {
    const [{ value }] = await db.select({ value: count() }).from(catalogItems).where(eq(catalogItems.userId, userId));
    if (value >= limits.maxCatalog) return c.json({ error: 'Catalog limit reached.' }, 403);
  }
  const parsed = catalogItemSchema.safeParse(await c.req.json());
  if (!parsed.success) return c.json({ error: 'Invalid catalog item', details: parsed.error.format() }, 400);
  const data = parsed.data;
  const [row] = await db.insert(catalogItems).values({ userId, data }).returning();
  return c.json({ id: row.id, ...(row.data as object) }, 201);
});

catalogRouter.put('/:id', async (c) => {
  const userId = c.get('userId') as string;
  const { id } = c.req.param();
  const parsed = catalogItemSchema.safeParse(await c.req.json());
  if (!parsed.success) return c.json({ error: 'Invalid catalog item', details: parsed.error.format() }, 400);
  const data = parsed.data;
  const [row] = await db.update(catalogItems).set({ data, updatedAt: new Date() })
    .where(and(eq(catalogItems.id, id), eq(catalogItems.userId, userId))).returning();
  if (!row) return c.json({ error: 'Not found' }, 404);
  return c.json({ id: row.id, ...(row.data as object) });
});

catalogRouter.delete('/:id', async (c) => {
  const userId = c.get('userId') as string;
  const { id } = c.req.param();
  await db.delete(catalogItems).where(and(eq(catalogItems.id, id), eq(catalogItems.userId, userId)));
  return c.json({ ok: true });
});
