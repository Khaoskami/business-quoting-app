import { Hono } from 'hono';
import type { AppEnv } from '../lib/hono-env';
import { db } from '../db';
import { catalogItems } from '../db/schema';
import { eq, and, count, sql } from 'drizzle-orm';
import { withTier, TIER_LIMITS, type Tier } from '../lib/tier';
import { catalogItemSchema } from '../lib/schemas';

export const catalogRouter = new Hono<AppEnv>();
catalogRouter.use('*', withTier);

catalogRouter.get('/', async (c) => {
  const userId = c.get('userId') as string;
  const rows = await db.query.catalogItems.findMany({ where: eq(catalogItems.userId, userId), orderBy: (x, { asc }) => [asc(x.createdAt)], limit: 500 });
  return c.json(rows.map(r => ({ id: r.id, ...(r.data as object) })));
});

async function lockUser(tx: any, userId: string) { await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${userId}, 0))`); }

catalogRouter.post('/', async (c) => {
  const userId = c.get('userId') as string;
  const tier = c.get('tier') as Tier;
  const parsed = catalogItemSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!parsed.success) return c.json({ error: 'Invalid catalog item', details: parsed.error.format() }, 400);
  try {
    const row = await db.transaction(async (tx) => {
      await lockUser(tx, userId);
      const limits = TIER_LIMITS[tier];
      if (limits.maxCatalog !== Infinity) {
        const [{ value }] = await tx.select({ value: count() }).from(catalogItems).where(eq(catalogItems.userId, userId));
        if (Number(value) >= limits.maxCatalog) throw new Error('CATALOG_LIMIT');
      }
      const [created] = await tx.insert(catalogItems).values({ userId, data: parsed.data }).returning();
      return created;
    });
    return c.json({ id: row.id, ...(row.data as object) }, 201);
  } catch (error: any) {
    if (error?.message === 'CATALOG_LIMIT') return c.json({ error: 'Catalog limit reached.' }, 403);
    return c.json({ error: 'Failed to create catalog item' }, 500);
  }
});

catalogRouter.put('/:id', async (c) => {
  const userId = c.get('userId') as string;
  const parsed = catalogItemSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!parsed.success) return c.json({ error: 'Invalid catalog item', details: parsed.error.format() }, 400);
  const [row] = await db.update(catalogItems).set({ data: parsed.data, updatedAt: new Date() }).where(and(eq(catalogItems.id, c.req.param('id')), eq(catalogItems.userId, userId))).returning();
  if (!row) return c.json({ error: 'Not found' }, 404);
  return c.json({ id: row.id, ...(row.data as object) });
});

catalogRouter.delete('/:id', async (c) => {
  const userId = c.get('userId') as string;
  const deleted = await db.delete(catalogItems).where(and(eq(catalogItems.id, c.req.param('id')), eq(catalogItems.userId, userId))).returning({ id: catalogItems.id });
  if (!deleted.length) return c.json({ error: 'Not found' }, 404);
  return c.json({ ok: true });
});
