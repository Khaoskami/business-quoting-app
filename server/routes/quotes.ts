import { Hono } from 'hono';
import { db } from '../db';
import { quotes } from '../db/schema';
import { eq, and, gte, count } from 'drizzle-orm';
import { withTier, TIER_LIMITS, type Tier } from '../lib/tier';

export const quotesRouter = new Hono();
quotesRouter.use('*', withTier);

quotesRouter.get('/', async (c) => {
  const userId = c.get('userId') as string;
  const rows = await db.query.quotes.findMany({
    where: eq(quotes.userId, userId),
    orderBy: (q, { desc }) => [desc(q.updatedAt)],
  });
  return c.json(rows.map(r => ({ id: r.id, ...(r.data as object), updatedAt: r.updatedAt })));
});

quotesRouter.post('/', async (c) => {
  const userId = c.get('userId') as string;
  const tier = c.get('tier') as Tier;
  const limits = TIER_LIMITS[tier];

  if (limits.quotesPerMonth !== Infinity) {
    const monthStart = new Date(); monthStart.setDate(1); monthStart.setHours(0, 0, 0, 0);
    const [{ value }] = await db.select({ value: count() }).from(quotes)
      .where(and(eq(quotes.userId, userId), gte(quotes.createdAt, monthStart)));
    if (value >= limits.quotesPerMonth) {
      return c.json({ error: 'Monthly quote limit reached. Upgrade to create more.' }, 403);
    }
  }

  const data = await c.req.json();
  const [row] = await db.insert(quotes).values({ userId, data }).returning();
  return c.json({ id: row.id, ...(row.data as object) }, 201);
});

quotesRouter.put('/:id', async (c) => {
  const userId = c.get('userId') as string;
  const { id } = c.req.param();
  const data = await c.req.json();
  const [row] = await db.update(quotes)
    .set({ data, updatedAt: new Date() })
    .where(and(eq(quotes.id, id), eq(quotes.userId, userId)))
    .returning();
  if (!row) return c.json({ error: 'Not found' }, 404);
  return c.json({ id: row.id, ...(row.data as object) });
});

quotesRouter.delete('/:id', async (c) => {
  const userId = c.get('userId') as string;
  const { id } = c.req.param();
  await db.delete(quotes).where(and(eq(quotes.id, id), eq(quotes.userId, userId)));
  return c.json({ ok: true });
});
