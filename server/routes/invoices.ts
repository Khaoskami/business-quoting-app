import { Hono } from 'hono';
import type { AppEnv } from '../lib/hono-env';
import { db } from '../db';
import { invoices } from '../db/schema';
import { eq, and } from 'drizzle-orm';

export const invoicesRouter = new Hono<AppEnv>();

invoicesRouter.get('/', async (c) => {
  const userId = c.get('userId') as string;
  const rows = await db.query.invoices.findMany({
    where: eq(invoices.userId, userId),
    orderBy: (i, { desc }) => [desc(i.createdAt)],
  });
  return c.json(rows.map(r => ({
    id: r.id, quoteId: r.quoteId, status: r.status, createdAt: r.createdAt, ...(r.data as object),
  })));
});

invoicesRouter.patch('/:id/status', async (c) => {
  const userId = c.get('userId') as string;
  const { id } = c.req.param();
  const { status } = await c.req.json() as { status: 'unpaid' | 'paid' | 'void' };
  if (!['unpaid', 'paid', 'void'].includes(status)) return c.json({ error: 'Invalid status' }, 400);
  const [row] = await db.update(invoices)
    .set({ status, updatedAt: new Date() })
    .where(and(eq(invoices.id, id), eq(invoices.userId, userId)))
    .returning();
  if (!row) return c.json({ error: 'Not found' }, 404);
  return c.json({ ok: true });
});
