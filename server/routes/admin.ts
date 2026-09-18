import { Hono } from 'hono';
import type { AppEnv } from '../lib/hono-env';
import { db } from '../db';
import { users, subscriptions } from '../db/schema';
import { eq, desc, count } from 'drizzle-orm';
import { z } from 'zod';

export const adminRouter = new Hono<AppEnv>();

const compSchema = z.object({
  tier: z.enum(['pro', 'business']),
  note: z.string().trim().max(1000).optional(),
}).strict();
const adminToggleSchema = z.object({ isAdmin: z.boolean() }).strict();

adminRouter.use('*', async (c, next) => {
  if (!c.get('isAdmin')) return c.json({ error: 'Forbidden' }, 403);
  await next();
});

adminRouter.get('/users', async (c) => {
  const rows = await db
    .select({
      id: users.id, name: users.name, email: users.email, createdAt: users.createdAt,
      isAdmin: users.isAdmin, tier: subscriptions.tier, status: subscriptions.status,
      comped: subscriptions.comped, compedNote: subscriptions.compedNote,
      periodEnd: subscriptions.currentPeriodEnd,
    })
    .from(users)
    .leftJoin(subscriptions, eq(users.id, subscriptions.userId))
    .orderBy(desc(users.createdAt))
    .limit(1000);
  return c.json(rows);
});

adminRouter.get('/stats', async (c) => {
  const [total] = await db.select({ value: count() }).from(users);
  const [proCount] = await db.select({ value: count() }).from(subscriptions).where(eq(subscriptions.tier, 'pro'));
  const [bizCount] = await db.select({ value: count() }).from(subscriptions).where(eq(subscriptions.tier, 'business'));
  const [comped] = await db.select({ value: count() }).from(subscriptions).where(eq(subscriptions.comped, true));
  return c.json({ totalUsers: total.value, proUsers: proCount.value, businessUsers: bizCount.value, compedUsers: comped.value });
});

adminRouter.post('/users/:id/comp', async (c) => {
  const adminId = c.get('userId') as string;
  const { id } = c.req.param();
  const parsed = compSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!parsed.success) return c.json({ error: 'Invalid comp request' }, 400);
  const { tier, note } = parsed.data;
  const updated = await db.update(subscriptions).set({
    tier, status: 'comped', comped: true, compedBy: adminId,
    compedNote: note ?? '', updatedAt: new Date(),
  }).where(eq(subscriptions.userId, id)).returning({ userId: subscriptions.userId });
  if (updated.length === 0) return c.json({ error: 'Not found' }, 404);
  return c.json({ ok: true });
});

adminRouter.post('/users/:id/revoke', async (c) => {
  const { id } = c.req.param();
  const updated = await db.update(subscriptions).set({
    tier: 'free', status: 'active', comped: false, compedBy: null,
    compedNote: null, updatedAt: new Date(),
  }).where(eq(subscriptions.userId, id)).returning({ userId: subscriptions.userId });
  if (updated.length === 0) return c.json({ error: 'Not found' }, 404);
  return c.json({ ok: true });
});

adminRouter.post('/users/:id/admin', async (c) => {
  const adminId = c.get('userId') as string;
  const { id } = c.req.param();
  const parsed = adminToggleSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!parsed.success) return c.json({ error: 'Invalid admin request' }, 400);

  if (id === adminId && parsed.data.isAdmin === false) {
    const [{ value }] = await db.select({ value: count() }).from(users).where(eq(users.isAdmin, true));
    if (Number(value) <= 1) return c.json({ error: 'You cannot remove the last administrator.' }, 409);
  }

  const updated = await db.update(users).set({ isAdmin: parsed.data.isAdmin, updatedAt: new Date() })
    .where(eq(users.id, id)).returning({ id: users.id });
  if (!updated.length) return c.json({ error: 'Not found' }, 404);
  return c.json({ ok: true });
});
