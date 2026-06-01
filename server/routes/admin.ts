import { Hono } from 'hono';
import type { AppEnv } from '../lib/hono-env';
import { db } from '../db';
import { users, subscriptions } from '../db/schema';
import { eq, desc, count } from 'drizzle-orm';

export const adminRouter = new Hono<AppEnv>();

adminRouter.use('*', async (c, next) => {
  if (!c.get('isAdmin')) return c.json({ error: 'Forbidden' }, 403);
  await next();
});

adminRouter.get('/users', async (c) => {
  const rows = await db
    .select({
      id:         users.id,
      name:       users.name,
      email:      users.email,
      createdAt:  users.createdAt,
      isAdmin:    users.isAdmin,
      tier:       subscriptions.tier,
      status:     subscriptions.status,
      comped:     subscriptions.comped,
      compedNote: subscriptions.compedNote,
      periodEnd:  subscriptions.currentPeriodEnd,
    })
    .from(users)
    .leftJoin(subscriptions, eq(users.id, subscriptions.userId))
    .orderBy(desc(users.createdAt));
  return c.json(rows);
});

adminRouter.get('/stats', async (c) => {
  const [total]    = await db.select({ value: count() }).from(users);
  const [proCount] = await db.select({ value: count() }).from(subscriptions).where(eq(subscriptions.tier, 'pro'));
  const [bizCount] = await db.select({ value: count() }).from(subscriptions).where(eq(subscriptions.tier, 'business'));
  const [comped]   = await db.select({ value: count() }).from(subscriptions).where(eq(subscriptions.comped, true));
  return c.json({
    totalUsers:    total.value,
    proUsers:      proCount.value,
    businessUsers: bizCount.value,
    compedUsers:   comped.value,
  });
});

adminRouter.post('/users/:id/comp', async (c) => {
  const adminId = c.get('userId') as string;
  const { id } = c.req.param();
  const { tier, note } = await c.req.json() as { tier: 'pro' | 'business'; note?: string };
  await db.update(subscriptions).set({
    tier,
    status:    'comped',
    comped:    true,
    compedBy:  adminId,
    compedNote: note ?? '',
    updatedAt: new Date(),
  }).where(eq(subscriptions.userId, id));
  return c.json({ ok: true });
});

adminRouter.post('/users/:id/revoke', async (c) => {
  const { id } = c.req.param();
  await db.update(subscriptions).set({
    tier:       'free',
    status:     'active',
    comped:     false,
    compedBy:   null,
    compedNote: null,
    updatedAt:  new Date(),
  }).where(eq(subscriptions.userId, id));
  return c.json({ ok: true });
});

adminRouter.post('/users/:id/admin', async (c) => {
  const { id } = c.req.param();
  const { isAdmin } = await c.req.json() as { isAdmin: boolean };
  await db.update(users).set({ isAdmin }).where(eq(users.id, id));
  return c.json({ ok: true });
});
