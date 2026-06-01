import { Hono } from 'hono';
import { db } from '../db';
import { businessProfiles, subscriptions } from '../db/schema';
import { eq } from 'drizzle-orm';
import { TIER_LIMITS } from '../lib/tier';

export const profileRouter = new Hono();

profileRouter.get('/', async (c) => {
  const userId = c.get('userId') as string;
  const profile = await db.query.businessProfiles.findFirst({ where: eq(businessProfiles.userId, userId) });
  const sub = await db.query.subscriptions.findFirst({ where: eq(subscriptions.userId, userId) });
  const tier = (sub?.tier as keyof typeof TIER_LIMITS) ?? 'free';
  return c.json({
    profile: profile?.data ?? {},
    subscription: {
      tier,
      status:           sub?.status,
      currentPeriodEnd: sub?.currentPeriodEnd,
      comped:           sub?.comped,
      limits:           TIER_LIMITS[tier],
    },
  });
});

profileRouter.put('/', async (c) => {
  const userId = c.get('userId') as string;
  const data = await c.req.json();
  await db.insert(businessProfiles).values({ userId, data })
    .onConflictDoUpdate({ target: businessProfiles.userId, set: { data, updatedAt: new Date() } });
  return c.json({ ok: true });
});
