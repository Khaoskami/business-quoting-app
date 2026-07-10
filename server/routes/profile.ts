import { Hono } from 'hono';
import type { AppEnv } from '../lib/hono-env';
import { db } from '../db';
import { businessProfiles, subscriptions } from '../db/schema';
import { eq } from 'drizzle-orm';
import { TIER_LIMITS, effectiveTier } from '../lib/tier';
import { profileSchema } from '../lib/schemas';

export const profileRouter = new Hono<AppEnv>();

profileRouter.get('/', async (c) => {
  const userId = c.get('userId') as string;
  const profile = await db.query.businessProfiles.findFirst({ where: eq(businessProfiles.userId, userId) });
  const sub = await db.query.subscriptions.findFirst({ where: eq(subscriptions.userId, userId) });
  const tier = effectiveTier(sub);
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
  const parsed = profileSchema.safeParse(await c.req.json());
  if (!parsed.success) return c.json({ error: 'Invalid profile', details: parsed.error.format() }, 400);
  const data = parsed.data;
  await db.insert(businessProfiles).values({ userId, data })
    .onConflictDoUpdate({ target: businessProfiles.userId, set: { data, updatedAt: new Date() } });
  return c.json({ ok: true });
});
