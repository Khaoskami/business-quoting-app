import type { Context, Next } from 'hono';
import { db } from '../db';
import { subscriptions } from '../db/schema';
import { eq } from 'drizzle-orm';

export const TIER_LIMITS = {
  free: {
    quotesPerMonth: 5,
    maxClients:     3,
    maxCatalog:     10,
    features: { discount: false, print: false, csv: true, signature: false, clientUrl: false, duplicate: false },
  },
  pro: {
    quotesPerMonth: 50,
    maxClients:     999,
    maxCatalog:     999,
    features: { discount: true, print: true, csv: true, signature: true, clientUrl: true, duplicate: true },
  },
  business: {
    quotesPerMonth: Infinity,
    maxClients:     Infinity,
    maxCatalog:     Infinity,
    features: { discount: true, print: true, csv: true, signature: true, clientUrl: true, duplicate: true },
  },
} as const;

export type Tier = keyof typeof TIER_LIMITS;

export async function withTier(c: Context, next: Next) {
  const userId = c.get('userId') as string;
  const sub = await db.query.subscriptions.findFirst({
    where: eq(subscriptions.userId, userId),
  });
  const tier: Tier = (sub?.tier as Tier) ?? 'free';
  c.set('tier', tier);
  c.set('tierLimits', TIER_LIMITS[tier]);
  await next();
}

export function requireFeature(feature: keyof typeof TIER_LIMITS.free.features) {
  return async (c: Context, next: Next) => {
    const limits = c.get('tierLimits') as typeof TIER_LIMITS.free;
    if (!limits.features[feature]) {
      return c.json({ error: 'This feature requires a paid plan.' }, 403);
    }
    await next();
  };
}
