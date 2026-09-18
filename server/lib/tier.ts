import type { Context, Next, MiddlewareHandler } from 'hono';
import { db } from '../db';
import { subscriptions } from '../db/schema';
import { eq } from 'drizzle-orm';

export const TIER_LIMITS = {
  free: {
    quotesPerMonth: 50,
    maxClients:     3,
    maxCatalog:     10,
    features: { discount: false, print: false, csv: true, signature: false, clientUrl: false, duplicate: false },
  },
  pro: {
    quotesPerMonth: 100,
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

export function quoteLimitReached(tier: Tier, quotesThisMonth: number): boolean {
  const cap = TIER_LIMITS[tier].quotesPerMonth;
  return cap !== Infinity && quotesThisMonth >= cap;
}

/**
 * Resolve the tier a subscription row actually grants right now.
 * A user-cancelled subscription keeps its paid tier until the end of the
 * period it already paid for (currentPeriodEnd), then falls back to free.
 * Rows downgraded for non-payment have tier already set to 'free', so they
 * are unaffected by this grace logic.
 */
export function effectiveTier(sub?: { tier?: string | null; status?: string | null; currentPeriodEnd?: Date | null } | null): Tier {
  const tier = (sub?.tier as Tier) ?? 'free';
  if (tier === 'free') return 'free';
  if (sub?.status === 'canceled') {
    const end = sub.currentPeriodEnd;
    if (!end || new Date(end).getTime() <= Date.now()) return 'free';
  }
  return tier;
}

export const withTier: MiddlewareHandler<any> = async (c, next) => {
  const userId = c.get('userId') as string;
  const sub = await db.query.subscriptions.findFirst({
    where: eq(subscriptions.userId, userId),
  });
  const tier: Tier = effectiveTier(sub);
  c.set('tier', tier);
  c.set('tierLimits', TIER_LIMITS[tier]);
  await next();
};

export function requireFeature(feature: keyof typeof TIER_LIMITS.free.features): MiddlewareHandler<any> {
  return async (c, next) => {
    const limits = c.get('tierLimits') as typeof TIER_LIMITS.free;
    if (!limits.features[feature]) {
      return c.json({ error: 'This feature requires a paid plan.' }, 403);
    }
    await next();
  };
}
