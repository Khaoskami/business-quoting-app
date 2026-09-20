import type { MiddlewareHandler } from 'hono';
import { db } from '../db';
import { subscriptions } from '../db/schema';
import { eq } from 'drizzle-orm';

/**
 * Backend tier keys stay `pro` and `business` for database/backwards
 * compatibility. The customer-facing name of `pro` is now Growth.
 */
export const TIER_LIMITS = {
  free: {
    quotesPerMonth: 5,
    maxClients: 3,
    maxCatalog: 10,
    clientEmailsPerMonth: 10,
    teamMembers: 1,
    features: {
      discount: false,
      print: true,
      csv: false,
      signature: false,
      clientUrl: true,
      duplicate: false,
      directEmail: true,
      manualReminders: false,
      autoReminders: false,
      recurringInvoices: false,
      clientPortal: false,
      advancedReports: false,
      team: false,
      customReminderSchedule: false,
      apiAccess: false,
      whiteLabel: false,
    },
  },
  pro: {
    quotesPerMonth: 300,
    maxClients: 250,
    maxCatalog: 500,
    clientEmailsPerMonth: 400,
    teamMembers: 5,
    features: {
      discount: true,
      print: true,
      csv: true,
      signature: true,
      clientUrl: true,
      duplicate: true,
      directEmail: true,
      manualReminders: true,
      autoReminders: true,
      recurringInvoices: true,
      clientPortal: true,
      advancedReports: true,
      team: true,
      customReminderSchedule: false,
      apiAccess: false,
      whiteLabel: false,
    },
  },
  business: {
    quotesPerMonth: Infinity,
    maxClients: Infinity,
    maxCatalog: Infinity,
    clientEmailsPerMonth: 2000,
    teamMembers: 10,
    features: {
      discount: true,
      print: true,
      csv: true,
      signature: true,
      clientUrl: true,
      duplicate: true,
      directEmail: true,
      manualReminders: true,
      autoReminders: true,
      recurringInvoices: true,
      clientPortal: true,
      advancedReports: true,
      team: true,
      customReminderSchedule: true,
      apiAccess: true,
      whiteLabel: true,
    },
  },
} as const;

export type Tier = keyof typeof TIER_LIMITS;

export const TIER_NAMES: Record<Tier, string> = {
  free: 'Free',
  pro: 'Growth',
  business: 'Business',
};

export function quoteLimitReached(tier: Tier, quotesThisMonth: number): boolean {
  const cap = TIER_LIMITS[tier].quotesPerMonth;
  return cap !== Infinity && quotesThisMonth >= cap;
}

export function clientEmailLimitReached(tier: Tier, emailsThisMonth: number): boolean {
  const cap = TIER_LIMITS[tier].clientEmailsPerMonth;
  return cap !== Infinity && emailsThisMonth >= cap;
}

export function effectiveTier(sub?: { tier?: string | null; status?: string | null; currentPeriodEnd?: Date | null } | null): Tier {
  const tier = (sub?.tier as Tier) ?? 'free';
  if (!TIER_LIMITS[tier]) return 'free';
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
