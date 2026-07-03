import { Hono } from 'hono';
import type { AppEnv } from '../lib/hono-env';
import { db } from '../db';
import { subscriptions, processedItns } from '../db/schema';
import { eq } from 'drizzle-orm';
import { buildSubscriptionRedirect, validateItn, cancelSubscription } from '../lib/payfast';

export const billingRouter = new Hono<AppEnv>();

const PRICES = { pro: 299, business: 599 } as const;
const FAILED_PAYMENT_LIMIT = 2; // downgrade to free on the 2nd failed renewal

// POST /api/billing/checkout — signed PayFast redirect URL.
billingRouter.post('/checkout', async (c) => {
  const userId = c.get('userId') as string;
  const userEmail = c.get('userEmail') as string;
  const { tier } = (await c.req.json()) as { tier: 'pro' | 'business' };
  if (tier !== 'pro' && tier !== 'business') return c.json({ error: 'Invalid tier' }, 400);

  await db.insert(subscriptions).values({ userId }).onConflictDoNothing();

  const clientBase = process.env.CLIENT_URL ?? 'http://localhost:5173';
  const apiBase    = process.env.BETTER_AUTH_URL ?? 'http://localhost:3000';

  const url = buildSubscriptionRedirect({
    amount:     PRICES[tier].toFixed(2),
    itemName:   `Business Quotes ${tier === 'pro' ? 'Pro' : 'Business'}`,
    email:      userEmail,
    mPaymentId: `${userId}:${Date.now()}`,
    userId,
    tier,
    returnUrl:  `${clientBase}/settings?billing=success`,
    cancelUrl:  `${clientBase}/settings?billing=cancelled`,
    notifyUrl:  `${apiBase}/api/billing/notify`,
  });

  return c.json({ url });
});

// POST /api/billing/notify — PayFast ITN (bypasses session auth; see index.ts).
// Always reply 200 fast; only mutate on a fully validated call.
billingRouter.post('/notify', async (c) => {
  const rawBody = await c.req.text();
  const data = await validateItn(rawBody);

  if (!data) {
    console.warn('[payfast] ITN validation FAILED');
    return c.text('', 200);
  }

  const status = (data.payment_status ?? '').toUpperCase(); // COMPLETE | FAILED | CANCELLED | PENDING
  const userId = data.custom_str1 || undefined;
  const tier   = data.custom_str2 as 'pro' | 'business' | undefined;
  const token  = data.token || null;
  const gross  = Number(data.amount_gross ?? 0);

  console.log('[payfast] ITN ok', {
    status, m_payment_id: data.m_payment_id, pf_payment_id: data.pf_payment_id, hasToken: !!token,
  });

  // Resolve the subscription: prefer userId, else match by stored token.
  let sub = userId
    ? await db.query.subscriptions.findFirst({ where: eq(subscriptions.userId, userId) })
    : undefined;
  if (!sub && token) {
    sub = await db.query.subscriptions.findFirst({ where: eq(subscriptions.stripeSubscriptionId, token) });
  }
  if (!sub) {
    console.warn('[payfast] ITN could not resolve a subscription');
    return c.text('', 200);
  }

  // Replay guard: PayFast re-delivers an ITN until acknowledged, and a
  // re-delivered FAILED ITN must not double-increment failedPayments (it could
  // wrongly trip the two-strike downgrade). Claim the (pf_payment_id, status)
  // pair inside the same transaction as the mutation so a crash between the
  // two can't strand a processed-marker without its effect. Returns false when
  // this exact ITN was already processed.
  const pfPaymentId = (data.pf_payment_id ?? '').trim();
  const claimItn = async (tx: Parameters<Parameters<typeof db.transaction>[0]>[0]): Promise<boolean> => {
    if (!pfPaymentId) return true; // nothing to dedupe on — process as before
    const inserted = await tx.insert(processedItns)
      .values({ pfPaymentId, paymentStatus: status })
      .onConflictDoNothing()
      .returning();
    if (inserted.length === 0) {
      console.log('[payfast] ITN replay ignored', { pf_payment_id: pfPaymentId, status });
      return false;
    }
    return true;
  };

  if (status === 'COMPLETE') {
    // Amount-tamper guard: gross must meet the expected price for the tier.
    const resolvedTier = tier ?? (sub.tier as 'pro' | 'business');
    const expected = resolvedTier === 'pro' ? PRICES.pro : resolvedTier === 'business' ? PRICES.business : null;
    if (expected == null || gross + 0.001 < expected) {
      console.warn('[payfast] ITN amount below expected; ignoring', { gross, expected, resolvedTier });
      return c.text('', 200);
    }
    // Monthly frequency: this charge pays for one month from now. Cancel paths
    // intentionally leave currentPeriodEnd untouched so the paid-through date
    // remains visible.
    const periodEnd = new Date();
    periodEnd.setMonth(periodEnd.getMonth() + 1);
    await db.transaction(async (tx) => {
      if (!(await claimItn(tx))) return;
      await tx.update(subscriptions).set({
        tier: resolvedTier,
        status: 'active',
        stripeSubscriptionId: token ?? sub.stripeSubscriptionId, // repurposed: PayFast token
        failedPayments: 0,
        currentPeriodEnd: periodEnd,
        updatedAt: new Date(),
      }).where(eq(subscriptions.userId, sub.userId));
    });
    return c.text('', 200);
  }

  if (status === 'FAILED') {
    const failed = (sub.failedPayments ?? 0) + 1;
    await db.transaction(async (tx) => {
      if (!(await claimItn(tx))) return;
      if (failed >= FAILED_PAYMENT_LIMIT) {
        await tx.update(subscriptions).set({
          tier: 'free', status: 'canceled', failedPayments: 0, updatedAt: new Date(),
        }).where(eq(subscriptions.userId, sub.userId));
        console.warn('[payfast] subscription downgraded to free after failed renewals', { userId: sub.userId });
      } else {
        await tx.update(subscriptions).set({
          status: 'past_due', failedPayments: failed, updatedAt: new Date(),
        }).where(eq(subscriptions.userId, sub.userId));
      }
    });
    return c.text('', 200);
  }

  if (status === 'CANCELLED') {
    await db.transaction(async (tx) => {
      if (!(await claimItn(tx))) return;
      await tx.update(subscriptions).set({
        tier: 'free', status: 'canceled', failedPayments: 0, updatedAt: new Date(),
      }).where(eq(subscriptions.userId, sub.userId));
    });
    return c.text('', 200);
  }

  return c.text('', 200); // PENDING or unknown — ignore
});

// POST /api/billing/cancel — cancel via PayFast recurring API using the token.
billingRouter.post('/cancel', async (c) => {
  const userId = c.get('userId') as string;
  const sub = await db.query.subscriptions.findFirst({ where: eq(subscriptions.userId, userId) });
  const token = sub?.stripeSubscriptionId;
  if (!token) return c.json({ error: 'No active subscription found.' }, 400);

  const ok = await cancelSubscription(token);
  if (!ok) return c.json({ error: 'Could not cancel automatically. Cancel from your PayFast account or contact support.' }, 502);

  await db.update(subscriptions).set({
    tier: 'free', status: 'canceled', failedPayments: 0, updatedAt: new Date(),
  }).where(eq(subscriptions.userId, userId));
  return c.json({ ok: true });
});
