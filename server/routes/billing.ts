import { Hono } from 'hono';
import type { AppEnv } from '../lib/hono-env';
import { db } from '../db';
import { subscriptions, processedItns, billingCheckouts } from '../db/schema';
import { and, eq, sql } from 'drizzle-orm';
import { buildSubscriptionRedirect, validateItn, cancelSubscription } from '../lib/payfast';
import { toMinor } from '../lib/finance';
import { randomBytes } from 'node:crypto';
import { PRICING } from '../../shared/pricing';

export const billingRouter = new Hono<AppEnv>();
const PRICES = { pro: PRICING.pro.price, business: PRICING.business.price } as const;
const FAILED_PAYMENT_LIMIT = 2;

billingRouter.post('/checkout', async (c) => {
  const userId = c.get('userId') as string;
  const userEmail = c.get('userEmail') as string;
  const body = await c.req.json().catch(() => ({})) as any;
  const tier = body?.tier as keyof typeof PRICES;
  if (tier !== 'pro' && tier !== 'business') return c.json({ error: 'Invalid tier' }, 400);
  await db.insert(subscriptions).values({ userId }).onConflictDoNothing();
  const sub = await db.query.subscriptions.findFirst({ where: eq(subscriptions.userId, userId) });
  if (sub?.tier === tier && sub.status !== 'canceled') return c.json({ error: 'You already have this plan.' }, 409);

  const merchantPaymentId = `bq_${Date.now().toString(36)}_${randomBytes(10).toString('hex')}`;
  const amountMinor = toMinor(PRICES[tier], 'ZAR');
  await db.insert(billingCheckouts).values({ merchantPaymentId, userId, tier, amountMinor, currency: 'ZAR' });

  const clientBase = process.env.CLIENT_URL!.replace(/\/+$/, '');
  const apiBase = process.env.BETTER_AUTH_URL!.replace(/\/+$/, '');
  const url = buildSubscriptionRedirect({
    amount: PRICES[tier].toFixed(2), itemName: `Business Quotes ${tier === 'pro' ? 'Growth' : 'Business'}`,
    email: userEmail, mPaymentId: merchantPaymentId, userId, tier,
    returnUrl: `${clientBase}/settings?billing=success`,
    cancelUrl: `${clientBase}/settings?billing=cancelled`,
    notifyUrl: `${apiBase}/api/billing/notify`,
  });
  return c.json({ url });
});

billingRouter.post('/notify', async (c) => {
  const rawBody = await c.req.text();
  const data = await validateItn(rawBody);
  if (!data) return c.text('', 200);
  const status = (data.payment_status ?? '').toUpperCase();
  const pfPaymentId = (data.pf_payment_id ?? '').trim();
  const merchantPaymentId = (data.m_payment_id ?? '').trim();
  if (!merchantPaymentId) return c.text('', 200);

  try {
    await db.transaction(async (tx) => {
      const [checkout] = await tx.execute(sql`
        select id, user_id, tier, amount_minor, status, payfast_token
        from billing_checkouts
        where merchant_payment_id = ${merchantPaymentId}
        for update
      `) as unknown as Array<any>;
      if (!checkout) return;
      if (checkout.status === 'complete') return;
      if (status === 'COMPLETE') {
        const grossMinor = toMinor(Number(data.amount_gross ?? 0), 'ZAR');
        if (grossMinor !== Number(checkout.amount_minor)) return;
      }
      if (pfPaymentId) {
        const inserted = await tx.insert(processedItns).values({ pfPaymentId, paymentStatus: status }).onConflictDoNothing().returning();
        if (!inserted.length) return;
      }
      if (status === 'COMPLETE') {
        await tx.update(billingCheckouts).set({ status: 'complete', payfastToken: data.token || null, updatedAt: new Date() }).where(eq(billingCheckouts.id, checkout.id));
        const periodEnd = new Date(); periodEnd.setMonth(periodEnd.getMonth() + 1);
        await tx.update(subscriptions).set({
          tier: checkout.tier, status: 'active', stripeSubscriptionId: data.token || null,
          failedPayments: 0, billingAmountMinor: Number(checkout.amount_minor), currentPeriodEnd: periodEnd, updatedAt: new Date(),
        }).where(eq(subscriptions.userId, checkout.userId));
      } else if (status === 'FAILED') {
        await tx.update(billingCheckouts).set({ status: 'failed', updatedAt: new Date() }).where(eq(billingCheckouts.id, checkout.id));
        const [sub] = await tx.execute(sql`select failed_payments, tier from subscriptions where user_id = ${checkout.userId} for update`) as unknown as Array<any>;
        const failed = Number(sub?.failed_payments ?? 0) + 1;
        if (failed >= FAILED_PAYMENT_LIMIT) {
          await tx.update(subscriptions).set({ tier: 'free', status: 'canceled', failedPayments: 0, updatedAt: new Date() }).where(eq(subscriptions.userId, checkout.userId));
        } else {
          await tx.update(subscriptions).set({ status: 'past_due', failedPayments: failed, updatedAt: new Date() }).where(eq(subscriptions.userId, checkout.userId));
        }
      } else if (status === 'CANCELLED') {
        await tx.update(billingCheckouts).set({ status: 'cancelled', updatedAt: new Date() }).where(eq(billingCheckouts.id, checkout.id));
        await tx.update(subscriptions).set({ status: 'canceled', failedPayments: 0, updatedAt: new Date() }).where(eq(subscriptions.userId, checkout.userId));
      }
    });
  } catch {
    // PayFast retries failed ITNs. Do not leak internals to the provider.
  }
  return c.text('', 200);
});

billingRouter.post('/cancel', async (c) => {
  const userId = c.get('userId') as string;
  const sub = await db.query.subscriptions.findFirst({ where: eq(subscriptions.userId, userId) });
  const token = sub?.stripeSubscriptionId;
  if (!token || sub?.tier === 'free') return c.json({ error: 'No active subscription found.' }, 400);
  if (sub.status === 'canceled') return c.json({ ok: true });
  const ok = await cancelSubscription(token);
  if (!ok) return c.json({ error: 'Could not cancel automatically. Cancel from your PayFast account or contact support.' }, 502);
  await db.update(subscriptions).set({ status: 'canceled', failedPayments: 0, updatedAt: new Date() }).where(and(eq(subscriptions.userId, userId), eq(subscriptions.stripeSubscriptionId, token)));
  return c.json({ ok: true });
});
