import { Hono } from 'hono';
import type { AppEnv } from '../lib/hono-env';
import type Stripe from 'stripe';
import { stripe } from '../lib/stripe';
import { db } from '../db';
import { subscriptions } from '../db/schema';
import { eq } from 'drizzle-orm';

export const billingRouter = new Hono<AppEnv>();

// POST /api/billing/checkout — create Stripe checkout session
billingRouter.post('/checkout', async (c) => {
  const userId = c.get('userId') as string;
  const userEmail = c.get('userEmail') as string;
  const { tier } = await c.req.json() as { tier: 'pro' | 'business' };

  const priceId = tier === 'pro'
    ? process.env.STRIPE_PRO_PRICE_ID!
    : process.env.STRIPE_BUSINESS_PRICE_ID!;

  let sub = await db.query.subscriptions.findFirst({ where: eq(subscriptions.userId, userId) });
  let customerId = sub?.stripeCustomerId;

  if (!customerId) {
    const customer = await stripe.customers.create({ email: userEmail, metadata: { userId } });
    customerId = customer.id;
    if (sub) {
      await db.update(subscriptions).set({ stripeCustomerId: customerId })
        .where(eq(subscriptions.userId, userId));
    } else {
      // No subscription row yet — create it instead of orphaning the customer.
      await db.insert(subscriptions).values({ userId, stripeCustomerId: customerId })
        .onConflictDoUpdate({ target: subscriptions.userId, set: { stripeCustomerId: customerId } });
    }
  }

  const session = await stripe.checkout.sessions.create({
    customer: customerId,
    mode: 'subscription',
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: `${process.env.CLIENT_URL}/settings?billing=success`,
    cancel_url:  `${process.env.CLIENT_URL}/settings?billing=cancelled`,
    metadata: { userId },
  });

  return c.json({ url: session.url });
});

// POST /api/billing/portal — Stripe billing portal
billingRouter.post('/portal', async (c) => {
  const userId = c.get('userId') as string;
  const sub = await db.query.subscriptions.findFirst({ where: eq(subscriptions.userId, userId) });
  if (!sub?.stripeCustomerId) return c.json({ error: 'No billing account found.' }, 400);

  const session = await stripe.billingPortal.sessions.create({
    customer:   sub.stripeCustomerId,
    return_url: `${process.env.CLIENT_URL}/settings`,
  });
  return c.json({ url: session.url });
});

// POST /api/billing/webhook — bypasses session auth; verified by Stripe signature.
billingRouter.post('/webhook', async (c) => {
  const sig  = c.req.header('stripe-signature');
  const body = await c.req.text();

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(body, sig!, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch {
    return c.text('Webhook signature verification failed', 400);
  }

  const handleSub = async (stripeSub: Stripe.Subscription, status: 'active' | 'past_due' | 'canceled') => {
    const customerId = stripeSub.customer as string;
    const existingSub = await db.query.subscriptions.findFirst({
      where: eq(subscriptions.stripeCustomerId, customerId),
    });
    if (!existingSub) return;

    const priceId = stripeSub.items?.data[0]?.price?.id;
    const tier = priceId === process.env.STRIPE_PRO_PRICE_ID ? 'pro'
               : priceId === process.env.STRIPE_BUSINESS_PRICE_ID ? 'business'
               : 'free';

    await db.update(subscriptions).set({
      tier: status === 'canceled' ? 'free' : tier,
      status,
      stripeSubscriptionId: stripeSub.id,
      currentPeriodEnd: status !== 'canceled' && (stripeSub as any).current_period_end
        ? new Date((stripeSub as any).current_period_end * 1000)
        : null,
      updatedAt: new Date(),
    }).where(eq(subscriptions.stripeCustomerId, customerId));
  };

  switch (event.type) {
    case 'checkout.session.completed': {
      // Reconcile the Stripe customer id back onto the subscription row using
      // the userId we stashed in checkout metadata. Guards against a missing
      // or stale stripeCustomerId (e.g. customer created but update lost).
      const session = event.data.object as Stripe.Checkout.Session;
      const uid = session.metadata?.userId;
      const customerId = session.customer as string | null;
      if (uid && customerId) {
        await db.insert(subscriptions)
          .values({ userId: uid, stripeCustomerId: customerId })
          .onConflictDoUpdate({
            target: subscriptions.userId,
            set: { stripeCustomerId: customerId, updatedAt: new Date() },
          });
      }
      break;
    }
    case 'customer.subscription.created':
    case 'customer.subscription.updated':
      await handleSub(event.data.object as Stripe.Subscription, 'active');
      break;
    case 'customer.subscription.deleted':
      await handleSub(event.data.object as Stripe.Subscription, 'canceled');
      break;
    case 'invoice.payment_failed': {
      const inv = event.data.object as Stripe.Invoice;
      if (inv.customer) {
        await db.update(subscriptions).set({ status: 'past_due', updatedAt: new Date() })
          .where(eq(subscriptions.stripeCustomerId, inv.customer as string));
      }
      break;
    }
  }

  return c.json({ received: true });
});
