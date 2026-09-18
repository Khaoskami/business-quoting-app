import { Hono } from 'hono';
import type { AppEnv } from '../lib/hono-env';
import { db } from '../db';
import { businessProfiles, subscriptions, quotes, invoices, invoicePayments, clients, catalogItems } from '../db/schema';
import { eq } from 'drizzle-orm';
import { TIER_LIMITS, effectiveTier } from '../lib/tier';
import { profileSchema } from '../lib/schemas';

export const profileRouter = new Hono<AppEnv>();

profileRouter.get('/export', async (c) => {
  const userId = c.get('userId') as string;
  const [profile, subscription, userQuotes, userInvoices, userPayments, userClients, userCatalog] = await Promise.all([
    db.query.businessProfiles.findFirst({ where: eq(businessProfiles.userId, userId) }),
    db.query.subscriptions.findFirst({ where: eq(subscriptions.userId, userId) }),
    db.query.quotes.findMany({ where: eq(quotes.userId, userId), orderBy: (q, { asc }) => [asc(q.createdAt)] }),
    db.query.invoices.findMany({ where: eq(invoices.userId, userId), orderBy: (i, { asc }) => [asc(i.createdAt)] }),
    db.query.invoicePayments.findMany({ where: eq(invoicePayments.userId, userId), orderBy: (p, { asc }) => [asc(p.createdAt)] }),
    db.query.clients.findMany({ where: eq(clients.userId, userId), orderBy: (cl, { asc }) => [asc(cl.createdAt)] }),
    db.query.catalogItems.findMany({ where: eq(catalogItems.userId, userId), orderBy: (ci, { asc }) => [asc(ci.createdAt)] }),
  ]);
  const payload = { exportedAt: new Date().toISOString(), profile: profile?.data ?? {}, subscription: subscription ? { tier: subscription.tier, status: subscription.status, currentPeriodEnd: subscription.currentPeriodEnd, comped: subscription.comped } : null, quotes: userQuotes.map(r => ({ id: r.id, version: r.version, data: r.data, createdAt: r.createdAt, updatedAt: r.updatedAt })), invoices: userInvoices.map(r => ({ id: r.id, quoteId: r.quoteId, invoiceNumber: r.invoiceNumber, status: r.status, currency: r.currency, amountMinor: r.amountMinor, amountPaidMinor: r.amountPaidMinor, dueAt: r.dueAt, data: r.data, createdAt: r.createdAt, updatedAt: r.updatedAt })), invoicePayments: userPayments, clients: userClients, catalog: userCatalog };
  c.header('Content-Disposition', `attachment; filename=business-quotes-export-${new Date().toISOString().slice(0,10)}.json`);
  c.header('Content-Type', 'application/json; charset=utf-8');
  return c.body(JSON.stringify(payload));
});

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
