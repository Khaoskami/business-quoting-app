import { Hono } from 'hono';
import type { AppEnv } from '../lib/hono-env';
import { db } from '../db';
import { clients, businessProfiles } from '../db/schema';
import { eq, and, count, sql } from 'drizzle-orm';
import { withTier, TIER_LIMITS, type Tier } from '../lib/tier';
import { enqueueClientEmail } from '../lib/email-outbox';
import { isEmailConfigured } from '../lib/email-service';
import { clientEmailHtml } from '../lib/billing-jobs';
import { randomUUID } from 'node:crypto';
import { clientEmailSchema, clientSchema } from '../lib/schemas';

export const clientsRouter = new Hono<AppEnv>();
clientsRouter.use('*', withTier);

clientsRouter.post('/:id/email', async (c) => {
  const userId = c.get('userId') as string;
  const tier = c.get('tier') as Tier;
  if (!TIER_LIMITS[tier].features.directEmail) return c.json({ error: 'Direct client email is not available on your plan.' }, 403);
  if (!isEmailConfigured()) return c.json({ error: 'Email delivery is not configured yet. Add SMTP_USER, SMTP_PASSWORD and EMAIL_FROM in Railway.' }, 503);

  const parsed = clientEmailSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!parsed.success) return c.json({ error: 'Invalid email message', details: parsed.error.format() }, 400);

  const client = await db.query.clients.findFirst({ where: and(eq(clients.id, c.req.param('id')), eq(clients.userId, userId)) });
  if (!client) return c.json({ error: 'Not found' }, 404);
  const data = client.data as any;
  if (!data.email) return c.json({ error: 'Add an email address to this client first.' }, 400);

  try {
    const business = (await db.query.businessProfiles.findFirst({ where: eq(businessProfiles.userId, userId) }))?.data ?? {};
    const result = await enqueueClientEmail({
      userId,
      tier,
      kind: 'client_email',
      toEmail: data.email,
      replyTo: business.email || (c.get('userEmail') as string),
      subject: parsed.data.subject,
      html: clientEmailHtml({ business, recipientName: data.name || data.company || 'there', message: parsed.data.message }),
      idempotencyKey: `client-email:${userId}:${client.id}:${randomUUID()}`,
    });
    if (!result.queued) return c.json({ error: `Monthly client email limit reached (${result.limit}). Upgrade your plan to keep emailing clients.` }, 429);
    return c.json({ ok: true, queued: true, remainingEmailCredits: result.remaining });
  } catch (error) {
    console.error('[email] client email queue failed', error);
    return c.json({ error: 'Could not queue this email.' }, 500);
  }
});

clientsRouter.get('/', async (c) => {
  const userId = c.get('userId') as string;
  const rows = await db.query.clients.findMany({ where: eq(clients.userId, userId), orderBy: (x, { asc }) => [asc(x.createdAt)], limit: 500 });
  return c.json(rows.map(r => ({ id: r.id, ...(r.data as object) })));
});

async function lockUser(tx: any, userId: string) { await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${userId}, 0))`); }

clientsRouter.post('/', async (c) => {
  const userId = c.get('userId') as string;
  const tier = c.get('tier') as Tier;
  const parsed = clientSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!parsed.success) return c.json({ error: 'Invalid client', details: parsed.error.format() }, 400);
  try {
    const row = await db.transaction(async (tx) => {
      await lockUser(tx, userId);
      const limits = TIER_LIMITS[tier];
      if (limits.maxClients !== Infinity) {
        const [{ value }] = await tx.select({ value: count() }).from(clients).where(eq(clients.userId, userId));
        if (Number(value) >= limits.maxClients) throw new Error('CLIENT_LIMIT');
      }
      const [created] = await tx.insert(clients).values({ userId, data: parsed.data }).returning();
      return created;
    });
    return c.json({ id: row.id, ...(row.data as object) }, 201);
  } catch (error: any) {
    if (error?.message === 'CLIENT_LIMIT') return c.json({ error: 'Client limit reached.' }, 403);
    return c.json({ error: 'Failed to create client' }, 500);
  }
});

clientsRouter.put('/:id', async (c) => {
  const userId = c.get('userId') as string;
  const parsed = clientSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!parsed.success) return c.json({ error: 'Invalid client', details: parsed.error.format() }, 400);
  const [row] = await db.update(clients).set({ data: parsed.data, updatedAt: new Date() }).where(and(eq(clients.id, c.req.param('id')), eq(clients.userId, userId))).returning();
  if (!row) return c.json({ error: 'Not found' }, 404);
  return c.json({ id: row.id, ...(row.data as object) });
});

clientsRouter.delete('/:id', async (c) => {
  const userId = c.get('userId') as string;
  const deleted = await db.delete(clients).where(and(eq(clients.id, c.req.param('id')), eq(clients.userId, userId))).returning({ id: clients.id });
  if (!deleted.length) return c.json({ error: 'Not found' }, 404);
  return c.json({ ok: true });
});
