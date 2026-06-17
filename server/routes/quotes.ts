import { Hono } from 'hono';
import type { AppEnv } from '../lib/hono-env';
import { db } from '../db';
import { quotes, quoteCounters, invoices, invoiceCounters } from '../db/schema';
import { eq, and, gte, count, sql } from 'drizzle-orm';
import { withTier, TIER_LIMITS, type Tier } from '../lib/tier';
import { quoteSchema } from '../lib/schemas';

export const quotesRouter = new Hono<AppEnv>();
quotesRouter.use('*', withTier);

quotesRouter.get('/', async (c) => {
  const userId = c.get('userId') as string;
  const rows = await db.query.quotes.findMany({
    where: eq(quotes.userId, userId),
    orderBy: (q, { desc }) => [desc(q.updatedAt)],
  });
  return c.json(rows.map(r => ({ id: r.id, ...(r.data as object), updatedAt: r.updatedAt })));
});

quotesRouter.post('/', async (c) => {
  const userId = c.get('userId') as string;
  const tier = c.get('tier') as Tier;
  const limits = TIER_LIMITS[tier];

  const parsed = quoteSchema.safeParse(await c.req.json());
  if (!parsed.success) return c.json({ error: 'Invalid quote', details: parsed.error.format() }, 400);
  const data = parsed.data;

  try {
    const result = await db.transaction(async (tx) => {
      // Tier monthly-limit check lives inside the tx so concurrent inserts
      // can't race past the cap.
      if (limits.quotesPerMonth !== Infinity) {
        const monthStart = new Date(); monthStart.setDate(1); monthStart.setHours(0, 0, 0, 0);
        const [{ value }] = await tx.select({ value: count() }).from(quotes)
          .where(and(eq(quotes.userId, userId), gte(quotes.createdAt, monthStart)));
        if (value >= limits.quotesPerMonth) {
          return { limit: true as const };
        }
      }

      // Ensure the counter row exists, then lock it FOR UPDATE so the sequence
      // stays gapless under concurrency.
      await tx.insert(quoteCounters).values({ userId, nextSeq: 1 }).onConflictDoNothing();
      const [counter] = await tx.execute(
        sql`select next_seq from quote_counters where user_id = ${userId} for update`
      ) as unknown as Array<{ next_seq: number }>;
      const seq = Number(counter.next_seq);

      // Server-authoritative quote number; ignore any client-sent value.
      data.quoteNumber = `QT-${String(seq).padStart(4, '0')}`;

      await tx.update(quoteCounters)
        .set({ nextSeq: seq + 1 })
        .where(eq(quoteCounters.userId, userId));

      const [row] = await tx.insert(quotes).values({ userId, data }).returning();
      return { row };
    });

    if ('limit' in result) {
      return c.json({ error: 'Monthly quote limit reached. Upgrade to create more.' }, 403);
    }
    return c.json({ id: result.row.id, ...(result.row.data as object) }, 201);
  } catch {
    return c.json({ error: 'Failed to create quote' }, 500);
  }
});

// Issue an invoice ONLY when the owner confirms the client accepted the quote.
// The confirmation is the activation event — no invoice exists before this call.
quotesRouter.post('/:id/accept', async (c) => {
  const userId = c.get('userId') as string;
  const { id } = c.req.param();

  const body = await c.req.json().catch(() => ({}));
  if (body?.confirmedByClient !== true) {
    return c.json({ error: 'Client acceptance must be confirmed before invoicing.' }, 400);
  }

  try {
    const result = await db.transaction(async (tx) => {
      const existing = await tx.query.quotes.findFirst({
        where: and(eq(quotes.id, id), eq(quotes.userId, userId)),
      });
      if (!existing) return { notFound: true as const };
      const qdata = existing.data as any;

      // Idempotent: if already accepted, return the existing invoice instead of minting a second.
      if (qdata.status === 'accepted') {
        const inv = await tx.query.invoices.findFirst({ where: eq(invoices.quoteId, id) });
        return { row: existing, invoice: inv ?? null, alreadyAccepted: true as const };
      }

      const acceptedAt = new Date().toISOString();
      const newData = { ...qdata, status: 'accepted', clientAcceptedAt: acceptedAt };
      const [row] = await tx.update(quotes)
        .set({ data: newData, updatedAt: new Date() })
        .where(and(eq(quotes.id, id), eq(quotes.userId, userId)))
        .returning();

      // Gapless invoice number, locked under concurrency.
      await tx.insert(invoiceCounters).values({ userId, nextSeq: 1 }).onConflictDoNothing();
      const [counter] = await tx.execute(
        sql`select next_seq from invoice_counters where user_id = ${userId} for update`
      ) as unknown as Array<{ next_seq: number }>;
      const seq = Number(counter.next_seq);

      const snapshot = {
        ...newData,
        invoiceNumber: `INV-${String(seq).padStart(4, '0')}`,
        sourceQuoteNumber: newData.quoteNumber,
        confirmedByClient: true,
        activatedAt: acceptedAt,
      };

      let invoice = null;
      try {
        [invoice] = await tx.insert(invoices).values({
          userId, quoteId: id, invoiceNumber: snapshot.invoiceNumber, data: snapshot, status: 'unpaid',
        }).returning();
        await tx.update(invoiceCounters).set({ nextSeq: seq + 1 }).where(eq(invoiceCounters.userId, userId));
      } catch (e: any) {
        if (e?.code !== '23505') throw e; // only swallow the unique(quoteId) race
        invoice = await tx.query.invoices.findFirst({ where: eq(invoices.quoteId, id) }) ?? null;
      }
      return { row, invoice };
    });

    if ('notFound' in result) return c.json({ error: 'Not found' }, 404);
    return c.json({
      id: result.row.id, ...(result.row.data as object),
      invoice: result.invoice, alreadyAccepted: 'alreadyAccepted' in result,
    });
  } catch {
    return c.json({ error: 'Failed to accept quote' }, 500);
  }
});

quotesRouter.put('/:id', async (c) => {
  const userId = c.get('userId') as string;
  const { id } = c.req.param();

  const parsed = quoteSchema.safeParse(await c.req.json());
  if (!parsed.success) return c.json({ error: 'Invalid quote', details: parsed.error.format() }, 400);
  const data = parsed.data;

  // Preserve the server-assigned quote number; never trust a client override.
  const existing = await db.query.quotes.findFirst({
    where: and(eq(quotes.id, id), eq(quotes.userId, userId)),
  });
  if (!existing) return c.json({ error: 'Not found' }, 404);
  data.quoteNumber = (existing.data as any)?.quoteNumber ?? data.quoteNumber;

  // Acceptance must only happen through /accept (which issues the invoice).
  const prevStatus = (existing.data as any)?.status;
  if (data.status === 'accepted' && prevStatus !== 'accepted') {
    return c.json({ error: 'Use Accept & Invoice to accept a quote.' }, 409);
  }

  const [row] = await db.update(quotes)
    .set({ data, updatedAt: new Date() })
    .where(and(eq(quotes.id, id), eq(quotes.userId, userId)))
    .returning();
  if (!row) return c.json({ error: 'Not found' }, 404);
  return c.json({ id: row.id, ...(row.data as object) });
});

quotesRouter.delete('/:id', async (c) => {
  const userId = c.get('userId') as string;
  const { id } = c.req.param();
  await db.delete(quotes).where(and(eq(quotes.id, id), eq(quotes.userId, userId)));
  return c.json({ ok: true });
});
