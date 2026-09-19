import { Hono } from 'hono';
import type { AppEnv } from '../lib/hono-env';
import { db } from '../db';
import { quotes, quoteCounters, invoices, invoiceCounters, clients, shareLinks, quoteEvents, businessProfiles, emailJobs, invoiceEvents } from '../db/schema';
import { eq, and, count, gte, sql } from 'drizzle-orm';
import { withTier, TIER_LIMITS, quoteLimitReached, type Tier } from '../lib/tier';
import { quoteResponseSchema, quoteSchema } from '../lib/schemas';
import { calculateTotals } from '../lib/finance';
import { getClientIp, hashRequestIdentifier, hashSecret } from '../lib/security';
import { upsertShareLink } from '../lib/share-links';
import { enqueueEmail } from '../lib/email-outbox';
import { invoiceEmailHtml, quoteEmailHtml, quoteFollowupEmailHtml } from '../lib/billing-jobs';
import { renderQuotePdf } from '../lib/pdf';

export const quotesRouter = new Hono<AppEnv>();
quotesRouter.use('*', withTier);

function baseUrl() { return process.env.CLIENT_URL ?? 'http://localhost:5173'; }
function withValidUntil(data: any, createdAt: Date) {
  const d = new Date(createdAt);
  d.setDate(d.getDate() + Number(data.validityDays ?? 30));
  return d.toISOString();
}

async function enrichClient(tx: any, userId: string, data: any) {
  const clientId = data.clientId || null;
  if (!clientId) return { ...data, clientId: '', clientEmail: data.clientEmail || '' };
  const client = await tx.query.clients.findFirst({ where: and(eq(clients.id, clientId), eq(clients.userId, userId)) });
  if (!client) throw new Error('CLIENT_NOT_FOUND');
  const c = client.data as any;
  return {
    ...data,
    clientId,
    clientName: c.company ? `${c.name} (${c.company})` : c.name,
    clientEmail: c.email || '',
    clientUrl: c.website || '',
  };
}

function normalizeData(data: any, createdAt: Date, version = 1) {
  const total = calculateTotals(data.items, data.taxPercent, data.discountPercent, data.currency);
  return {
    ...data,
    quoteNumber: data.quoteNumber,
    status: data.status === 'accepted' ? 'draft' : data.status,
    createdAt: createdAt.toISOString(),
    validUntil: withValidUntil(data, createdAt),
    version,
    totalMinor: total.totalMinor,
  };
}

async function lockUser(tx: any, userId: string) {
  await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${userId}, 0))`);
}

async function createInvoice(tx: any, userId: string, qdata: any, invoiceCreatedAt: Date) {
  const existing = await tx.query.invoices.findFirst({ where: and(eq(invoices.quoteId, qdata.id), eq(invoices.userId, userId)) });
  if (existing) return existing;

  await tx.insert(invoiceCounters).values({ userId, nextSeq: 1 }).onConflictDoNothing();
  const [counter] = await tx.execute(sql`select next_seq from invoice_counters where user_id = ${userId} for update`) as unknown as Array<{ next_seq: number }>;
  const seq = Number(counter.next_seq);
  const invoiceNumber = `INV-${String(seq).padStart(4, '0')}`;
  const totals = calculateTotals(qdata.items, qdata.taxPercent, qdata.discountPercent, qdata.currency);
  const dueAt = new Date(invoiceCreatedAt);
  dueAt.setDate(dueAt.getDate() + Number(qdata.paymentTermsDays ?? 30));
  const snapshot = {
    ...qdata,
    quoteId: qdata.id,
    sourceQuoteNumber: qdata.quoteNumber,
    invoiceNumber,
    issuedAt: invoiceCreatedAt.toISOString(),
    dueAt: dueAt.toISOString(),
    totalMinor: totals.totalMinor,
  };
  const [invoice] = await tx.insert(invoices).values({
    userId,
    quoteId: qdata.id,
    invoiceNumber,
    status: 'unpaid',
    currency: qdata.currency,
    amountMinor: totals.totalMinor,
    amountPaidMinor: 0,
    clientEmail: qdata.clientEmail || null,
    dueAt,
    data: snapshot,
  }).returning();
  await tx.update(invoiceCounters).set({ nextSeq: seq + 1 }).where(eq(invoiceCounters.userId, userId));
  await tx.insert(invoiceEvents).values({ userId, invoiceId: invoice.id, eventType: 'created', metadata: { sourceQuoteId: qdata.id, sourceQuoteNumber: qdata.quoteNumber } });
  return invoice;
}

quotesRouter.get('/', async (c) => {
  const userId = c.get('userId') as string;
  const deletedOnly = c.req.query('deletedOnly') === '1';
  const rows = await db.query.quotes.findMany({
    where: deletedOnly ? and(eq(quotes.userId, userId), sql`${quotes.deletedAt} is not null`) : and(eq(quotes.userId, userId), sql`${quotes.deletedAt} is null`),
    orderBy: (q, { desc }) => [desc(q.updatedAt), desc(q.id)],
    limit: 250,
  });
  return c.json(rows.map(r => ({ id: r.id, version: r.version, deletedAt: r.deletedAt, ...(r.data as object), updatedAt: r.updatedAt })));
});

quotesRouter.post('/', async (c) => {
  const userId = c.get('userId') as string;
  const tier = c.get('tier') as Tier;
  const limits = TIER_LIMITS[tier];
  const parsed = quoteSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!parsed.success) return c.json({ error: 'Invalid quote', details: parsed.error.format() }, 400);
  const raw = parsed.data;
  const idempotencyKey = c.req.header('Idempotency-Key')?.trim().slice(0, 200) || null;

  try {
    const result = await db.transaction(async (tx) => {
      if (idempotencyKey) {
        const prior = await tx.query.quotes.findFirst({ where: and(eq(quotes.userId, userId), eq(quotes.idempotencyKey, idempotencyKey)) });
        if (prior) return { row: prior, reused: true as const };
      }
      await lockUser(tx, userId);
      if (limits.quotesPerMonth !== Infinity) {
        const monthStart = new Date(); monthStart.setDate(1); monthStart.setHours(0, 0, 0, 0);
        const [{ value }] = await tx.select({ value: count() }).from(quotes)
          .where(and(eq(quotes.userId, userId), gte(quotes.createdAt, monthStart)));
        if (quoteLimitReached(tier, Number(value))) return { limit: true as const };
      }
      const enriched = await enrichClient(tx, userId, raw);
      await tx.insert(quoteCounters).values({ userId, nextSeq: 1 }).onConflictDoNothing();
      const [counter] = await tx.execute(sql`select next_seq from quote_counters where user_id = ${userId} for update`) as unknown as Array<{ next_seq: number }>;
      const seq = Number(counter.next_seq);
      const now = new Date();
      const data = normalizeData({ ...enriched, quoteNumber: `QT-${String(seq).padStart(4, '0')}` }, now, 1);
      const [row] = await tx.insert(quotes).values({ userId, data, version: 1, idempotencyKey }).returning();
      await tx.update(quoteCounters).set({ nextSeq: seq + 1 }).where(eq(quoteCounters.userId, userId));
      await tx.insert(quoteEvents).values({ userId, quoteId: row.id, eventType: 'created', metadata: {} });
      return { row, reused: false as const };
    });
    if ('limit' in result) return c.json({ error: 'Monthly quote limit reached. Upgrade to create more.' }, 403);
    const row = result.row;
    return c.json({ id: row.id, version: row.version, ...(row.data as object) }, result.reused ? 200 : 201);
  } catch (error: any) {
    if (error?.message === 'CLIENT_NOT_FOUND') return c.json({ error: 'Selected client was not found.' }, 400);
    return c.json({ error: 'Failed to create quote' }, 500);
  }
});

quotesRouter.put('/:id', async (c) => {
  const userId = c.get('userId') as string;
  const { id } = c.req.param();
  const parsed = quoteSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!parsed.success) return c.json({ error: 'Invalid quote', details: parsed.error.format() }, 400);
  try {
    const result = await db.transaction(async (tx) => {
      const existing = await tx.query.quotes.findFirst({ where: and(eq(quotes.id, id), eq(quotes.userId, userId)) });
      if (!existing) return { notFound: true as const };
      if (existing.deletedAt) return { deleted: true as const };
      const old = existing.data as any;
      if (old.status === 'accepted') return { locked: true as const };
      if (parsed.data.version !== undefined && parsed.data.version !== existing.version) return { conflict: true as const, version: existing.version };
      const enriched = await enrichClient(tx, userId, parsed.data);
      const createdAt = existing.createdAt;
      const data = normalizeData({ ...enriched, quoteNumber: old.quoteNumber, status: parsed.data.status }, createdAt, existing.version + 1);
      const [row] = await tx.update(quotes).set({ data, version: existing.version + 1, updatedAt: new Date() })
        .where(and(eq(quotes.id, id), eq(quotes.userId, userId), eq(quotes.version, existing.version))).returning();
      if (!row) return { conflict: true as const, version: existing.version };
      await tx.insert(quoteEvents).values({ userId, quoteId: id, eventType: 'updated', metadata: {} });
      return { row };
    });
    if ('notFound' in result) return c.json({ error: 'Not found' }, 404);
    if ('locked' in result) return c.json({ error: 'Accepted quotes are locked because the invoice is frozen.' }, 409);
    if ('deleted' in result) return c.json({ error: 'Deleted quotes must be restored before editing.' }, 409);
    if ('conflict' in result) return c.json({ error: 'This quote changed in another session. Reload before saving.', version: result.version }, 409);
    return c.json({ id: result.row.id, version: result.row.version, ...(result.row.data as object) });
  } catch (error: any) {
    if (error?.message === 'CLIENT_NOT_FOUND') return c.json({ error: 'Selected client was not found.' }, 400);
    return c.json({ error: 'Failed to update quote' }, 500);
  }
});

quotesRouter.post('/:id/duplicate', async (c) => {
  const userId = c.get('userId') as string;
  const tier = c.get('tier') as Tier;
  if (!TIER_LIMITS[tier].features.duplicate) return c.json({ error: 'Duplicate quotes are available on paid plans.' }, 403);
  const sourceId = c.req.param('id');
  const idempotencyKey = c.req.header('Idempotency-Key')?.trim().slice(0, 200) || null;
  try {
    const result = await db.transaction(async (tx) => {
      if (idempotencyKey) {
        const prior = await tx.query.quotes.findFirst({ where: and(eq(quotes.userId, userId), eq(quotes.idempotencyKey, idempotencyKey)) });
        if (prior) return { row: prior, reused: true as const };
      }
      await lockUser(tx, userId);
      const source = await tx.query.quotes.findFirst({ where: and(eq(quotes.id, sourceId), eq(quotes.userId, userId)) });
      if (!source) return { notFound: true as const };
      if (source.deletedAt) return { deleted: true as const };
      if (source.data && (source.data as any).status === 'accepted') return { locked: true as const };
      const [{ value }] = await tx.select({ value: count() }).from(quotes).where(and(eq(quotes.userId, userId), gte(quotes.createdAt, (() => { const d = new Date(); d.setDate(1); d.setHours(0,0,0,0); return d; })())));
      if (quoteLimitReached(tier, Number(value))) return { limit: true as const };
      await tx.insert(quoteCounters).values({ userId, nextSeq: 1 }).onConflictDoNothing();
      const [counter] = await tx.execute(sql`select next_seq from quote_counters where user_id = ${userId} for update`) as unknown as Array<{ next_seq: number }>;
      const seq = Number(counter.next_seq);
      const now = new Date();
      const sourceData = source.data as any;
      const data = normalizeData({
        ...sourceData,
        id: undefined,
        quoteNumber: `QT-${String(seq).padStart(4, '0')}`,
        status: 'draft',
        sentAt: undefined,
        clientAcceptedAt: undefined,
        clientResponseAt: undefined,
        clientResponseName: undefined,
        clientResponseMessage: undefined,
        acceptanceSource: undefined,
        invoiceShareToken: undefined,
      }, now, 1);
      const [row] = await tx.insert(quotes).values({ userId, data, version: 1, idempotencyKey }).returning();
      await tx.update(quoteCounters).set({ nextSeq: seq + 1 }).where(eq(quoteCounters.userId, userId));
      await tx.insert(quoteEvents).values({ userId, quoteId: row.id, eventType: 'created', metadata: { source: 'duplicate', sourceQuoteId: source.id } });
      return { row, reused: false as const };
    });
    if ('notFound' in result) return c.json({ error: 'Quote not found.' }, 404);
    if ('locked' in result) return c.json({ error: 'Accepted quotes are locked and cannot be duplicated.' }, 409);
    if ('limit' in result) return c.json({ error: 'Monthly quote limit reached. Upgrade to create more.' }, 403);
    return c.json({ id: result.row.id, version: result.row.version, ...(result.row.data as object) }, result.reused ? 200 : 201);
  } catch {
    return c.json({ error: 'Could not duplicate quote.' }, 500);
  }
});

quotesRouter.post('/:id/send', async (c) => {
  const userId = c.get('userId') as string;
  const id = c.req.param('id');
  const tier = c.get('tier') as Tier;
  if (!TIER_LIMITS[tier].features.clientUrl) return c.json({ error: 'Client sharing is available on paid plans.' }, 403);
  try {
    const result = await db.transaction(async (tx) => {
      const [row] = await tx.execute(sql`
        select id, user_id, data, version, deleted_at
        from quotes
        where id = ${id} and user_id = ${userId}
        for update
      `) as unknown as Array<{ id: string; user_id: string; data: any; version: number; deleted_at: Date | null }>;
      if (!row) return { notFound: true as const };
      const rawData = typeof row.data === 'string' ? JSON.parse(row.data) : row.data;
      if ((row as any).deleted_at ?? false) return { deleted: true as const };
      const q = rawData as any;
      if (q.status === 'accepted' || q.status === 'declined') return { locked: true as const };
      if (!q.clientEmail) return { noEmail: true as const };
      const token = await upsertShareLink(tx, userId, 'quote', id, q.validUntil ? new Date(q.validUntil) : null);
      const data = { ...q, status: 'sent', sentAt: new Date().toISOString() };
      const updated = await tx.update(quotes).set({ data, updatedAt: new Date(), version: row.version + 1 })
        .where(and(eq(quotes.id, id), eq(quotes.userId, userId), eq(quotes.version, row.version))).returning({ id: quotes.id });
      if (!updated.length) return { conflict: true as const };
      await tx.insert(quoteEvents).values({ userId, quoteId: id, eventType: 'sent', metadata: {} });
      return { q: data, token };
    });
    if ('notFound' in result) return c.json({ error: 'Not found' }, 404);
    if ('locked' in result) return c.json({ error: 'This quote can no longer be sent.' }, 409);
    if ('deleted' in result) return c.json({ error: 'Deleted quotes cannot be sent. Restore the quote first.' }, 409);
    if ('noEmail' in result) return c.json({ error: 'Add a client email before sending the quote.' }, 400);
    if ('conflict' in result) return c.json({ error: 'This quote changed while it was being sent. Please try again.' }, 409);
    const total = calculateTotals(result.q.items, result.q.taxPercent, result.q.discountPercent, result.q.currency);
    const business = (await db.query.businessProfiles.findFirst({ where: eq(businessProfiles.userId, userId) }))?.data ?? {};
    await enqueueEmail({
      userId,
      kind: 'quote_sent',
      quoteId: id,
      toEmail: result.q.clientEmail,
      subject: `${result.q.quoteNumber} from ${business.name || 'Business Quotes'}`,
      html: quoteEmailHtml({ business, quote: { ...result.q, totalDisplay: `${result.q.currency} ${total.total.toFixed(2)}` }, token: result.token }),
      idempotencyKey: `quote:${id}:sent:${result.q.version}`,
    });
    return c.json({ ok: true, url: `${baseUrl()}/public/quote/${result.token}`, queued: true });
  } catch {
    return c.json({ error: 'Failed to send quote' }, 500);
  }
});

quotesRouter.post('/:id/remind', async (c) => {
  const userId = c.get('userId') as string;
  const id = c.req.param('id');
  const tier = c.get('tier') as Tier;
  if (!TIER_LIMITS[tier].features.clientUrl) return c.json({ error: 'Client sharing is available on paid plans.' }, 403);
  try {
    const result = await db.transaction(async (tx) => {
      const [row] = await tx.execute(sql`
        select id, data, version, deleted_at
        from quotes
        where id = ${id} and user_id = ${userId}
        for update
      `) as unknown as Array<{ id: string; data: any; version: number; deleted_at: Date | null }>;
      if (!row) return { notFound: true as const };
      if (row.deleted_at) return { deleted: true as const };
      const q = (typeof row.data === 'string' ? JSON.parse(row.data) : row.data) as any;
      if (q.status !== 'sent') return { notAwaiting: true as const };
      if (!q.clientEmail) return { noEmail: true as const };
      const token = await upsertShareLink(tx, userId, 'quote', id, q.validUntil ? new Date(q.validUntil) : null);
      const now = new Date().toISOString();
      const updatedData = { ...q, sentAt: now };
      const updated = await tx.update(quotes).set({ data: updatedData, updatedAt: new Date(), version: row.version + 1 })
        .where(and(eq(quotes.id, id), eq(quotes.userId, userId), eq(quotes.version, row.version))).returning({ id: quotes.id });
      if (!updated.length) return { conflict: true as const };
      await tx.insert(quoteEvents).values({ userId, quoteId: id, eventType: 'sent', metadata: { source: 'manual_followup' } });
      return { q: updatedData, token };
    });
    if ('notFound' in result) return c.json({ error: 'Not found' }, 404);
    if ('deleted' in result) return c.json({ error: 'Archived quotes must be restored before following up.' }, 409);
    if ('notAwaiting' in result) return c.json({ error: 'Only quotes awaiting a client response can receive a follow-up.' }, 409);
    if ('noEmail' in result) return c.json({ error: 'Add a client email before following up.' }, 400);
    if ('conflict' in result) return c.json({ error: 'This quote changed while the follow-up was being prepared. Please try again.' }, 409);
    const total = calculateTotals(result.q.items, result.q.taxPercent, result.q.discountPercent, result.q.currency);
    const business = (await db.query.businessProfiles.findFirst({ where: eq(businessProfiles.userId, userId) }))?.data ?? {};
    await enqueueEmail({
      userId,
      kind: 'quote_sent',
      quoteId: id,
      toEmail: result.q.clientEmail,
      subject: `Following up: ${result.q.quoteNumber} from ${business.name || 'Business Quotes'}`,
      html: quoteFollowupEmailHtml({ business, quote: { ...result.q, totalDisplay: `${result.q.currency} ${total.total.toFixed(2)}` }, token: result.token }),
      idempotencyKey: `quote:${id}:followup:${result.q.version}`,
    });
    return c.json({ ok: true, queued: true });
  } catch {
    return c.json({ error: 'Failed to send follow-up' }, 500);
  }
});

async function ownerAccept(userId: string, id: string) {
  return db.transaction(async (tx) => {
    const [existing] = await tx.execute(sql`
      select id, user_id, data, version, created_at, updated_at
      from quotes
      where id = ${id} and user_id = ${userId}
      for update
    `) as unknown as Array<any>;
    if (!existing) return { notFound: true as const };
    if (existing.deleted_at) return { deleted: true as const };
    existing.data = typeof existing.data === 'string' ? JSON.parse(existing.data) : existing.data;
    existing.version = Number(existing.version);
    existing.createdAt = new Date(existing.created_at);
    const q = { ...(existing.data as any), id: existing.id };
    if (q.status === 'accepted') {
      const inv = await tx.query.invoices.findFirst({ where: eq(invoices.quoteId, id) });
      const link = inv ? await tx.query.shareLinks.findFirst({ where: and(eq(shareLinks.invoiceId, inv.id), eq(shareLinks.userId, userId), sql`${shareLinks.revokedAt} is null`) }) : null;
      return { row: { id: existing.id, version: existing.version, data: q }, invoice: inv, invoiceToken: null as string | null, existingInvoiceUrl: link ? null : null, alreadyAccepted: true as const };
    }
    if (q.status === 'declined') return { declined: true as const };
    const acceptedAt = new Date();
    if (!q.clientEmail && q.clientName) {
      // Manual owner confirmation is allowed even without an email address.
      // The audit event records that this was not a public client response.
    }
    q.status = 'accepted';
    q.clientAcceptedAt = acceptedAt.toISOString();
    q.acceptanceSource = 'owner_confirmed';
    q.version = existing.version + 1;
    const [row] = await tx.update(quotes).set({ data: q, version: existing.version + 1, updatedAt: acceptedAt })
      .where(and(eq(quotes.id, id), eq(quotes.userId, userId), eq(quotes.version, existing.version))).returning();
    if (!row) return { conflict: true as const, version: existing.version };
    const invoice = await createInvoice(tx, userId, q, acceptedAt);
    const invoiceToken = await upsertShareLink(tx, userId, 'invoice', invoice.id, null);
    await tx.insert(quoteEvents).values({ userId, quoteId: id, eventType: 'accepted', metadata: { source: 'owner_confirmed' } });
    await tx.insert(quoteEvents).values({ userId, quoteId: id, eventType: 'invoice_issued', metadata: { invoiceId: invoice.id } });
    return { row, invoice, invoiceToken };
  });
}

quotesRouter.post('/:id/accept', async (c) => {
  const userId = c.get('userId') as string;
  const body = await c.req.json().catch(() => ({}));
  if (body?.confirmedByClient !== true) return c.json({ error: 'Client acceptance must be confirmed before invoicing.' }, 400);
  try {
    const result = await ownerAccept(userId, c.req.param('id'));
    if ('notFound' in result) return c.json({ error: 'Not found' }, 404);
    if ('declined' in result) return c.json({ error: 'A declined quote cannot be accepted.' }, 409);
    if ('deleted' in result) return c.json({ error: 'Deleted quotes must be restored before acceptance.' }, 409);
    if ('alreadyAccepted' in result) return c.json({ id: result.row.id, version: result.row.version, ...(result.row.data as object), invoice: result.invoice, alreadyAccepted: true });
    const business = (await db.query.businessProfiles.findFirst({ where: eq(businessProfiles.userId, userId) }))?.data ?? {};
    if (result.invoice && result.invoiceToken && result.row.data && (result.row.data as any).clientEmail) {
      const qd = result.row.data as any;
      const total = calculateTotals(qd.items, qd.taxPercent, qd.discountPercent, qd.currency);
      await enqueueEmail({ userId, kind: 'invoice_issued', invoiceId: result.invoice.id, toEmail: qd.clientEmail, subject: `${result.invoice.invoiceNumber} from ${business.name || 'Business Quotes'}`, html: invoiceEmailHtml({ business, invoice: { ...qd, invoiceNumber: result.invoice.invoiceNumber, totalDisplay: `${qd.currency} ${total.total.toFixed(2)}`, dueDisplay: result.invoice.dueAt?.toISOString() ?? '' }, token: result.invoiceToken }), idempotencyKey: `invoice:${result.invoice.id}:issued` });
    }
    return c.json({ id: result.row.id, version: result.row.version, ...(result.row.data as object), invoice: result.invoice, invoiceUrl: result.invoiceToken ? `${baseUrl()}/public/invoice/${result.invoiceToken}` : null, alreadyAccepted: false });
  } catch {
    return c.json({ error: 'Failed to accept quote' }, 500);
  }
});

quotesRouter.delete('/:id', async (c) => {
  const userId = c.get('userId') as string;
  const { id } = c.req.param();
  const result = await db.transaction(async (tx) => {
    const [row] = await tx.execute(sql`select id, deleted_at from quotes where id = ${id} and user_id = ${userId} for update`) as unknown as Array<{ id: string; deleted_at: Date | null }>;
    if (!row) return { notFound: true as const };
    if (row.deleted_at) return { alreadyDeleted: true as const };
    const now = new Date();
    await tx.update(quotes).set({ deletedAt: now, deletedBy: userId, updatedAt: now }).where(and(eq(quotes.id, id), eq(quotes.userId, userId)));
    await tx.update(shareLinks).set({ revokedAt: now }).where(and(eq(shareLinks.quoteId, id), sql`${shareLinks.revokedAt} is null`));
    await tx.update(emailJobs).set({ status: 'failed', lastError: 'Document archived before delivery.' }).where(and(eq(emailJobs.quoteId, id), eq(emailJobs.status, 'pending')));
    await tx.insert(quoteEvents).values({ userId, quoteId: id, eventType: 'deleted', metadata: { mode: 'soft_delete' } });
    return { ok: true as const };
  });
  if ('notFound' in result) return c.json({ error: 'Not found' }, 404);
  if ('alreadyDeleted' in result) return c.json({ error: 'Quote is already deleted.' }, 409);
  return c.json({ ok: true, softDeleted: true });
});

quotesRouter.post('/:id/restore', async (c) => {
  const userId = c.get('userId') as string;
  const { id } = c.req.param();
  const restored = await db.transaction(async (tx) => {
    const [row] = await tx.execute(sql`select id, deleted_at from quotes where id = ${id} and user_id = ${userId} for update`) as unknown as Array<{ id: string; deleted_at: Date | null }>;
    if (!row) return { notFound: true as const };
    if (!row.deleted_at) return { active: true as const };
    const now = new Date();
    await tx.update(quotes).set({ deletedAt: null, deletedBy: null, updatedAt: now }).where(eq(quotes.id, id));
    await tx.insert(quoteEvents).values({ userId, quoteId: id, eventType: 'restored', metadata: { mode: 'soft_delete_restore' } });
    return { ok: true as const };
  });
  if ('notFound' in restored) return c.json({ error: 'Not found' }, 404);
  if ('active' in restored) return c.json({ error: 'Quote is already active.' }, 409);
  return c.json({ ok: true });
});


quotesRouter.get('/:id/pdf', async (c) => {
  const userId = c.get('userId') as string;
  const row = await db.query.quotes.findFirst({ where: and(eq(quotes.id, c.req.param('id')), eq(quotes.userId, userId)) });
  if (!row) return c.json({ error: 'Not found' }, 404);
  try {
    const business = (await db.query.businessProfiles.findFirst({ where: eq(businessProfiles.userId, userId) }))?.data ?? {};
    const result = await renderQuotePdf({ id: row.id, version: row.version, deletedAt: row.deletedAt, ...(row.data as object) }, business);
    c.header('Content-Type', 'application/pdf');
    c.header('Content-Disposition', `attachment; filename="${result.filename}"`);
    c.header('Content-Length', String(result.pdf.byteLength));
    return c.body(result.pdf as any);
  } catch (error) {
    console.error('[pdf] quote', error);
    return c.json({ error: 'Could not generate PDF.' }, 500);
  }
});

quotesRouter.get('/:id/events', async (c) => {
  const userId = c.get('userId') as string;
  const row = await db.query.quotes.findFirst({ where: and(eq(quotes.id, c.req.param('id')), eq(quotes.userId, userId)) });
  if (!row) return c.json({ error: 'Not found' }, 404);
  return c.json(await db.query.quoteEvents.findMany({ where: eq(quoteEvents.quoteId, row.id), orderBy: (e, { desc }) => [desc(e.createdAt)] }));
});

// Public capability URLs. These do not require a session cookie.
export const publicQuotesRouter = new Hono();

publicQuotesRouter.get('/:token', async (c) => {
  const tokenHash = hashSecret(c.req.param('token'));
  const link = await db.query.shareLinks.findFirst({ where: and(eq(shareLinks.tokenHash, tokenHash), sql`${shareLinks.revokedAt} is null`) });
  if (!link?.quoteId) return c.json({ error: 'Link not found or expired.' }, 404);
  const row = await db.query.quotes.findFirst({ where: eq(quotes.id, link.quoteId) });
  if (!row) return c.json({ error: 'Quote not found.' }, 404);
  if (row.deletedAt) return c.json({ error: 'This quote is no longer available.' }, 410);
  const q = row.data as any;
  const expired = Boolean(link.expiresAt && link.expiresAt.getTime() <= Date.now());
  await db.insert(quoteEvents).values({ userId: row.userId, quoteId: row.id, eventType: 'viewed', metadata: {}, ipHash: hashRequestIdentifier(getClientIp(c.req.raw)), userAgent: c.req.header('user-agent')?.slice(0, 500) });
  const business = (await db.query.businessProfiles.findFirst({ where: eq(businessProfiles.userId, row.userId) }))?.data ?? {};
  return c.json({ quote: { id: row.id, version: row.version, ...q }, business, expired, canRespond: !expired && ['draft', 'sent'].includes(q.status) });
});


publicQuotesRouter.get('/:token/pdf', async (c) => {
  const token = c.req.param('token');
  const tokenHash = hashSecret(token);
  const link = await db.query.shareLinks.findFirst({ where: and(eq(shareLinks.tokenHash, tokenHash), sql`${shareLinks.revokedAt} is null`) });
  if (!link?.quoteId) return c.json({ error: 'Link not found or expired.' }, 404);
  const row = await db.query.quotes.findFirst({ where: eq(quotes.id, link.quoteId) });
  if (!row) return c.json({ error: 'Quote not found.' }, 404);
  if (row.deletedAt) return c.json({ error: 'This quote is no longer available.' }, 410);
  try {
    const business = (await db.query.businessProfiles.findFirst({ where: eq(businessProfiles.userId, row.userId) }))?.data ?? {};
    const result = await renderQuotePdf({ id: row.id, version: row.version, ...(row.data as object) }, business);
    c.header('Content-Type', 'application/pdf');
    c.header('Content-Disposition', `attachment; filename="${result.filename}"`);
    c.header('Content-Length', String(result.pdf.byteLength));
    return c.body(result.pdf as any);
  } catch (error) {
    console.error('[pdf] public quote', error);
    return c.json({ error: 'Could not generate PDF.' }, 500);
  }
});

publicQuotesRouter.post('/:token/respond', async (c) => {
  const parsed = quoteResponseSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!parsed.success) return c.json({ error: 'Invalid response', details: parsed.error.format() }, 400);
  const tokenHash = hashSecret(c.req.param('token'));
  try {
    const result = await db.transaction(async (tx) => {
      const link = await tx.query.shareLinks.findFirst({ where: and(eq(shareLinks.tokenHash, tokenHash), sql`${shareLinks.revokedAt} is null`) });
      if (!link?.quoteId) return { notFound: true as const };
      const existing = await tx.query.quotes.findFirst({ where: eq(quotes.id, link.quoteId) });
      if (!existing) return { notFound: true as const };
      if (existing.deletedAt) return { deleted: true as const };
      const q = { ...(existing.data as any), id: existing.id };
      if (q.status === 'accepted') return { already: 'accepted' as const, quote: q };
      if (q.status === 'declined') return { already: 'declined' as const, quote: q };
      if (link.expiresAt && link.expiresAt.getTime() <= Date.now()) return { expired: true as const };
      const now = new Date();
      q.status = parsed.data.action === 'accept' ? 'accepted' : 'declined';
      q.clientResponseName = parsed.data.name;
      q.clientResponseMessage = parsed.data.message;
      q.clientResponseSignature = parsed.data.signature || parsed.data.name;
      q.clientResponseAt = now.toISOString();
      q.acceptanceSource = 'public_link';
      q.version = existing.version + 1;
      const [row] = await tx.update(quotes).set({ data: q, version: existing.version + 1, updatedAt: now })
        .where(and(eq(quotes.id, existing.id), eq(quotes.version, existing.version))).returning();
      if (!row) return { conflict: true as const };
      await tx.insert(quoteEvents).values({ userId: row.userId, quoteId: row.id, eventType: parsed.data.action === 'accept' ? 'accepted' : 'declined', metadata: { source: 'public_link', name: parsed.data.name, hasMessage: Boolean(parsed.data.message) }, ipHash: hashRequestIdentifier(getClientIp(c.req.raw)), userAgent: c.req.header('user-agent')?.slice(0, 500) });
      let invoice = null;
      if (parsed.data.action === 'accept') {
        invoice = await createInvoice(tx, row.userId, q, now);
        await tx.insert(quoteEvents).values({ userId: row.userId, quoteId: row.id, eventType: 'invoice_issued', metadata: { invoiceId: invoice.id } });
        const invoiceToken = await upsertShareLink(tx, row.userId, 'invoice', invoice.id, null);
        q.invoiceShareToken = invoiceToken;
        await tx.update(quotes).set({ data: q }).where(eq(quotes.id, row.id));
        return { row, quote: q, invoice, invoiceToken };
      }
      return { row, quote: q, invoice: null, invoiceToken: null };
    });
    if ('notFound' in result) return c.json({ error: 'Link not found or expired.' }, 404);
    if ('expired' in result) return c.json({ error: 'This quote is no longer open for response.' }, 410);
    if ('deleted' in result) return c.json({ error: 'This quote is no longer available.' }, 410);
    if ('conflict' in result) return c.json({ error: 'Someone already responded to this quote. Refresh the page.' }, 409);
    if ('already' in result) return c.json({ ok: true, status: result.already, quote: result.quote }, 200);
    if (result.invoice) {
      if (!result.quote.clientEmail) return c.json({ ok: true, status: 'accepted', invoice: { id: result.invoice.id, invoiceNumber: result.invoice.invoiceNumber, url: `${baseUrl()}/public/invoice/${result.invoiceToken}` }, emailQueued: false });
      const business = (await db.query.businessProfiles.findFirst({ where: eq(businessProfiles.userId, result.row.userId) }))?.data ?? {};
      const total = calculateTotals(result.quote.items, result.quote.taxPercent, result.quote.discountPercent, result.quote.currency);
      await enqueueEmail({ userId: result.row.userId, kind: 'invoice_issued', invoiceId: result.invoice.id, toEmail: result.quote.clientEmail || '', subject: `${result.invoice.invoiceNumber} from ${business.name || 'Business Quotes'}`, html: invoiceEmailHtml({ business, invoice: { ...result.quote, invoiceNumber: result.invoice.invoiceNumber, totalDisplay: `${result.quote.currency} ${total.total.toFixed(2)}`, dueDisplay: result.invoice.dueAt?.toISOString() ?? '' }, token: result.invoiceToken! }), idempotencyKey: `invoice:${result.invoice.id}:issued` });
      return c.json({ ok: true, status: 'accepted', invoice: { id: result.invoice.id, invoiceNumber: result.invoice.invoiceNumber, url: `${baseUrl()}/public/invoice/${result.invoiceToken}` } });
    }
    return c.json({ ok: true, status: 'declined' });
  } catch {
    return c.json({ error: 'Could not record your response.' }, 500);
  }
});
