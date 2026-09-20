import { randomUUID } from 'node:crypto';
import { Hono } from 'hono';
import type { AppEnv } from '../lib/hono-env';
import { db } from '../db';
import { invoices, invoicePayments, shareLinks, businessProfiles, invoiceEvents, emailJobs } from '../db/schema';
import { and, asc, desc, eq, sql } from 'drizzle-orm';
import { withTier } from '../lib/tier';
import { invoicePaymentSchema } from '../lib/schemas';
import { fromMinor, toMinor } from '../lib/finance';
import { hashSecret, getClientIp, hashRequestIdentifier } from '../lib/security';
import { upsertShareLink } from '../lib/share-links';
import { enqueueEmail } from '../lib/email-outbox';
import { invoiceEmailHtml, invoiceReminderEmailHtml } from '../lib/billing-jobs';
import { renderInvoicePdf } from '../lib/pdf';

export const invoicesRouter = new Hono<AppEnv>();
invoicesRouter.use('*', withTier);

function publicUrl(token: string) { return `${(process.env.CLIENT_URL ?? 'http://localhost:5173').replace(/\/+$/, '')}/public/invoice/${token}`; }

invoicesRouter.get('/', async (c) => {
  const userId = c.get('userId') as string;
  const deletedOnly = c.req.query('deletedOnly') === '1';
  const rows = await db.query.invoices.findMany({ where: deletedOnly ? and(eq(invoices.userId, userId), sql`${invoices.deletedAt} is not null`) : and(eq(invoices.userId, userId), sql`${invoices.deletedAt} is null`), orderBy: [desc(invoices.createdAt)], limit: 250 });
  return c.json(rows.map(r => {
    const balanceMinor = Math.max(0, r.amountMinor - r.amountPaidMinor);
    const overdue = r.status !== 'paid' && r.status !== 'void' && Boolean(r.dueAt && r.dueAt.getTime() < Date.now());
    return { id: r.id, quoteId: r.quoteId, status: overdue ? 'overdue' : r.status, deletedAt: r.deletedAt, createdAt: r.createdAt, dueAt: r.dueAt, amountMinor: r.amountMinor, amountPaidMinor: r.amountPaidMinor, balance: fromMinor(balanceMinor, r.currency), ...(r.data as object) };
  }));
});


invoicesRouter.post('/:id/share', async (c) => {
  const userId = c.get('userId') as string;
  const created = await db.transaction(async (tx) => {
    const [invoice] = await tx.execute(sql`select id, deleted_at from invoices where id = ${c.req.param('id')} and user_id = ${userId} for update`) as unknown as Array<{ id: string; deleted_at: Date | null }>;
    if (!invoice || invoice.deleted_at) return null;
    const token = await upsertShareLink(tx, userId, 'invoice', invoice.id, null);
    await tx.insert(invoiceEvents).values({ userId, invoiceId: invoice.id, eventType: 'sent', metadata: { source: 'share_link' } });
    return token;
  });
  if (!created) return c.json({ error: 'Not found or archived.' }, 404);
  return c.json({ ok: true, url: publicUrl(created) });
});

function displayMoney(minor: number, currency: string) {
  try {
    return new Intl.NumberFormat('en-US', { style: 'currency', currency }).format(fromMinor(Number(minor || 0), currency));
  } catch {
    return `${currency} ${fromMinor(Number(minor || 0), currency).toFixed(currency === 'JPY' ? 0 : 2)}`;
  }
}

function displayDate(value?: Date | null) {
  return value ? new Intl.DateTimeFormat('en', { day: 'numeric', month: 'short', year: 'numeric' }).format(value) : 'On receipt';
}

invoicesRouter.post('/:id/send', async (c) => {
  const userId = c.get('userId') as string;
  const id = c.req.param('id');
  try {
    const result = await db.transaction(async (tx) => {
      const [row] = await tx.execute(sql`select id, invoice_number, status, currency, amount_minor, amount_paid_minor, due_at, client_email, data, deleted_at from invoices where id = ${id} and user_id = ${userId} for update`) as unknown as Array<any>;
      if (!row) return { notFound: true as const };
      if (row.deleted_at) return { deleted: true as const };
      if (row.status === 'void') return { void: true as const };
      if (!row.client_email) return { noEmail: true as const };
      const token = await upsertShareLink(tx, userId, 'invoice', id, null);
      const now = new Date();
      await tx.update(invoices).set({ sentAt: now, updatedAt: now }).where(and(eq(invoices.id, id), eq(invoices.userId, userId)));
      await tx.insert(invoiceEvents).values({ userId, invoiceId: id, eventType: 'sent', metadata: { source: 'manual_send' } });
      return { row, token };
    });
    if ('notFound' in result) return c.json({ error: 'Not found' }, 404);
    if ('deleted' in result) return c.json({ error: 'Archived invoices must be restored before sending.' }, 409);
    if ('void' in result) return c.json({ error: 'Void invoices cannot be sent.' }, 409);
    if ('noEmail' in result) return c.json({ error: 'Add a client email before sending the invoice.' }, 400);
    const business = (await db.query.businessProfiles.findFirst({ where: eq(businessProfiles.userId, userId) }))?.data ?? {};
    const data = typeof result.row.data === 'string' ? JSON.parse(result.row.data) : result.row.data;
    await enqueueEmail({
      userId, kind: 'invoice_issued', invoiceId: id, toEmail: result.row.client_email,
      subject: `${result.row.invoice_number} from ${business.name || 'Business Quotes'}`,
      html: invoiceEmailHtml({ business, invoice: { ...data, invoiceNumber: result.row.invoice_number, totalDisplay: displayMoney(result.row.amount_minor, result.row.currency), dueDisplay: displayDate(result.row.due_at) }, token: result.token }),
      idempotencyKey: `invoice:${id}:manual-send:${randomUUID()}`,
    });
    return c.json({ ok: true, url: publicUrl(result.token), queued: true });
  } catch {
    return c.json({ error: 'Failed to send invoice.' }, 500);
  }
});

invoicesRouter.post('/:id/remind', async (c) => {
  const userId = c.get('userId') as string;
  const id = c.req.param('id');
  try {
    const result = await db.transaction(async (tx) => {
      const [row] = await tx.execute(sql`select id, invoice_number, currency, amount_minor, amount_paid_minor, status, due_at, client_email, data, deleted_at from invoices where id = ${id} and user_id = ${userId} for update`) as unknown as Array<any>;
      if (!row) return { notFound: true as const };
      if (row.deleted_at) return { deleted: true as const };
      if (row.status === 'void') return { void: true as const };
      if (row.status === 'paid' || Number(row.amount_paid_minor) >= Number(row.amount_minor)) return { paid: true as const };
      if (!row.client_email) return { noEmail: true as const };
      const token = await upsertShareLink(tx, userId, 'invoice', id, null);
      await tx.insert(invoiceEvents).values({ userId, invoiceId: id, eventType: 'sent', metadata: { source: 'manual_reminder' } });
      return { row, token };
    });
    if ('notFound' in result) return c.json({ error: 'Not found' }, 404);
    if ('deleted' in result) return c.json({ error: 'Archived invoices must be restored before sending reminders.' }, 409);
    if ('void' in result) return c.json({ error: 'Void invoices cannot receive reminders.' }, 409);
    if ('paid' in result) return c.json({ error: 'Paid invoices do not need a reminder.' }, 409);
    if ('noEmail' in result) return c.json({ error: 'Add a client email before sending a reminder.' }, 400);
    const business = (await db.query.businessProfiles.findFirst({ where: eq(businessProfiles.userId, userId) }))?.data ?? {};
    const data = typeof result.row.data === 'string' ? JSON.parse(result.row.data) : result.row.data;
    const balanceMinor = Math.max(0, Number(result.row.amount_minor) - Number(result.row.amount_paid_minor));
    await enqueueEmail({
      userId, kind: 'invoice_reminder', invoiceId: id, toEmail: result.row.client_email,
      subject: `${result.row.invoice_number} payment reminder`,
      html: invoiceReminderEmailHtml({ business, invoice: { ...data, invoiceNumber: result.row.invoice_number, balanceDisplay: displayMoney(balanceMinor, result.row.currency), dueDisplay: displayDate(result.row.due_at) }, token: result.token }),
      idempotencyKey: `invoice:${id}:manual-reminder:${crypto.randomUUID()}`,
    });
    return c.json({ ok: true, queued: true });
  } catch {
    return c.json({ error: 'Failed to send reminder.' }, 500);
  }
});

invoicesRouter.post('/:id/payments', async (c) => {
  const userId = c.get('userId') as string;
  const key = c.req.header('Idempotency-Key')?.trim();
  if (!key) return c.json({ error: 'Idempotency-Key header is required for payments.' }, 400);
  const parsed = invoicePaymentSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!parsed.success) return c.json({ error: 'Invalid payment', details: parsed.error.format() }, 400);

  try {
    const result = await db.transaction(async (tx) => {
      const existingPayment = await tx.query.invoicePayments.findFirst({ where: and(eq(invoicePayments.userId, userId), eq(invoicePayments.idempotencyKey, key)) });
      if (existingPayment && existingPayment.invoiceId !== c.req.param('id')) return { idempotencyConflict: true as const };
      const [invoice] = await tx.execute(sql`select id, currency, amount_minor, amount_paid_minor, status, due_at, deleted_at from invoices where id = ${c.req.param('id')} and user_id = ${userId} for update`) as unknown as Array<any>;
      if (existingPayment) {
        if (invoice?.deleted_at) return { deleted: true as const };
        return { payment: existingPayment, reused: true as const };
      }
      if (!invoice) return { notFound: true as const };
      if (invoice.deleted_at) return { deleted: true as const };
      if (invoice.status === 'void') return { void: true as const };
      if (invoice.status === 'paid') return { paid: true as const };
      const amountMinor = toMinor(parsed.data.amount, invoice.currency);
      const balanceMinor = Number(invoice.amount_minor) - Number(invoice.amount_paid_minor);
      if (amountMinor <= 0 || amountMinor > balanceMinor) return { over: true as const, balance: fromMinor(balanceMinor, invoice.currency) };
      const [payment] = await tx.insert(invoicePayments).values({
        userId, invoiceId: invoice.id, idempotencyKey: key, amountMinor, currency: invoice.currency,
        method: parsed.data.method, note: parsed.data.note || null,
        receivedAt: parsed.data.receivedAt ? new Date(parsed.data.receivedAt) : new Date(),
      }).returning();
      const paidMinor = Number(invoice.amount_paid_minor) + amountMinor;
      const status = paidMinor >= Number(invoice.amount_minor) ? 'paid' : (Number(invoice.due_at ? new Date(invoice.due_at).getTime() : Date.now()) < Date.now() ? 'overdue' : 'partially_paid');
      await tx.update(invoices).set({ amountPaidMinor: paidMinor, status, paidAt: status === 'paid' ? new Date() : null, updatedAt: new Date() }).where(and(eq(invoices.id, invoice.id), eq(invoices.userId, userId)));
      await tx.insert(invoiceEvents).values({ userId, invoiceId: invoice.id, eventType: 'payment_received', metadata: { paymentId: payment.id, amountMinor, status } });
      if (status === 'paid') await tx.insert(invoiceEvents).values({ userId, invoiceId: invoice.id, eventType: 'paid', metadata: { paymentId: payment.id } });
      return { payment, status, balanceMinor: Number(invoice.amount_minor) - paidMinor, dueAt: invoice.due_at ? new Date(invoice.due_at) : null };
    });
    if ('idempotencyConflict' in result) return c.json({ error: 'Idempotency-Key was already used for a different invoice.' }, 409);
    if ('notFound' in result) return c.json({ error: 'Not found' }, 404);
    if ('void' in result) return c.json({ error: 'Void invoices cannot receive payments.' }, 409);
    if ('deleted' in result) return c.json({ error: 'Deleted invoices cannot receive payments. Restore the invoice first.' }, 409);
    if ('paid' in result) return c.json({ error: 'Invoice is already paid.' }, 409);
    if ('over' in result) return c.json({ error: `Payment exceeds the remaining balance of ${result.balance}.` }, 400);
    return c.json({ ok: true, payment: result.payment, status: result.status, balance: fromMinor(result.balanceMinor, result.payment.currency) }, result.reused ? 200 : 201);
  } catch {
    return c.json({ error: 'Failed to record payment' }, 500);
  }
});

invoicesRouter.patch('/:id/status', async (c) => {
  const userId = c.get('userId') as string;
  const body = await c.req.json().catch(() => ({})) as any;
  const status = body?.status;
  if (!['void', 'unpaid'].includes(status)) return c.json({ error: 'Only void or reopen-to-unpaid is allowed here.' }, 400);
  const result = await db.transaction(async (tx) => {
    const [current] = await tx.execute(sql`select id, status, amount_paid_minor, deleted_at from invoices where id = ${c.req.param('id')} and user_id = ${userId} for update`) as unknown as Array<any>;
    if (!current) return { notFound: true as const };
    if (current.deleted_at) return { deleted: true as const };
    if (status === 'unpaid' && Number(current.amount_paid_minor) > 0) return { paidHistory: true as const };
    const now = new Date();
    const [row] = await tx.update(invoices).set({ status, voidedAt: status === 'void' ? now : null, updatedAt: now }).where(and(eq(invoices.id, c.req.param('id')), eq(invoices.userId, userId))).returning();
    await tx.insert(invoiceEvents).values({ userId, invoiceId: row.id, eventType: status === 'void' ? 'voided' : 'reopened', metadata: { previousStatus: current.status } });
    return { row };
  });
  if ('notFound' in result) return c.json({ error: 'Not found' }, 404);
  if ('deleted' in result) return c.json({ error: 'Deleted invoices must be restored before changing status.' }, 409);
  if ('paidHistory' in result) return c.json({ error: 'An invoice with recorded payments cannot be reset to unpaid.' }, 409);
  return c.json({ ok: true });
});

invoicesRouter.delete('/:id', async (c) => {
  const userId = c.get('userId') as string;
  const result = await db.transaction(async (tx) => {
    const [row] = await tx.execute(sql`select id, deleted_at, status from invoices where id = ${c.req.param('id')} and user_id = ${userId} for update`) as unknown as Array<any>;
    if (!row) return { notFound: true as const };
    if (row.deleted_at) return { alreadyDeleted: true as const };
    const now = new Date();
    await tx.update(invoices).set({ deletedAt: now, deletedBy: userId, updatedAt: now }).where(and(eq(invoices.id, row.id), eq(invoices.userId, userId)));
    await tx.update(shareLinks).set({ revokedAt: now }).where(and(eq(shareLinks.invoiceId, row.id), sql`${shareLinks.revokedAt} is null`));
    await tx.update(emailJobs).set({ status: 'failed', lastError: 'Document archived before delivery.' }).where(and(eq(emailJobs.invoiceId, row.id), eq(emailJobs.status, 'pending')));
    await tx.insert(invoiceEvents).values({ userId, invoiceId: row.id, eventType: 'deleted', metadata: { mode: 'soft_delete', previousStatus: row.status } });
    return { ok: true as const };
  });
  if ('notFound' in result) return c.json({ error: 'Not found' }, 404);
  if ('alreadyDeleted' in result) return c.json({ error: 'Invoice is already deleted.' }, 409);
  return c.json({ ok: true, softDeleted: true });
});

invoicesRouter.post('/:id/restore', async (c) => {
  const userId = c.get('userId') as string;
  const result = await db.transaction(async (tx) => {
    const [row] = await tx.execute(sql`select id, deleted_at from invoices where id = ${c.req.param('id')} and user_id = ${userId} for update`) as unknown as Array<any>;
    if (!row) return { notFound: true as const };
    if (!row.deleted_at) return { active: true as const };
    const now = new Date();
    await tx.update(invoices).set({ deletedAt: null, deletedBy: null, updatedAt: now }).where(and(eq(invoices.id, row.id), eq(invoices.userId, userId)));
    await tx.insert(invoiceEvents).values({ userId, invoiceId: row.id, eventType: 'restored', metadata: { mode: 'soft_delete_restore' } });
    return { ok: true as const };
  });
  if ('notFound' in result) return c.json({ error: 'Not found' }, 404);
  if ('active' in result) return c.json({ error: 'Invoice is already active.' }, 409);
  return c.json({ ok: true });
});


invoicesRouter.get('/:id/pdf', async (c) => {
  const userId = c.get('userId') as string;
  const invoice = await db.query.invoices.findFirst({ where: and(eq(invoices.id, c.req.param('id')), eq(invoices.userId, userId)) });
  if (!invoice) return c.json({ error: 'Not found' }, 404);
  try {
    const [businessRow, payments] = await Promise.all([
      db.query.businessProfiles.findFirst({ where: eq(businessProfiles.userId, userId) }),
      db.query.invoicePayments.findMany({ where: eq(invoicePayments.invoiceId, invoice.id), orderBy: (p, { asc }) => [asc(p.receivedAt)] }),
    ]);
    const result = await renderInvoicePdf(invoice, businessRow?.data ?? {}, payments);
    c.header('Content-Type', 'application/pdf');
    c.header('Content-Disposition', `attachment; filename="${result.filename}"`);
    c.header('Content-Length', String(result.pdf.byteLength));
    return c.body(result.pdf as any);
  } catch (error) {
    console.error('[pdf] invoice', error);
    return c.json({ error: 'Could not generate PDF.' }, 500);
  }
});

invoicesRouter.get('/:id/events', async (c) => {
  const userId = c.get('userId') as string;
  const row = await db.query.invoices.findFirst({ where: and(eq(invoices.id, c.req.param('id')), eq(invoices.userId, userId)) });
  if (!row) return c.json({ error: 'Not found' }, 404);
  return c.json(await db.query.invoiceEvents.findMany({ where: eq(invoiceEvents.invoiceId, row.id), orderBy: (e, { desc }) => [desc(e.createdAt)] }));
});

export const publicInvoicesRouter = new Hono();

publicInvoicesRouter.get('/:token/pdf', async (c) => {
  const token = c.req.param('token');
  const tokenHash = hashSecret(token);
  const link = await db.query.shareLinks.findFirst({ where: and(eq(shareLinks.tokenHash, tokenHash), sql`${shareLinks.revokedAt} is null`) });
  if (!link?.invoiceId) return c.json({ error: 'Invoice link not found or expired.' }, 404);
  const invoice = await db.query.invoices.findFirst({ where: eq(invoices.id, link.invoiceId) });
  if (!invoice) return c.json({ error: 'Invoice not found.' }, 404);
  if (invoice.deletedAt) return c.json({ error: 'This invoice is no longer available.' }, 410);
  try {
    const [businessRow, payments] = await Promise.all([
      db.query.businessProfiles.findFirst({ where: eq(businessProfiles.userId, invoice.userId) }),
      db.query.invoicePayments.findMany({ where: eq(invoicePayments.invoiceId, invoice.id), orderBy: (p, { asc }) => [asc(p.receivedAt)] }),
    ]);
    const result = await renderInvoicePdf(invoice, businessRow?.data ?? {}, payments);
    c.header('Content-Type', 'application/pdf');
    c.header('Content-Disposition', `attachment; filename="${result.filename}"`);
    c.header('Content-Length', String(result.pdf.byteLength));
    return c.body(result.pdf as any);
  } catch (error) {
    console.error('[pdf] public invoice', error);
    return c.json({ error: 'Could not generate PDF.' }, 500);
  }
});

publicInvoicesRouter.get('/:token', async (c) => {
  const tokenHash = hashSecret(c.req.param('token'));
  const link = await db.query.shareLinks.findFirst({ where: and(eq(shareLinks.tokenHash, tokenHash), sql`${shareLinks.revokedAt} is null`) });
  if (!link?.invoiceId) return c.json({ error: 'Invoice link not found or expired.' }, 404);
  const invoice = await db.query.invoices.findFirst({ where: eq(invoices.id, link.invoiceId) });
  if (!invoice) return c.json({ error: 'Invoice not found.' }, 404);
  if (invoice.deletedAt) return c.json({ error: 'This invoice is no longer available.' }, 410);
  const business = (await db.query.businessProfiles.findFirst({ where: eq(businessProfiles.userId, invoice.userId) }))?.data ?? {};
  const payments = await db.query.invoicePayments.findMany({ where: eq(invoicePayments.invoiceId, invoice.id), orderBy: [desc(invoicePayments.receivedAt)] });
  const overdue = invoice.status !== 'paid' && invoice.status !== 'void' && Boolean(invoice.dueAt && invoice.dueAt.getTime() < Date.now());
  await db.insert(invoiceEvents).values({ userId: invoice.userId, invoiceId: invoice.id, eventType: 'viewed', metadata: { source: 'public_link' }, ipHash: hashRequestIdentifier(getClientIp(c.req.raw)), userAgent: c.req.header('user-agent')?.slice(0, 500) });
  return c.json({
    invoice: { id: invoice.id, invoiceNumber: invoice.invoiceNumber, status: overdue ? 'overdue' : invoice.status, currency: invoice.currency, amountMinor: invoice.amountMinor, amountPaidMinor: invoice.amountPaidMinor, dueAt: invoice.dueAt, createdAt: invoice.createdAt, ...(invoice.data as any) },
    payments: payments.map(p => ({ id: p.id, amount: fromMinor(p.amountMinor, p.currency), method: p.method, receivedAt: p.receivedAt })),
    balance: fromMinor(Math.max(0, invoice.amountMinor - invoice.amountPaidMinor), invoice.currency),
    business: { name: business.name, email: business.email, phone: business.phone, address: business.address, taxId: business.taxId, logo: business.logo, paymentInstructions: business.paymentInstructions, terms: business.terms },
    url: publicUrl(c.req.param('token')),
  });
});
