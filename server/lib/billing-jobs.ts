import { db } from '../db';
import { businessProfiles, invoices, emailJobs, shareLinks } from '../db/schema';
import { and, eq, gte, lte, lt, inArray, sql } from 'drizzle-orm';
import { enqueueEmail } from './email-outbox';
import { decryptSecret } from './security';
import { upsertShareLink } from './share-links';

function esc(value: unknown) {
  return String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function appUrl(path: string) {
  return `${(process.env.CLIENT_URL ?? 'http://localhost:5173').replace(/\/+$/, '')}${path}`;
}

export function quoteEmailHtml(opts: { business: any; quote: any; token: string }) {
  return `<!doctype html><html><body style="font-family:Arial,sans-serif;color:#1e2430;line-height:1.5;max-width:680px;margin:0 auto;padding:24px">
  <h1 style="font-size:22px">${esc(opts.business?.name || 'Business Quotes')}</h1>
  <p>Your quote <strong>${esc(opts.quote.quoteNumber)}</strong> is ready to review.</p>
  <p><strong>${esc(opts.quote.title || 'Quote')}</strong><br/>Total: ${esc(String(opts.quote.totalDisplay || opts.quote.total || ''))}</p>
  <p><a href="${esc(appUrl(`/public/quote/${opts.token}`))}" style="display:inline-block;padding:10px 16px;background:#3b6b8a;color:#fff;text-decoration:none">Review quote</a></p>
  <p style="font-size:12px;color:#6b7280">You can review the quote online and record your acceptance or decline.</p>
  </body></html>`;
}

export function invoiceEmailHtml(opts: { business: any; invoice: any; token: string }) {
  return `<!doctype html><html><body style="font-family:Arial,sans-serif;color:#1e2430;line-height:1.5;max-width:680px;margin:0 auto;padding:24px">
  <h1 style="font-size:22px">${esc(opts.business?.name || 'Business Quotes')}</h1>
  <p>Invoice <strong>${esc(opts.invoice.invoiceNumber)}</strong> is ready.</p>
  <p>Total: <strong>${esc(String(opts.invoice.totalDisplay || ''))}</strong></p>
  <p>Due: <strong>${esc(String(opts.invoice.dueDisplay || 'On receipt'))}</strong></p>
  <p><a href="${esc(appUrl(`/public/invoice/${opts.token}`))}" style="display:inline-block;padding:10px 16px;background:#3b6b8a;color:#fff;text-decoration:none">View invoice</a></p>
  </body></html>`;
}

export function quoteFollowupEmailHtml(opts: { business: any; quote: any; token: string }) {
  return `<!doctype html><html><body style="font-family:Arial,sans-serif;color:#1e2430;line-height:1.5;max-width:680px;margin:0 auto;padding:24px">
  <h1 style="font-size:22px">${esc(opts.business?.name || 'Business Quotes')}</h1>
  <p>Just following up on quote <strong>${esc(opts.quote.quoteNumber)}</strong>.</p>
  <p><strong>${esc(opts.quote.title || 'Quote')}</strong><br/>Total: <strong>${esc(String(opts.quote.totalDisplay || ''))}</strong></p>
  <p><a href="${esc(appUrl(`/public/quote/${opts.token}`))}" style="display:inline-block;padding:10px 16px;background:#3b6b8a;color:#fff;text-decoration:none">Review quote</a></p>
  <p style="font-size:12px;color:#6b7280">Reply through the quote page to accept, decline, or leave a message.</p>
  </body></html>`;
}

export function invoiceReminderEmailHtml(opts: { business: any; invoice: any; token: string }) {
  return `<!doctype html><html><body style="font-family:Arial,sans-serif;color:#1e2430;line-height:1.5;max-width:680px;margin:0 auto;padding:24px">
  <h1 style="font-size:22px">${esc(opts.business?.name || 'Business Quotes')}</h1>
  <p>This is a reminder about invoice <strong>${esc(opts.invoice.invoiceNumber)}</strong>.</p>
  <p>Amount remaining: <strong>${esc(String(opts.invoice.balanceDisplay || ''))}</strong></p>
  <p>Due: <strong>${esc(String(opts.invoice.dueDisplay || 'On receipt'))}</strong></p>
  <p><a href="${esc(appUrl(`/public/invoice/${opts.token}`))}" style="display:inline-block;padding:10px 16px;background:#3b6b8a;color:#fff;text-decoration:none">Review invoice</a></p>
  <p style="font-size:12px;color:#6b7280">Please ignore this message if payment has already been made.</p>
  </body></html>`;
}

function dateOnly(d: Date) {
  return new Intl.DateTimeFormat('en', { year: 'numeric', month: '2-digit', day: '2-digit', timeZone: 'UTC' }).format(d);
}

function diffDays(target: Date, now: Date) {
  return Math.floor((Date.UTC(target.getUTCFullYear(), target.getUTCMonth(), target.getUTCDate()) - Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())) / 86_400_000);
}

export async function scheduleInvoiceReminderJobs() {
  const now = new Date();
  const windowEnd = new Date(now.getTime() + 3 * 86_400_000);
  const rows = await db.query.invoices.findMany({
    where: and(
      lte(invoices.dueAt, windowEnd),
      gte(invoices.dueAt, new Date(now.getTime() - 14 * 86_400_000)),
      lt(invoices.amountPaidMinor, invoices.amountMinor),
      sql`${invoices.deletedAt} is null`,
    ),
    orderBy: (i, { asc }) => [asc(i.dueAt), asc(i.id)],
    limit: 1000,
  });

  const userIds = [...new Set(rows.map(r => r.userId))];
  const profileRows = userIds.length ? await db.query.businessProfiles.findMany({ where: inArray(businessProfiles.userId, userIds) }) : [];
  const profileByUser = new Map(profileRows.map(p => [p.userId, p.data as any]));
  const invoiceIds = rows.map(r => r.id);
  const shareRows = invoiceIds.length ? await db.query.shareLinks.findMany({ where: and(inArray(shareLinks.invoiceId, invoiceIds), sql`${shareLinks.revokedAt} is null`) }) : [];
  const shareByInvoice = new Map(shareRows.filter(r => r.invoiceId).map(r => [r.invoiceId!, r]));

  for (const invoice of rows) {
    if (!invoice.clientEmail || invoice.status === 'void' || invoice.status === 'paid') continue;
    if (!invoice.dueAt) continue;
    const days = diffDays(invoice.dueAt, now);
    const keys: Array<[string, string]> = [];
    if (days === 3) keys.push(['3d_before', 'Your invoice is due in 3 days']);
    if (days === 0) keys.push(['due_today', 'Invoice due today']);
    if (days === -3) keys.push(['3d_overdue', 'Invoice is 3 days overdue']);
    if (days === -14) keys.push(['14d_overdue', 'Invoice is 14 days overdue']);
    if (!keys.length) continue;

    const profile: any = profileByUser.get(invoice.userId) ?? {};
    let token = shareByInvoice.get(invoice.id)?.tokenCiphertext ? decryptSecret(shareByInvoice.get(invoice.id)!.tokenCiphertext!) : null;
    if (!token) {
      token = await db.transaction((tx) => upsertShareLink(tx, invoice.userId, 'invoice', invoice.id, null));
      shareByInvoice.set(invoice.id, { tokenCiphertext: null } as any);
      // The upsert generated the raw token for this job; it is not persisted in plaintext.
    }
    const reminderUrl = appUrl(`/public/invoice/${token}`);
    for (const [kind, subject] of keys) {
      await db.insert(emailJobs).values({
        userId: invoice.userId,
        kind: 'invoice_reminder',
        invoiceId: invoice.id,
        toEmail: invoice.clientEmail,
        subject,
        html: `<html><body style="font-family:Arial,sans-serif;max-width:680px;margin:0 auto;padding:24px;color:#1e2430"><h1>${esc(profile.name || 'Business Quotes')}</h1><p>Invoice <strong>${esc(invoice.invoiceNumber)}</strong> remains outstanding.</p><p>Please review the invoice and arrange payment as soon as practical.</p><p>Due date: ${esc(dateOnly(invoice.dueAt))}</p><p><a href="${esc(reminderUrl)}" style="display:inline-block;padding:10px 16px;background:#3b6b8a;color:#fff;text-decoration:none">View invoice</a></p></body></html>`,
        idempotencyKey: `invoice:${invoice.id}:reminder:${kind}:${dateOnly(invoice.dueAt)}`,
      }).onConflictDoNothing({ target: emailJobs.idempotencyKey });
    }
  }
}
