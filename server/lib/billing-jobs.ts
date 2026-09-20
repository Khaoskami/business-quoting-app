import { db } from '../db';
import { businessProfiles, invoices, subscriptions, shareLinks } from '../db/schema';
import { and, eq, gte, lte, lt, inArray, sql } from 'drizzle-orm';
import { enqueueClientEmail } from './email-outbox';
import { decryptSecret } from './security';
import { upsertShareLink } from './share-links';
import { effectiveTier, TIER_LIMITS } from './tier';
import { fromMinor } from './finance';
import { isEmailConfigured } from './email-service';

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

export function clientEmailHtml(opts: { business: any; recipientName: string; message: string }) {
  const body = esc(opts.message).replace(/\r?\n/g, '<br>');
  return `<!doctype html><html><body style="font-family:Arial,sans-serif;color:#1e2430;line-height:1.6;max-width:680px;margin:0 auto;padding:24px">
  <h1 style="font-size:22px">${esc(opts.business?.name || 'Business Quotes')}</h1>
  <p>${esc(opts.recipientName || 'Hello')},</p>
  <div style="white-space:normal">${body}</div>
  <hr style="border:0;border-top:1px solid #e5e7eb;margin:28px 0" />
  <p style="font-size:12px;color:#6b7280">Sent from ${esc(opts.business?.name || 'Business Quotes')}.</p>
  </body></html>`;
}

function dateOnly(d: Date) {
  return new Intl.DateTimeFormat('en', { year: 'numeric', month: '2-digit', day: '2-digit', timeZone: 'UTC' }).format(d);
}

function diffDays(target: Date, now: Date) {
  return Math.floor((Date.UTC(target.getUTCFullYear(), target.getUTCMonth(), target.getUTCDate()) - Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())) / 86_400_000);
}

export async function scheduleInvoiceReminderJobs() {
  if (!isEmailConfigured()) return;
  const now = new Date();
  const windowEnd = new Date(now.getTime() + 3 * 86_400_000);
  const rows = await db.query.invoices.findMany({
    where: and(
      lte(invoices.dueAt, windowEnd),
      gte(invoices.dueAt, new Date(now.getTime() - 90 * 86_400_000)),
      lt(invoices.amountPaidMinor, invoices.amountMinor),
      sql`${invoices.deletedAt} is null`,
    ),
    orderBy: (i, { asc }) => [asc(i.dueAt), asc(i.id)],
    limit: 1000,
  });

  const userIds = [...new Set(rows.map(r => r.userId))];
  const profileRows = userIds.length ? await db.query.businessProfiles.findMany({ where: inArray(businessProfiles.userId, userIds) }) : [];
  const profileByUser = new Map(profileRows.map(p => [p.userId, p.data as any]));
  const subscriptionRows = userIds.length ? await db.query.subscriptions.findMany({ where: inArray(subscriptions.userId, userIds) }) : [];
  const subscriptionByUser = new Map(subscriptionRows.map(s => [s.userId, s]));
  const invoiceIds = rows.map(r => r.id);
  const shareRows = invoiceIds.length ? await db.query.shareLinks.findMany({ where: and(inArray(shareLinks.invoiceId, invoiceIds), sql`${shareLinks.revokedAt} is null`) }) : [];
  const shareByInvoice = new Map(shareRows.filter(r => r.invoiceId).map(r => [r.invoiceId!, r]));

  for (const invoice of rows) {
    if (!invoice.clientEmail || invoice.status === 'void' || invoice.status === 'paid' || !invoice.dueAt) continue;

    const tier = effectiveTier(subscriptionByUser.get(invoice.userId));
    const limits = TIER_LIMITS[tier];
    if (!limits.features.autoReminders) continue;

    const profile: any = profileByUser.get(invoice.userId) ?? {};
    const settings = profile.emailSettings ?? {};
    if (settings.autoReminders === false) continue;

    const configuredDays = Array.isArray(settings.reminderDays) ? settings.reminderDays : null;
    const reminderDays = tier === 'business' && configuredDays?.length
      ? [...new Set(configuredDays.map((d: any) => Number(d)).filter((d: number) => Number.isInteger(d) && d >= -90 && d <= 90))]
      : [3, 0, -3, -14];

    const days = diffDays(invoice.dueAt, now);
    if (!reminderDays.includes(days)) continue;

    let token = shareByInvoice.get(invoice.id)?.tokenCiphertext ? decryptSecret(shareByInvoice.get(invoice.id)!.tokenCiphertext!) : null;
    if (!token) {
      token = await db.transaction((tx) => upsertShareLink(tx, invoice.userId, 'invoice', invoice.id, null));
    }

    const reminderUrl = appUrl(`/public/invoice/${token}`);
    const profileEmail = String(profile.email || '').trim();
    const subject = days > 0
      ? `Invoice ${invoice.invoiceNumber} is due in ${days} day${days === 1 ? '' : 's'}`
      : days === 0
        ? `Invoice ${invoice.invoiceNumber} is due today`
        : `Invoice ${invoice.invoiceNumber} is ${Math.abs(days)} day${Math.abs(days) === 1 ? '' : 's'} overdue`;

    const balanceMinor = Math.max(0, Number(invoice.amountMinor) - Number(invoice.amountPaidMinor));
    await enqueueClientEmail({
      userId: invoice.userId,
      tier,
      kind: 'invoice_reminder',
      invoiceId: invoice.id,
      toEmail: invoice.clientEmail,
      replyTo: profileEmail || undefined,
      subject,
      html: invoiceReminderEmailHtml({ business: profile, invoice: { ...(invoice.data as any), invoiceNumber: invoice.invoiceNumber, balanceDisplay: `${invoice.currency} ${fromMinor(balanceMinor, invoice.currency).toFixed(invoice.currency === 'JPY' ? 0 : 2)}`, dueDisplay: dateOnly(invoice.dueAt) }, token }),
      idempotencyKey: `invoice:${invoice.id}:auto-reminder:${days}:${dateOnly(invoice.dueAt)}`,
    });
  }
}
