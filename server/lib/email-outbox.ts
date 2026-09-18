import { Resend } from 'resend';
import { db } from '../db';
import { emailJobs, quotes, invoices } from '../db/schema';
import { and, eq, lte, sql } from 'drizzle-orm';

let resend: Resend | null = null;
function getResend() {
  if (!process.env.RESEND_API_KEY) return null;
  resend ??= new Resend(process.env.RESEND_API_KEY);
  return resend;
}

export async function enqueueEmail(job: {
  userId: string;
  kind: 'quote_sent' | 'invoice_issued' | 'invoice_reminder';
  quoteId?: string;
  invoiceId?: string;
  toEmail: string;
  subject: string;
  html: string;
  idempotencyKey: string;
  scheduledAt?: Date;
}) {
  await db.insert(emailJobs).values({
    userId: job.userId,
    kind: job.kind,
    quoteId: job.quoteId,
    invoiceId: job.invoiceId,
    toEmail: job.toEmail,
    subject: job.subject,
    html: job.html,
    idempotencyKey: job.idempotencyKey,
    scheduledAt: job.scheduledAt ?? new Date(),
    nextAttemptAt: job.scheduledAt ?? new Date(),
  }).onConflictDoNothing({ target: emailJobs.idempotencyKey });
}

async function claimJob() {
  return db.transaction(async (tx) => {
    const [job] = await tx.execute(sql`
      select id, user_id, kind, quote_id, invoice_id, to_email, subject, html, attempts
      from email_jobs
      where status = 'pending' and next_attempt_at <= now()
      order by scheduled_at asc, id asc
      for update skip locked
      limit 1
    `) as unknown as Array<any>;
    if (!job) return null;
    await tx.update(emailJobs).set({
      status: 'processing',
      attempts: Number(job.attempts) + 1,
      nextAttemptAt: new Date(Date.now() + 15 * 60 * 1000),
    }).where(eq(emailJobs.id, job.id));
    return job;
  });
}

export async function processEmailJobs(maxJobs = 5) {
  const client = getResend();
  if (!client) return;
  for (let i = 0; i < maxJobs; i += 1) {
    const job = await claimJob();
    if (!job) break;
    try {
      if (job.quote_id) {
        const quote = await db.query.quotes.findFirst({ where: eq(quotes.id, job.quote_id) });
        if (!quote || quote.deletedAt) {
          await db.update(emailJobs).set({ status: 'failed', lastError: 'Quote was archived before delivery.' }).where(eq(emailJobs.id, job.id));
          continue;
        }
      }
      if (job.invoice_id) {
        const invoice = await db.query.invoices.findFirst({ where: eq(invoices.id, job.invoice_id) });
        if (!invoice || invoice.deletedAt) {
          await db.update(emailJobs).set({ status: 'failed', lastError: 'Invoice was archived before delivery.' }).where(eq(emailJobs.id, job.id));
          continue;
        }
      }
      const result = await client.emails.send({
        from: process.env.RESET_FROM_EMAIL ?? 'no-reply@invalid.example',
        to: job.to_email,
        subject: job.subject,
        html: job.html,
      });
      if (result.error) throw new Error(result.error.message || 'Email provider error');
      await db.update(emailJobs).set({ status: 'sent', sentAt: new Date(), lastError: null }).where(eq(emailJobs.id, job.id));
    } catch (error: any) {
      const attempts = Number(job.attempts);
      const exhausted = attempts >= 8;
      const delayMs = Math.min(6 * 60 * 60 * 1000, (2 ** Math.max(0, attempts - 1)) * 30_000);
      await db.update(emailJobs).set({
        status: exhausted ? 'failed' : 'pending',
        nextAttemptAt: new Date(Date.now() + delayMs),
        lastError: String(error?.message ?? error).slice(0, 2_000),
      }).where(eq(emailJobs.id, job.id));
    }
  }
}

export async function resetStuckEmailJobs() {
  await db.update(emailJobs).set({ status: 'pending', nextAttemptAt: new Date() })
    .where(and(eq(emailJobs.status, 'processing'), lte(emailJobs.nextAttemptAt, new Date())));
}
