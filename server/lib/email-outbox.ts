import { db } from '../db';
import { emailJobs, emailUsage, quotes, invoices } from '../db/schema';
import { and, eq, lte, sql } from 'drizzle-orm';
import { TIER_LIMITS, clientEmailLimitReached, type Tier } from './tier';
import { sendEmail } from './email-service';

function monthStartUtc(now = new Date()) {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
}


export async function getClientEmailUsage(userId: string) {
  const monthStart = monthStartUtc();
  const [usage] = await db.select({ clientEmailsQueued: emailUsage.clientEmailsQueued })
    .from(emailUsage)
    .where(and(eq(emailUsage.userId, userId), eq(emailUsage.monthStart, monthStart)))
    .limit(1);
  return Number(usage?.clientEmailsQueued ?? 0);
}

export async function enqueueClientEmail(job: {
  userId: string;
  tier: Tier;
  kind: 'quote_sent' | 'invoice_issued' | 'invoice_reminder' | 'client_email';
  quoteId?: string;
  invoiceId?: string;
  toEmail: string;
  replyTo?: string | null;
  subject: string;
  html: string;
  idempotencyKey: string;
  scheduledAt?: Date;
}) {
  const now = new Date();
  const scheduledAt = job.scheduledAt ?? now;
  const monthStart = monthStartUtc(now);

  return db.transaction(async (tx) => {
    const [existing] = await tx.select({ id: emailJobs.id, status: emailJobs.status }).from(emailJobs)
      .where(eq(emailJobs.idempotencyKey, job.idempotencyKey)).limit(1);
    if (existing) return { queued: true as const, duplicate: true as const, remaining: null };

    await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${job.userId}, 0))`);

    // Re-check the idempotency key after the lock. A concurrent request can
    // have inserted the same job while this transaction was waiting.
    const [existingAfterLock] = await tx.select({ id: emailJobs.id, status: emailJobs.status }).from(emailJobs)
      .where(eq(emailJobs.idempotencyKey, job.idempotencyKey)).limit(1);
    if (existingAfterLock) return { queued: true as const, duplicate: true as const, remaining: null };

    const [usage] = await tx.select({ clientEmailsQueued: emailUsage.clientEmailsQueued })
      .from(emailUsage)
      .where(and(eq(emailUsage.userId, job.userId), eq(emailUsage.monthStart, monthStart)))
      .limit(1);

    const used = Number(usage?.clientEmailsQueued ?? 0);
    const limit = TIER_LIMITS[job.tier].clientEmailsPerMonth;
    if (clientEmailLimitReached(job.tier, used)) {
      return { queued: false as const, duplicate: false as const, remaining: 0, limit };
    }

    if (!usage) {
      await tx.insert(emailUsage).values({
        userId: job.userId,
        monthStart,
        clientEmailsQueued: 1,
        updatedAt: now,
      });
    } else {
      await tx.update(emailUsage).set({ clientEmailsQueued: used + 1, updatedAt: now })
        .where(and(eq(emailUsage.userId, job.userId), eq(emailUsage.monthStart, monthStart)));
    }

    await tx.insert(emailJobs).values({
      userId: job.userId,
      kind: job.kind,
      quoteId: job.quoteId,
      invoiceId: job.invoiceId,
      toEmail: job.toEmail,
      replyTo: job.replyTo ?? null,
      subject: job.subject,
      html: job.html,
      idempotencyKey: job.idempotencyKey,
      scheduledAt,
      nextAttemptAt: scheduledAt,
    });

    return { queued: true as const, duplicate: false as const, remaining: limit === Infinity ? null : Math.max(0, limit - used - 1) };
  });
}

async function claimJob() {
  return db.transaction(async (tx) => {
    const [job] = await tx.execute(sql`
      select id, user_id, kind, quote_id, invoice_id, to_email, reply_to, subject, html, attempts
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

export async function processEmailJobs(maxJobs = 10) {
  if (!process.env.RESEND_API_KEY) return;
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

      await sendEmail({
        to: job.to_email,
        subject: job.subject,
        html: job.html,
        replyTo: job.reply_to || undefined,
      });

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
