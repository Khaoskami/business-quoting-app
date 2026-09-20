import {
  pgTable, text, boolean, timestamp,
  uuid, jsonb, pgEnum, integer, bigint, index, uniqueIndex, primaryKey, check
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';

export const tierEnum = pgEnum('tier', ['free', 'pro', 'business']);
export const subStatusEnum = pgEnum('sub_status', [
  'active', 'trialing', 'past_due', 'canceled', 'comped'
]);
export const invoiceStatusEnum = pgEnum('invoice_status', [
  'unpaid', 'partially_paid', 'paid', 'overdue', 'void'
]);
export const quoteEventTypeEnum = pgEnum('quote_event_type', [
  'created', 'updated', 'sent', 'viewed', 'accepted', 'declined', 'invoice_issued', 'deleted', 'restored'
]);
export const emailJobStatusEnum = pgEnum('email_job_status', [
  'pending', 'processing', 'sent', 'failed'
]);
export const emailJobKindEnum = pgEnum('email_job_kind', [
  'quote_sent', 'invoice_issued', 'invoice_reminder', 'client_email'
]);
export const invoiceEventTypeEnum = pgEnum('invoice_event_type', [
  'created', 'sent', 'viewed', 'payment_received', 'paid', 'overdue', 'voided', 'reopened', 'deleted', 'restored'
]);
export const billingCheckoutStatusEnum = pgEnum('billing_checkout_status', [
  'pending', 'complete', 'failed', 'cancelled'
]);

export const users = pgTable('users', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  email: text('email').notNull().unique(),
  emailVerified: boolean('email_verified').notNull().default(false),
  image: text('image'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
  isAdmin: boolean('is_admin').notNull().default(false),
});

export const sessions = pgTable('sessions', {
  id: text('id').primaryKey(),
  expiresAt: timestamp('expires_at').notNull(),
  token: text('token').notNull().unique(),
  createdAt: timestamp('created_at').notNull(),
  updatedAt: timestamp('updated_at').notNull(),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
});

export const accounts = pgTable('accounts', {
  id: text('id').primaryKey(),
  accountId: text('account_id').notNull(),
  providerId: text('provider_id').notNull(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  accessToken: text('access_token'),
  refreshToken: text('refresh_token'),
  idToken: text('id_token'),
  accessTokenExpiresAt: timestamp('access_token_expires_at'),
  refreshTokenExpiresAt: timestamp('refresh_token_expires_at'),
  scope: text('scope'),
  password: text('password'),
  createdAt: timestamp('created_at').notNull(),
  updatedAt: timestamp('updated_at').notNull(),
});

export const verifications = pgTable('verifications', {
  id: text('id').primaryKey(),
  identifier: text('identifier').notNull(),
  value: text('value').notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at'),
  updatedAt: timestamp('updated_at'),
});

export const subscriptions = pgTable('subscriptions', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: text('user_id').notNull().unique().references(() => users.id, { onDelete: 'cascade' }),
  tier: tierEnum('tier').notNull().default('free'),
  status: subStatusEnum('status').notNull().default('active'),
  stripeCustomerId: text('stripe_customer_id'),
  stripeSubscriptionId: text('stripe_subscription_id'),
  currentPeriodEnd: timestamp('current_period_end'),
  failedPayments: integer('failed_payments').notNull().default(0),
  billingAmountMinor: bigint('billing_amount_minor', { mode: 'number' }).notNull().default(0),
  comped: boolean('comped').notNull().default(false),
  compedBy: text('comped_by').references(() => users.id),
  compedNote: text('comped_note'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});

export const processedItns = pgTable('processed_itns', {
  pfPaymentId: text('pf_payment_id').notNull(),
  paymentStatus: text('payment_status').notNull(),
  processedAt: timestamp('processed_at').notNull().defaultNow(),
}, (t) => [
  primaryKey({ columns: [t.pfPaymentId, t.paymentStatus] }),
]);

export const billingCheckouts = pgTable('billing_checkouts', {
  id: uuid('id').primaryKey().defaultRandom(),
  merchantPaymentId: text('merchant_payment_id').notNull().unique(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  tier: tierEnum('tier').notNull(),
  amountMinor: bigint('amount_minor', { mode: 'number' }).notNull(),
  currency: text('currency').notNull().default('ZAR'),
  status: billingCheckoutStatusEnum('status').notNull().default('pending'),
  payfastToken: text('payfast_token'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, (t) => [index('billing_checkouts_user_id_idx').on(t.userId)]);

export const businessProfiles = pgTable('business_profiles', {
  userId: text('user_id').primaryKey().references(() => users.id, { onDelete: 'cascade' }),
  data: jsonb('data').notNull().default({}),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});

export const quotes = pgTable('quotes', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  data: jsonb('data').notNull(),
  version: integer('version').notNull().default(1),
  idempotencyKey: text('idempotency_key'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
  deletedAt: timestamp('deleted_at'),
  deletedBy: text('deleted_by').references(() => users.id, { onDelete: 'set null' }),
}, (t) => [
  index('quotes_user_id_created_at_idx').on(t.userId, t.createdAt),
  index('quotes_user_id_deleted_at_idx').on(t.userId, t.deletedAt),
  index('quotes_user_id_updated_at_idx').on(t.userId, t.updatedAt),
  uniqueIndex('quotes_user_id_idempotency_key_uq').on(t.userId, t.idempotencyKey),
]);

export const quoteCounters = pgTable('quote_counters', {
  userId: text('user_id').primaryKey().references(() => users.id, { onDelete: 'cascade' }),
  nextSeq: integer('next_seq').notNull().default(1),
});

export const invoices = pgTable('invoices', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  quoteId: uuid('quote_id').notNull().unique().references(() => quotes.id, { onDelete: 'restrict' }),
  invoiceNumber: text('invoice_number').notNull(),
  status: invoiceStatusEnum('status').notNull().default('unpaid'),
  currency: text('currency').notNull().default('ZAR'),
  amountMinor: bigint('amount_minor', { mode: 'number' }).notNull().default(0),
  amountPaidMinor: bigint('amount_paid_minor', { mode: 'number' }).notNull().default(0),
  clientEmail: text('client_email'),
  dueAt: timestamp('due_at'),
  sentAt: timestamp('sent_at'),
  paidAt: timestamp('paid_at'),
  voidedAt: timestamp('voided_at'),
  deletedAt: timestamp('deleted_at'),
  deletedBy: text('deleted_by').references(() => users.id, { onDelete: 'set null' }),
  data: jsonb('data').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, (t) => [
  index('invoices_user_id_idx').on(t.userId),
  index('invoices_user_status_due_idx').on(t.userId, t.status, t.dueAt),
  index('invoices_due_at_idx').on(t.dueAt),
  index('invoices_user_id_deleted_at_idx').on(t.userId, t.deletedAt),
  uniqueIndex('invoices_user_id_number_uq').on(t.userId, t.invoiceNumber),
  check('invoices_amounts_nonnegative', sql`amount_minor >= 0 and amount_paid_minor >= 0`),
]);

export const invoiceCounters = pgTable('invoice_counters', {
  userId: text('user_id').primaryKey().references(() => users.id, { onDelete: 'cascade' }),
  nextSeq: integer('next_seq').notNull().default(1),
});

export const invoicePayments = pgTable('invoice_payments', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  invoiceId: uuid('invoice_id').notNull().references(() => invoices.id, { onDelete: 'restrict' }),
  idempotencyKey: text('idempotency_key').notNull(),
  amountMinor: bigint('amount_minor', { mode: 'number' }).notNull(),
  currency: text('currency').notNull(),
  method: text('method').notNull(),
  note: text('note'),
  receivedAt: timestamp('received_at').notNull().defaultNow(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
}, (t) => [
  index('invoice_payments_invoice_id_idx').on(t.invoiceId, t.receivedAt),
  uniqueIndex('invoice_payments_user_idempotency_uq').on(t.userId, t.idempotencyKey),
  check('invoice_payments_positive_amount', sql`amount_minor > 0`),
]);

export const clients = pgTable('clients', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  data: jsonb('data').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, (t) => [index('clients_user_id_idx').on(t.userId)]);

export const catalogItems = pgTable('catalog_items', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  data: jsonb('data').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, (t) => [index('catalog_items_user_id_idx').on(t.userId)]);

export const shareLinks = pgTable('share_links', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  quoteId: uuid('quote_id').unique().references(() => quotes.id, { onDelete: 'cascade' }),
  invoiceId: uuid('invoice_id').unique().references(() => invoices.id, { onDelete: 'cascade' }),
  tokenHash: text('token_hash').notNull().unique(),
  tokenCiphertext: text('token_ciphertext'),
  expiresAt: timestamp('expires_at'),
  revokedAt: timestamp('revoked_at'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
}, (t) => [
  index('share_links_user_id_idx').on(t.userId),
  check('share_links_exactly_one_document', sql`((quote_id is not null)::int + (invoice_id is not null)::int) = 1`),
]);

export const quoteEvents = pgTable('quote_events', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  quoteId: uuid('quote_id').notNull().references(() => quotes.id, { onDelete: 'cascade' }),
  eventType: quoteEventTypeEnum('event_type').notNull(),
  metadata: jsonb('metadata').notNull().default({}),
  ipHash: text('ip_hash'),
  userAgent: text('user_agent'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
}, (t) => [index('quote_events_quote_id_created_at_idx').on(t.quoteId, t.createdAt)]);

export const invoiceEvents = pgTable('invoice_events', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  invoiceId: uuid('invoice_id').notNull().references(() => invoices.id, { onDelete: 'cascade' }),
  eventType: invoiceEventTypeEnum('event_type').notNull(),
  metadata: jsonb('metadata').notNull().default({}),
  ipHash: text('ip_hash'),
  userAgent: text('user_agent'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
}, (t) => [index('invoice_events_invoice_id_created_at_idx').on(t.invoiceId, t.createdAt)]);

export const emailUsage = pgTable('email_usage', {
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  monthStart: timestamp('month_start').notNull(),
  clientEmailsQueued: integer('client_emails_queued').notNull().default(0),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, (t) => [
  primaryKey({ columns: [t.userId, t.monthStart] }),
  index('email_usage_month_idx').on(t.monthStart),
]);

export const emailJobs = pgTable('email_jobs', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  kind: emailJobKindEnum('kind').notNull(),
  quoteId: uuid('quote_id').references(() => quotes.id, { onDelete: 'cascade' }),
  invoiceId: uuid('invoice_id').references(() => invoices.id, { onDelete: 'cascade' }),
  toEmail: text('to_email').notNull(),
  replyTo: text('reply_to'),
  subject: text('subject').notNull(),
  html: text('html').notNull(),
  idempotencyKey: text('idempotency_key').notNull().unique(),
  scheduledAt: timestamp('scheduled_at').notNull().defaultNow(),
  status: emailJobStatusEnum('status').notNull().default('pending'),
  attempts: integer('attempts').notNull().default(0),
  nextAttemptAt: timestamp('next_attempt_at').notNull().defaultNow(),
  lastError: text('last_error'),
  sentAt: timestamp('sent_at'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
}, (t) => [index('email_jobs_status_next_attempt_idx').on(t.status, t.nextAttemptAt)]);
