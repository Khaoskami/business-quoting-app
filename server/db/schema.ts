import {
  pgTable, text, boolean, timestamp,
  uuid, jsonb, pgEnum, integer
} from 'drizzle-orm/pg-core';

// ── Enums ────────────────────────────────────────────────
export const tierEnum = pgEnum('tier', ['free', 'pro', 'business']);
export const subStatusEnum = pgEnum('sub_status', [
  'active', 'trialing', 'past_due', 'canceled', 'comped'
]);
export const invoiceStatusEnum = pgEnum('invoice_status', ['unpaid', 'paid', 'void']);

// ── Users (owned by Better Auth, extended here) ──────────
export const users = pgTable('users', {
  id:            text('id').primaryKey(),
  name:          text('name').notNull(),
  email:         text('email').notNull().unique(),
  emailVerified: boolean('email_verified').notNull().default(false),
  image:         text('image'),
  createdAt:     timestamp('created_at').notNull().defaultNow(),
  updatedAt:     timestamp('updated_at').notNull().defaultNow(),
  isAdmin:       boolean('is_admin').notNull().default(false),
});

// ── Better Auth tables (do not rename these) ────────────
export const sessions = pgTable('sessions', {
  id:        text('id').primaryKey(),
  expiresAt: timestamp('expires_at').notNull(),
  token:     text('token').notNull().unique(),
  createdAt: timestamp('created_at').notNull(),
  updatedAt: timestamp('updated_at').notNull(),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  userId:    text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
});

export const accounts = pgTable('accounts', {
  id:                    text('id').primaryKey(),
  accountId:             text('account_id').notNull(),
  providerId:            text('provider_id').notNull(),
  userId:                text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  accessToken:           text('access_token'),
  refreshToken:          text('refresh_token'),
  idToken:               text('id_token'),
  accessTokenExpiresAt:  timestamp('access_token_expires_at'),
  refreshTokenExpiresAt: timestamp('refresh_token_expires_at'),
  scope:                 text('scope'),
  password:              text('password'),
  createdAt:             timestamp('created_at').notNull(),
  updatedAt:             timestamp('updated_at').notNull(),
});

export const verifications = pgTable('verifications', {
  id:         text('id').primaryKey(),
  identifier: text('identifier').notNull(),
  value:      text('value').notNull(),
  expiresAt:  timestamp('expires_at').notNull(),
  createdAt:  timestamp('created_at'),
  updatedAt:  timestamp('updated_at'),
});

// ── Subscriptions ────────────────────────────────────────
export const subscriptions = pgTable('subscriptions', {
  id:                   uuid('id').primaryKey().defaultRandom(),
  userId:               text('user_id').notNull().unique().references(() => users.id, { onDelete: 'cascade' }),
  tier:                 tierEnum('tier').notNull().default('free'),
  status:               subStatusEnum('status').notNull().default('active'),
  stripeCustomerId:     text('stripe_customer_id'),
  stripeSubscriptionId: text('stripe_subscription_id'),
  currentPeriodEnd:     timestamp('current_period_end'),
  comped:               boolean('comped').notNull().default(false),
  compedBy:             text('comped_by').references(() => users.id),
  compedNote:           text('comped_note'),
  createdAt:            timestamp('created_at').notNull().defaultNow(),
  updatedAt:            timestamp('updated_at').notNull().defaultNow(),
});

// ── Business profiles ────────────────────────────────────
export const businessProfiles = pgTable('business_profiles', {
  userId:    text('user_id').primaryKey().references(() => users.id, { onDelete: 'cascade' }),
  data:      jsonb('data').notNull().default({}),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});

// ── Quotes ───────────────────────────────────────────────
export const quotes = pgTable('quotes', {
  id:        uuid('id').primaryKey().defaultRandom(),
  userId:    text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  data:      jsonb('data').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});

// ── Per-user gapless quote sequence counters ─────────────
export const quoteCounters = pgTable('quote_counters', {
  userId:  text('user_id').primaryKey().references(() => users.id, { onDelete: 'cascade' }),
  nextSeq: integer('next_seq').notNull().default(1),
});

// ── Invoices (issued only when client acceptance is confirmed) ──
export const invoices = pgTable('invoices', {
  id:            uuid('id').primaryKey().defaultRandom(),
  userId:        text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  quoteId:       uuid('quote_id').notNull().unique().references(() => quotes.id, { onDelete: 'restrict' }),
  invoiceNumber: text('invoice_number').notNull(),
  status:        invoiceStatusEnum('status').notNull().default('unpaid'),
  data:          jsonb('data').notNull(), // frozen snapshot of the quote at acceptance time
  createdAt:     timestamp('created_at').notNull().defaultNow(),
  updatedAt:     timestamp('updated_at').notNull().defaultNow(),
});

// ── Per-user gapless invoice sequence counters ──
export const invoiceCounters = pgTable('invoice_counters', {
  userId:  text('user_id').primaryKey().references(() => users.id, { onDelete: 'cascade' }),
  nextSeq: integer('next_seq').notNull().default(1),
});

// ── Clients ──────────────────────────────────────────────
export const clients = pgTable('clients', {
  id:        uuid('id').primaryKey().defaultRandom(),
  userId:    text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  data:      jsonb('data').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});

// ── Catalog items ────────────────────────────────────────
export const catalogItems = pgTable('catalog_items', {
  id:        uuid('id').primaryKey().defaultRandom(),
  userId:    text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  data:      jsonb('data').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});
