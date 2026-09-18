ALTER TYPE "invoice_status" ADD VALUE IF NOT EXISTS 'partially_paid';
ALTER TYPE "invoice_status" ADD VALUE IF NOT EXISTS 'overdue';

DO $$ BEGIN
  CREATE TYPE "quote_event_type" AS ENUM ('created','updated','sent','viewed','accepted','declined','invoice_issued');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE "email_job_status" AS ENUM ('pending','processing','sent','failed');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE "email_job_kind" AS ENUM ('quote_sent','invoice_issued','invoice_reminder');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE "billing_checkout_status" AS ENUM ('pending','complete','failed','cancelled');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

ALTER TABLE "quotes"
  ADD COLUMN IF NOT EXISTS "version" integer NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS "idempotency_key" text;
CREATE UNIQUE INDEX IF NOT EXISTS "quotes_user_id_idempotency_key_uq"
  ON "quotes" ("user_id", "idempotency_key");
CREATE INDEX IF NOT EXISTS "quotes_user_id_updated_at_idx"
  ON "quotes" ("user_id", "updated_at");

ALTER TABLE "invoices"
  ADD COLUMN IF NOT EXISTS "currency" text NOT NULL DEFAULT 'ZAR',
  ADD COLUMN IF NOT EXISTS "amount_minor" bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS "amount_paid_minor" bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS "client_email" text,
  ADD COLUMN IF NOT EXISTS "due_at" timestamp,
  ADD COLUMN IF NOT EXISTS "sent_at" timestamp,
  ADD COLUMN IF NOT EXISTS "paid_at" timestamp,
  ADD COLUMN IF NOT EXISTS "voided_at" timestamp;
CREATE INDEX IF NOT EXISTS "invoices_user_status_due_idx"
  ON "invoices" ("user_id", "status", "due_at");

UPDATE "invoices" i
SET
  "currency" = COALESCE(NULLIF(i."data"->>'currency',''), 'ZAR'),
  "amount_minor" = CASE COALESCE(NULLIF(i."data"->>'currency',''), 'ZAR')
    WHEN 'JPY' THEN ROUND((
      COALESCE((SELECT SUM(COALESCE(NULLIF(x->>'quantity','')::numeric,0) * COALESCE(NULLIF(x->>'unitPrice','')::numeric,0))
        FROM jsonb_array_elements(COALESCE(i."data"->'items','[]'::jsonb)) x), 0)
      * (1 - COALESCE(NULLIF(i."data"->>'discountPercent','')::numeric,0) / 100)
      * (1 + COALESCE(NULLIF(i."data"->>'taxPercent','')::numeric,0) / 100)
    ))::bigint
    ELSE ROUND((
      COALESCE((SELECT SUM(COALESCE(NULLIF(x->>'quantity','')::numeric,0) * COALESCE(NULLIF(x->>'unitPrice','')::numeric,0))
        FROM jsonb_array_elements(COALESCE(i."data"->'items','[]'::jsonb)) x), 0)
      * (1 - COALESCE(NULLIF(i."data"->>'discountPercent','')::numeric,0) / 100)
      * (1 + COALESCE(NULLIF(i."data"->>'taxPercent','')::numeric,0) / 100)
      * 100
    ))::bigint
  END,
  "client_email" = NULLIF(i."data"->>'clientEmail',''),
  "due_at" = i."created_at" + make_interval(days => LEAST(GREATEST(COALESCE(NULLIF(i."data"->>'paymentTermsDays','')::integer,30),0),365)),
  "updated_at" = COALESCE(i."updated_at", now())
WHERE i."amount_minor" = 0;

CREATE TABLE IF NOT EXISTS "invoice_payments" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id" text NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
  "invoice_id" uuid NOT NULL REFERENCES "invoices"("id") ON DELETE RESTRICT,
  "idempotency_key" text NOT NULL,
  "amount_minor" bigint NOT NULL,
  "currency" text NOT NULL,
  "method" text NOT NULL,
  "note" text,
  "received_at" timestamp NOT NULL DEFAULT now(),
  "created_at" timestamp NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS "invoice_payments_invoice_id_idx"
  ON "invoice_payments" ("invoice_id", "received_at");
CREATE UNIQUE INDEX IF NOT EXISTS "invoice_payments_user_idempotency_uq"
  ON "invoice_payments" ("user_id", "idempotency_key");

CREATE TABLE IF NOT EXISTS "share_links" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id" text NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
  "quote_id" uuid UNIQUE REFERENCES "quotes"("id") ON DELETE CASCADE,
  "invoice_id" uuid UNIQUE REFERENCES "invoices"("id") ON DELETE CASCADE,
  "token_hash" text NOT NULL UNIQUE,
  "expires_at" timestamp,
  "revoked_at" timestamp,
  "created_at" timestamp NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS "share_links_user_id_idx" ON "share_links" ("user_id");

CREATE TABLE IF NOT EXISTS "quote_events" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id" text NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
  "quote_id" uuid NOT NULL REFERENCES "quotes"("id") ON DELETE CASCADE,
  "event_type" "quote_event_type" NOT NULL,
  "metadata" jsonb NOT NULL DEFAULT '{}'::jsonb,
  "ip_hash" text,
  "user_agent" text,
  "created_at" timestamp NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS "quote_events_quote_id_created_at_idx"
  ON "quote_events" ("quote_id", "created_at");

CREATE TABLE IF NOT EXISTS "email_jobs" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id" text NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
  "kind" "email_job_kind" NOT NULL,
  "quote_id" uuid REFERENCES "quotes"("id") ON DELETE CASCADE,
  "invoice_id" uuid REFERENCES "invoices"("id") ON DELETE CASCADE,
  "to_email" text NOT NULL,
  "subject" text NOT NULL,
  "html" text NOT NULL,
  "idempotency_key" text NOT NULL UNIQUE,
  "scheduled_at" timestamp NOT NULL DEFAULT now(),
  "status" "email_job_status" NOT NULL DEFAULT 'pending',
  "attempts" integer NOT NULL DEFAULT 0,
  "next_attempt_at" timestamp NOT NULL DEFAULT now(),
  "last_error" text,
  "sent_at" timestamp
);
CREATE INDEX IF NOT EXISTS "email_jobs_status_next_attempt_idx"
  ON "email_jobs" ("status", "next_attempt_at");

CREATE TABLE IF NOT EXISTS "billing_checkouts" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "merchant_payment_id" text NOT NULL UNIQUE,
  "user_id" text NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
  "tier" "tier" NOT NULL,
  "amount_minor" bigint NOT NULL,
  "currency" text NOT NULL DEFAULT 'ZAR',
  "status" "billing_checkout_status" NOT NULL DEFAULT 'pending',
  "payfast_token" text,
  "created_at" timestamp NOT NULL DEFAULT now(),
  "updated_at" timestamp NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS "billing_checkouts_user_id_idx"
  ON "billing_checkouts" ("user_id");

