ALTER TABLE "subscriptions" ADD COLUMN IF NOT EXISTS "billing_amount_minor" bigint NOT NULL DEFAULT 0;

UPDATE "subscriptions"
SET "billing_amount_minor" = CASE
  WHEN "tier" = 'pro' AND "billing_amount_minor" = 0 THEN 29900
  WHEN "tier" = 'business' AND "billing_amount_minor" = 0 THEN 59900
  ELSE "billing_amount_minor"
END;

ALTER TYPE "email_job_kind" ADD VALUE IF NOT EXISTS 'client_email';

ALTER TABLE "email_jobs" ADD COLUMN IF NOT EXISTS "reply_to" text;

CREATE TABLE IF NOT EXISTS "email_usage" (
  "user_id" text NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
  "month_start" timestamp NOT NULL,
  "client_emails_queued" integer NOT NULL DEFAULT 0,
  "created_at" timestamp NOT NULL DEFAULT now(),
  "updated_at" timestamp NOT NULL DEFAULT now(),
  PRIMARY KEY ("user_id", "month_start")
);

CREATE INDEX IF NOT EXISTS "email_usage_month_idx" ON "email_usage" ("month_start");
