ALTER TYPE "quote_event_type" ADD VALUE IF NOT EXISTS 'deleted';
ALTER TYPE "quote_event_type" ADD VALUE IF NOT EXISTS 'restored';

DO $$ BEGIN
  CREATE TYPE "invoice_event_type" AS ENUM ('created','sent','viewed','payment_received','paid','overdue','voided','reopened','deleted','restored');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

ALTER TABLE "quotes"
  ADD COLUMN IF NOT EXISTS "deleted_at" timestamp,
  ADD COLUMN IF NOT EXISTS "deleted_by" text REFERENCES "users"("id") ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS "quotes_user_id_deleted_at_idx" ON "quotes" ("user_id", "deleted_at");

ALTER TABLE "invoices"
  ADD COLUMN IF NOT EXISTS "deleted_at" timestamp,
  ADD COLUMN IF NOT EXISTS "deleted_by" text REFERENCES "users"("id") ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS "invoices_user_id_deleted_at_idx" ON "invoices" ("user_id", "deleted_at");

CREATE TABLE IF NOT EXISTS "invoice_events" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id" text NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
  "invoice_id" uuid NOT NULL REFERENCES "invoices"("id") ON DELETE CASCADE,
  "event_type" "invoice_event_type" NOT NULL,
  "metadata" jsonb NOT NULL DEFAULT '{}'::jsonb,
  "ip_hash" text,
  "user_agent" text,
  "created_at" timestamp NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS "invoice_events_invoice_id_created_at_idx"
  ON "invoice_events" ("invoice_id", "created_at");

INSERT INTO "invoice_events" (user_id, invoice_id, event_type, metadata, created_at)
SELECT i.user_id, i.id, 'created', jsonb_build_object('source', 'migration', 'quoteId', i.quote_id), i.created_at
FROM invoices i
WHERE NOT EXISTS (SELECT 1 FROM invoice_events e WHERE e.invoice_id = i.id AND e.event_type = 'created');
