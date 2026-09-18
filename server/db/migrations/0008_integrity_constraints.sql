ALTER TABLE "invoices" ADD CONSTRAINT "invoices_amounts_nonnegative" CHECK (amount_minor >= 0 AND amount_paid_minor >= 0);
ALTER TABLE "invoice_payments" ADD CONSTRAINT "invoice_payments_positive_amount" CHECK (amount_minor > 0);
ALTER TABLE "billing_checkouts" ADD CONSTRAINT "billing_checkouts_positive_amount" CHECK (amount_minor > 0);
ALTER TABLE "share_links" ADD CONSTRAINT "share_links_exactly_one_document" CHECK (((quote_id IS NOT NULL)::int + (invoice_id IS NOT NULL)::int) = 1);
CREATE UNIQUE INDEX IF NOT EXISTS "invoices_user_id_number_uq" ON "invoices" ("user_id", "invoice_number");
