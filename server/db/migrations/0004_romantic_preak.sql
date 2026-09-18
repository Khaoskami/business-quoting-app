CREATE INDEX "catalog_items_user_id_idx" ON "catalog_items" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "clients_user_id_idx" ON "clients" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "invoices_user_id_idx" ON "invoices" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "quotes_user_id_created_at_idx" ON "quotes" USING btree ("user_id","created_at");