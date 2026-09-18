CREATE TYPE "public"."invoice_status" AS ENUM('unpaid', 'paid', 'void');--> statement-breakpoint
CREATE TABLE "invoice_counters" (
	"user_id" text PRIMARY KEY NOT NULL,
	"next_seq" integer DEFAULT 1 NOT NULL
);
--> statement-breakpoint
CREATE TABLE "invoices" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" text NOT NULL,
	"quote_id" uuid NOT NULL,
	"invoice_number" text NOT NULL,
	"status" "invoice_status" DEFAULT 'unpaid' NOT NULL,
	"data" jsonb NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "invoices_quote_id_unique" UNIQUE("quote_id")
);
--> statement-breakpoint
ALTER TABLE "invoice_counters" ADD CONSTRAINT "invoice_counters_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "invoices" ADD CONSTRAINT "invoices_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "invoices" ADD CONSTRAINT "invoices_quote_id_quotes_id_fk" FOREIGN KEY ("quote_id") REFERENCES "public"."quotes"("id") ON DELETE restrict ON UPDATE no action;