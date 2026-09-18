CREATE TABLE "quote_counters" (
	"user_id" text PRIMARY KEY NOT NULL,
	"next_seq" integer DEFAULT 1 NOT NULL
);
--> statement-breakpoint
ALTER TABLE "quote_counters" ADD CONSTRAINT "quote_counters_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;