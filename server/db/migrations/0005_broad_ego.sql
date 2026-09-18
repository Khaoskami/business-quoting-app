CREATE TABLE "processed_itns" (
	"pf_payment_id" text NOT NULL,
	"payment_status" text NOT NULL,
	"processed_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "processed_itns_pf_payment_id_payment_status_pk" PRIMARY KEY("pf_payment_id","payment_status")
);
