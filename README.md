# Business Quotes App

Multi-user SaaS for creating quotes and invoices with server-authoritative pricing, client review links, payment history, transactional email, PostgreSQL persistence, and PayFast subscription billing.

## Product promise

Business Quotes is designed around one job instead of two disconnected modules: turn a quote into cash with as little admin work as possible.

The primary path is: Client → Quote → Send → Follow up → Approval → Invoice → Reminder → Payment. The dashboard now acts as a work queue, quote and invoice lists expose next actions, quote creation keeps client setup in context, and accepted quotes become invoices without re-keying the pricing.

See [`QUOTE_INVOICE_AUDIT.md`](./QUOTE_INVOICE_AUDIT.md) for the UX audit, market evidence, identified pain points, and implementation map.


## Document lifecycle and retention

Deleting a quote or invoice is a soft delete. The record remains in PostgreSQL, retains its audit history, and can be restored. Quote deletion does not delete or alter a linked invoice. Invoice deletion does not delete payment records. Public links are revoked when a document is deleted, and archived documents cannot receive new payments or client responses until restored.

Use the active list by default. The archived list is available with the `deletedOnly=1` API query. Lifecycle history is exposed through `/api/quotes/:id/events` and `/api/invoices/:id/events`.

## Production design

The application keeps PostgreSQL as the source of truth. Quote and invoice mutations are validated at the API boundary, use optimistic concurrency where records are editable, and use database transactions for counters, payment recording, subscription ITNs, and usage limits.

Public quote and invoice links are bearer capabilities. Only a SHA-256 token hash is stored in PostgreSQL. Links can be revoked; quote links also inherit the quote validity date. Public views do not expose account credentials, session data, or internal subscription information.

Accepted quotes are immutable because they become the source document for an invoice. Invoices store a monetary snapshot in integer minor units. Payments are append-only and idempotent. Recorded invoice payments cannot be edited by changing invoice status directly.

Email delivery uses a PostgreSQL outbox. Workers claim jobs with `FOR UPDATE SKIP LOCKED`, retry failed messages with backoff, and deduplicate by idempotency key. This is safe to run on more than one application replica without adding Redis just to deliver mail.

## Stack

Runtime: Bun

API: Hono

Auth: Better Auth with email/password, secure httpOnly sessions, production email verification, and auth-route rate limiting

Database: PostgreSQL + Drizzle ORM

Payments: PayFast for application subscriptions

Email: Resend

Frontend: React 18 + Vite + TanStack Query + React Router

Deploy: Railway

## Local development

```bash
bun install

cp .env.example .env
bun run db:migrate
bun run dev
```

Server: `http://localhost:3000`

Vite client: `http://localhost:5173`

## Production

Build:

```bash
bun run build
bun start
```

Required production environment values:

```text
DATABASE_URL
BETTER_AUTH_SECRET
BETTER_AUTH_URL
CLIENT_URL
RESEND_API_KEY
RESET_FROM_EMAIL
```

For live PayFast subscriptions also provide:

```text
PAYFAST_MERCHANT_ID
PAYFAST_MERCHANT_KEY
PAYFAST_PASSPHRASE
PAYFAST_SANDBOX=false
```

`BETTER_AUTH_SECRET` must be at least 32 characters. Production public URLs must use HTTPS.

### Railway

Railway supports a pre-deploy command for database migrations. Configure the service with:

```text
Pre-deploy command: bun run db:migrate
Start command: bun start
```

Do not run `drizzle-kit migrate` from the application start command when horizontally scaling. Railway documents pre-deploy commands specifically for migrations and runs them before the new deployment is live. citeturn384541search0turn384541search1

Use the Railway domain during initial setup, then point your custom domain to the service and set both `CLIENT_URL` and `BETTER_AUTH_URL` to the final HTTPS origin. The SPA includes an SVG favicon and does not load third-party web fonts.

Health checks:

`GET /api/health` confirms the process is alive.

`GET /api/ready` performs a database query and should be used for readiness.

### PayFast

Set PayFast's ITN notify URL to:

`https://your-domain.example/api/billing/notify`

The application binds each checkout to a random merchant payment identifier stored server-side and verifies the posted gross amount against that checkout before applying subscription changes. Replayed ITNs are deduplicated by PayFast payment ID and status.

## Tiers

| Tier | Price | Quotes/month | Clients | Catalog | Quote sharing | Printing |
|---|---:|---:|---:|---:|---|---|
| Free | · | 50 | 3 | 10 | No | No |
| Pro | R299/month | 100 | 999 | 999 | Yes | Yes |
| Business | R599/month | Unlimited | Unlimited | Unlimited | Yes | Yes |

Prices are in ZAR for the application subscription. Customer quotes and invoices support the currencies configured in the application.

## Quote workflow

Draft a quote → select a saved client → calculate totals on the server → save with optimistic concurrency → create a revocable client link → client reviews and accepts or declines → accepted quotes are frozen → invoice is issued from the accepted snapshot.

The public acceptance flow records the respondent's typed name and response message. It is an acceptance record, not a claim of qualified electronic signature or regulated e-signature status.

## Invoice workflow

Invoice amount and currency are snapshotted when the invoice is issued. Due dates come from payment terms. Manual payments are recorded as separate immutable payment records and can be partial. The remaining balance and status are derived from those payments. Invoice links are revocable bearer URLs.

Payment collection from end customers is intentionally not routed through the application's own SaaS subscription merchant account. A business can show its own payment instructions and record payments safely; customer-facing card/bank payment processing should be connected to the business's own payment account before enabling live collection.

## Automated reminders

The outbox scheduler creates invoice reminder emails at 3 days before due, on the due date, and at 3 and 14 days overdue. Duplicate sends are prevented with an idempotency key. The reminder worker can run on multiple replicas.

## Authentication hardening

Production email verification is enabled using Better Auth and Resend. Better Auth supports requiring verified emails before sign-in and sending verification links through a transactional provider. citeturn967677view0

Password reset links are generated by Better Auth and delivered through the same verified sender.

The server also applies same-origin checks to cookie-authenticated mutations, strict request schemas, request size limits, and a per-process abuse throttle. The throttle is intentionally not a security boundary and should not be treated as a distributed rate limiter.

For very high traffic, move only the abuse-throttling state to a shared store after measurement. Do not add Redis merely because the app is deployed to more than one replica.

## Customer-facing capabilities benchmark

The implementation covers the recurring pain points most relevant to a focused quoting/invoicing product:

Client review and acceptance links, response messages, conversion from accepted quote to invoice, partial payment recording, payment history, due dates, overdue states, automatic reminders, invoice sharing, immutable accepted documents, duplicate quotes, conflict detection for concurrent editing, idempotent mutations, and professional print/CSV output.

Current market documentation shows these are common workflow expectations: QuickBooks documents recurring transactions and progress invoicing; Zoho documents customer-portal quote acceptance and partial invoice payments; FreshBooks documents recurring invoices, partial payments, reminders, deposits, and estimate approval; Xero documents online payment links, reminders, tracking, and repeating invoices. citeturn384541search9turn384541search6turn384541search5turn384541search8turn384541search10turn384541search11

This project deliberately does not pretend to be a full accounting ledger. Tax filing, bank reconciliation, general-ledger postings, qualified e-signatures, customer-specific payment-provider accounts, and country-specific compliance engines should be added only when their product and legal requirements are defined.

## Privacy and legal pages

The production build serves:

`/privacy-policy.html`

`/terms.html`

The application also links these pages from authentication screens. They describe public document links, verification/password-reset email processing, and support-based account deletion requests.

## Data safety notes

Never calculate or trust invoice totals solely in the browser.

Never accept an invoice as paid by changing a status field.

Never store public share tokens in plaintext.

Never use a user's email address as an administrator credential.

Never trust PayFast callback values without validating the signed ITN and matching the stored checkout amount.

Never run schema migrations from every application replica at startup.

## License

Copyright (c) 2026 Khaoskami. All rights reserved. See [LICENSE](./LICENSE).

### Railway production deployment

This repository contains checked-in Drizzle migrations. Railway runs `bun run db:migrate` as the pre-deploy command before the application is released. Do not run `db:generate` during the production image build. Deploy updates against the existing Railway PostgreSQL service and keep the existing `DATABASE_URL` reference unchanged.

The document-retention migration (`0010_document_soft_delete_and_invoice_events`) only adds nullable columns, indexes, an invoice-events table, enum values, and historical creation events. It does not delete existing quotes, invoices, payments, or customers. Quotes and invoices are soft-deleted by the application after this migration.

## PDF documents

Quote and invoice downloads are generated on the server as real `application/pdf` files. The browser no longer opens an HTML print page for document downloads. The production image installs Chromium and Noto fonts so currency symbols such as `R`, `$`, `€`, `£`, `¥`, `₹`, `₦`, and `د.إ` are rendered as PDF glyphs instead of relying on the user's browser font or encoding.

Authenticated endpoints are `/api/quotes/:id/pdf` and `/api/invoices/:id/pdf`. Public capability URLs are `/api/public/quotes/:token/pdf` and `/api/public/invoices/:token/pdf`. PDF generation is locally concurrency-limited and cleans temporary files after completion.
