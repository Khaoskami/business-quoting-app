# Ponyl + Anti-Vibe Production Vet Report

Date: 2026-09-18
Repository: Business Quotes App

## Result

The uploaded application has been hardened around a PostgreSQL source of truth, strict trust-boundary validation, immutable financial records, idempotent mutations, concurrency control, transactional counters, capability links, transactional email, production authentication, and deployment-safe migrations.

The implementation intentionally avoids adding infrastructure merely for appearance. PostgreSQL remains the coordination layer. The existing Hono, Drizzle, Better Auth, Resend, React, Vite, and PayFast stack is reused.

## Decision ladder

1. Need to exist: only business-critical safety, quoting, invoicing, client sharing, email, billing, and portability changes were added.
2. Already in the codebase: existing routes, database, tier system, React Query, Resend, PayFast, and print utilities were extended instead of replaced.
3. Standard library: cryptography, hashing, URL handling, HTML escaping, and date/number formatting use platform APIs.
4. Native platform: browser print, CSV download, file APIs, and standard form controls are used.
5. Existing dependency: no new runtime package was added.
6. One line where appropriate: small validation/security helpers remain compact.
7. Minimum code that works: no Redis, queue broker, component library, animation framework, or accounting SDK was introduced without a demonstrated need.

## Security and data-integrity fixes

### Trust boundaries

All quote, client, catalog, profile, payment, and admin mutations are validated with strict Zod schemas. Unknown fields are stripped instead of accepted.

The application uses server-authoritative totals. Browser-submitted totals are not trusted for invoice amounts.

### Money

Invoices persist amount, amount paid, and currency separately in integer minor units. JPY is treated as a zero-decimal currency. The browser and server use the same precision rules.

### Quote concurrency

Editable quotes use versions for optimistic concurrency. Accepted quotes are locked. Quote sending and acceptance lock the database row before replacing capability links or issuing invoices.

### Invoice concurrency

Payment recording locks the invoice row. Payments are append-only. Overpayments are rejected. An idempotency key can safely replay the same payment request, while reuse of a key for a different invoice returns a conflict.

### Accepted-document freezing

Accepting a quote produces an invoice snapshot. The accepted quote cannot be edited or deleted through normal mutation routes. Invoice status changes cannot erase recorded payment history.

### Share links

Public document links use 256-bit random bearer tokens. PostgreSQL stores only the SHA-256 lookup hash. The current token is additionally encrypted with AES-256-GCM so reminder workers can send the current link without storing the token in plaintext. Link replacement is an upsert, which avoids the prior unique-key collision bug.

### Billing

PayFast ITNs must pass provider validation and the checkout amount must match the server-created checkout record before subscription state changes. ITN replay handling is status-aware. Failed payment counters are updated under row locks.

### Authentication

Production email verification is required. Password reset and verification email sends do not block the authentication request on the provider call, which reduces timing differences. Password changes can revoke other sessions.

### Browser request protection

Authenticated state-changing browser requests require the application origin. API responses are marked no-store. Standard response headers include content-type sniffing protection, referrer policy, frame protection, permissions policy, cross-origin opener policy, and production HSTS.

### Deployment safety

Database migrations are no longer executed from every application replica at startup. Railway runs migrations in its pre-deploy phase, then starts the application.

## Reliability and scalability fixes

### Database coordination

Usage limits and document counters use PostgreSQL advisory transaction locks. This prevents concurrent requests from exceeding per-user limits or issuing duplicate document numbers.

### Email outbox

Quote and invoice messages are stored as database jobs. Workers claim rows using `FOR UPDATE SKIP LOCKED`, retry with backoff, and deduplicate by idempotency key. Multiple replicas can run the worker without delivering the same job twice.

### Reminder automation

Invoice reminders are scheduled in the database at three days before due, on the due date, three days overdue, and fourteen days overdue. Reminder links are actionable and point to the current invoice capability URL.

### Indexing

Invoice due dates have a dedicated index for the scheduler. Invoice numbers are unique per user. Payment, share-link, event, email-job, quote, and checkout access paths have supporting indexes.

### Portability

Authenticated users can export profile, subscription state, quotes, invoices, payments, clients, and catalog data as JSON.

## Quote and invoice workflow coverage

The application now covers the following common workflow pain points:

| Workflow pain point | Status | Implementation |
|---|---|---|
| Fast quote creation | Covered | Existing editor retained and completed |
| Reusable catalog items | Covered | Catalog picker and server validation |
| Duplicate an existing quote | Covered | Idempotent duplicate endpoint and editor action |
| Client self-service review | Covered | Secure public quote link |
| Quote accept/decline | Covered | Public response flow with typed respondent acknowledgement |
| Quote-to-invoice conversion | Covered | Transactional invoice creation from accepted snapshot |
| Clear payment terms | Covered | Due date and terms captured at quote time |
| Partial payments | Covered | Append-only, idempotent manual payment records |
| Payment history | Covered | Immutable invoice payment records and public history |
| Overdue state | Covered | Derived from due date and remaining balance |
| Automated payment reminders | Covered | Database outbox and scheduler |
| Reminder links that actually work | Covered | Encrypted recovery of current share token |
| Data export | Covered | JSON account export |
| Auditability of quote responses | Covered | Quote event records and request metadata hashes |
| Concurrent editing protection | Covered | Version checks and row locks |
| Production migration safety | Covered | Railway pre-deploy migrations |
| Public document privacy | Covered | Hashed bearer links, revocation, no session exposure |
| Mobile-friendly access | Covered | Responsive web frontend |

## Benchmark against current market expectations

Current official product documentation shows that mature invoicing products commonly include recurring invoices, online payment options, automated reminders, customer portals, quote approval, partial payments, payment schedules, and payment automation.

QuickBooks documents recurring invoices and estimates plus recurring payment options. Zoho documents customer-portal quote acceptance, customer comments, recurring invoices, automated reminders, and partial payments. FreshBooks documents recurring invoices, partial payments, payment schedules, reminders, late fees, and retainers. Xero documents click-to-pay, multiple online payment methods, automatic reminders, repeating invoices, invoice status tracking, and mobile invoicing. PandaDoc documents payment within proposal/signing flows and qualified electronic signatures.

This application deliberately does not ship a shallow imitation of financial infrastructure. The following remain explicit product boundaries:

| Capability | Current status | Reason |
|---|---|---|
| Online customer card/bank payments | Not enabled | Requires tenant-owned payment accounts, onboarding, webhooks, settlement, refunds, chargebacks, and provider-specific secret handling. Routing customer money through the SaaS subscription merchant account would be unsafe. |
| Autopay for customer invoices | Not enabled | Same tenant-owned payment-provider boundary. |
| Recurring customer invoices | Not enabled | Current invoice model is intentionally quote-originated; automatic recurring issuance needs a separate schedule model and invoice lifecycle rather than silently overloading quote acceptance. |
| Payment schedules / retainers | Not enabled | Requires installment/credit allocation semantics and additional accounting state. |
| Late fees | Not enabled | Needs explicit contractual settings and jurisdiction-aware tax/accounting treatment. |
| Qualified / regulated e-signatures | Not enabled | Requires dedicated signer identity, evidence, consent, signature lifecycle, and legal-provider infrastructure. Typed acceptance is not represented as a qualified signature. |
| Accounting integrations | Not enabled | Requires OAuth, account mapping, synchronization conflict handling, reconciliation rules, and provider-specific ledgers. |
| Full tax compliance engine | Not enabled | Percentage tax in quotes is supported; country-specific filing and tax rules are not fabricated. |
| Team workspaces / granular roles | Limited | Admin access exists, but a full organization/team model was not added because it changes the tenancy and authorization model substantially. |

These boundaries are deliberate. Adding one of these systems without its full trust and reconciliation model would create more risk than value.

## Anti-vibe audit

No CSS gradient was found in the frontend.

No fake reviews or fake customer counters were added.

No AI-generation badges were added.

No primary UI iconography uses emoji.

No new animation framework or scroll/cursor effect was introduced.

The existing small interaction transitions were retained because they provide direct interaction feedback rather than decoration.

The application uses real workflow copy instead of generic hero claims.

A favicon is registered and now exists at `public/favicon.svg`.

`privacy-policy.html` and `terms.html` are present and were corrected for the current data flows.

## Test and verification status

Passed in this environment:

1. Server and browser monetary calculations were transpiled and executed independently. ZAR rounding, JPY zero-decimal rounding, minor-unit conversion, and HTML print escaping checks passed.
2. Security primitives were transpiled and executed independently. Token generation, deterministic hashing, AES-256-GCM round trips, and tamper rejection passed.
3. Repository scans found no `.passthrough()` schemas, no live FX network dependency in print output, and no CSS gradients.

Not fully executable in this container:

The repository's native runtime test suite is Bun-based, but Bun is not installed in the execution environment. Installing Bun through npm also timed out, and the repository dependencies could not be installed completely within the available environment. PostgreSQL integration tests therefore could not be executed here.

The existing test suite was updated where the hardened billing and print behavior changed. The final runtime gate for deployment is `bun test` against a disposable PostgreSQL database, followed by a staging migration and PayFast sandbox ITN test.

## Production release gate

Set HTTPS values for `BETTER_AUTH_URL` and `CLIENT_URL`.

Set `BETTER_AUTH_SECRET` to a generated secret of at least 32 characters.

Configure a verified Resend sender.

Run database migrations using the Railway pre-deploy command.

Run the full Bun test suite against PostgreSQL.

Exercise PayFast sandbox checkout, COMPLETE, FAILED, replay, wrong-amount, and cancellation scenarios.

Verify `/api/ready` returns 200 only after PostgreSQL is reachable.

Verify the final custom domain is used in auth, public links, and PayFast return/notify URLs.

Verify the Privacy Policy, Terms & Conditions, and favicon on the production domain.

## Document deletion and financial audit hardening

The document lifecycle was upgraded after the initial production hardening pass.

Quotes now use soft deletion through `deleted_at` and `deleted_by`. The DELETE endpoint updates the quote instead of removing its row, records a `deleted` quote event, revokes the active quote share link, and prevents queued quote delivery from sending after archival. Accepted quotes can also be archived without breaking their linked invoice because the invoice remains attached by its existing foreign key.

Quotes can be restored through a dedicated restore endpoint. Restoration records a `restored` quote event. Restoring does not silently reactivate an old public link; sending the quote creates or rotates the capability link again.

Invoices now use the same soft-delete mechanism. Invoice deletion records an `invoice_events.deleted` event, revokes its public link, and prevents queued delivery or reminder jobs from sending after archival. A restore endpoint records `invoice_events.restored`.

Invoices and payment records are never hard-deleted by the application. `invoice_payments` remains a separate immutable transaction table, while `invoice_events` records the lifecycle. Payment receipt and full-payment transitions are logged explicitly.

Archived quotes and invoices are excluded from active lists and can be inspected through the archived-list mode. The application exposes history endpoints for both quote and invoice event logs.

Public quote and invoice capability URLs return HTTP 410 after archival. This prevents a deleted business document from remaining accessible through a previously issued bearer link.

The reminder scheduler excludes archived invoices. The email worker also checks the current document state immediately before sending so a queued message cannot resurrect an archived workflow by sending after deletion.

Migration: `server/db/migrations/0010_document_soft_delete_and_invoice_events.sql`
