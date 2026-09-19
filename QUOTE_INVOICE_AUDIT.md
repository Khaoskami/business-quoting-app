# Quote + Invoice UX Audit

## Product objective

The app should not feel like a database with a few document forms. It should feel like a lightweight quote-to-cash assistant:

Pick a client → build a quote → send it → follow up → capture approval → issue the invoice → remind → record payment.

The product should answer one question on every screen: what should I do next?

This audit combines a repository review with current 2026 market/review evidence. It targets recurring quote and invoicing friction rather than trying to reproduce a full accounting suite.

## Pain points found and how the repo now solves them

| Pain point | Why it hurts | Product response in this repo |
|---|---|---|
| Starting a quote requires navigating between client and quote screens | Small businesses lose time switching context and risk creating incomplete documents | Quote builder accepts a `client` query parameter and Clients now has one-click New quote |
| The quote form exposes too many concerns at once | Users have to reason about client, line items, tax, terms, notes, and sending at the same time | Quote editor is organized into Step 1 client, Step 2 line items, Step 3 advanced details |
| Creating a client interrupts quote creation | A missing client becomes a dead end | Inline Add client modal creates the client and immediately attaches it to the quote |
| Draft work can disappear if a tab is closed | Rebuilding a quote is pure waste | New quote drafts are autosaved locally on the device and restored on return |
| Users cannot tell whether a quote is actually ready to send | A generic Draft label hides the blocking reason | Quote checklist and attention states surface Missing client, Missing email, Add line items, Awaiting reply, Follow up, Act soon, Expired |
| Follow-up work is easy to forget | A sent quote can sit without a response and quietly become stale | Quotes have a first-class Follow up state and a dedicated follow-up email action |
| Sending and following up are the same mental task | A resend can feel ambiguous | First send is Send; response chasing is Follow up |
| Quote expiry is hard to notice | Time-sensitive offers can go stale without a visible next action | Expiry is surfaced as Act soon and Expired in the dashboard and quote list |
| Accepted quotes can be accidentally altered | Accepted pricing needs to remain an auditable source document | Existing immutable accepted-quote behavior is retained; the owner approval action now requires an explicit confirmation step |
| Invoice creation can feel like a second data-entry job | Re-keying accepted quote data creates errors and delay | Existing acceptance flow creates the invoice from the accepted pricing snapshot |
| Invoices are passive records instead of a collection work queue | The user must inspect individual records to know what is late | Invoice page and dashboard surface Outstanding, Overdue, Due soon, Paid states |
| Sending an invoice again is harder than it should be | Email delivery often needs a resend after an address change or missed message | New Send invoice action queues an email and refreshes the client link |
| Overdue chasing is manual | The user has to write a reminder every time | New Remind invoice action queues a payment reminder with balance and due date |
| Automatic reminders are not enough for every situation | A business may need an immediate manual nudge | Manual invoice reminder sits beside the document, while the existing scheduled reminders remain intact |
| Payment state is easy to misread | “Sent” does not answer how much is still owed | Invoice cards show balance remaining against the original total; public invoice shows a dedicated Balance due callout |
| Public invoice status is misleading | A hardcoded “sent” badge can say “sent” when an invoice is paid or overdue | Public invoice now maps status to Paid, Overdue, Partially paid, Open, Void |
| Recording a payment is buried in a dense row | The user has to parse many actions before finding collection work | Invoice actions are grouped around the collection task: send, remind, record payment, share, PDF, history |
| Archived data is not reliably reachable | Archive flows often become dead ends when UI and API parameters drift | Fixed the archived-document query parameter for quotes and invoices to use the server's `deletedOnly=1` contract |
| Money totals can be missing from legacy/derived list rows | A list view can show zero when `totalMinor` is not present | Quote list falls back to the same shared `calcTotals` calculation used elsewhere |
| Tax can be silently assumed for new quotes | A hardcoded tax rate can put the wrong tax amount on a document | New quotes now start at 0% tax instead of silently guessing a jurisdiction-specific 15% |
| Client list is disconnected from revenue work | Client management becomes a separate administrative chore | Every client row can now launch a quote directly |
| Users can lose the client link after sharing | A sent document may be hard to retrieve | Send/share flows copy the public link and show an in-app “link ready” banner |
| Audit history is useful but easy to ignore | Teams need confidence about who sent, approved, or paid | Quote and invoice history remains accessible as a timeline from the working UI |

## Dashboard redesign

The dashboard is now a work queue rather than a generic reporting page.

It surfaces:

1. Outstanding money
2. Overdue invoices
3. Quotes awaiting replies
4. Accepted quotes
5. A prioritized Needs attention queue
6. A visible quote-to-cash flow
7. Recent quote/invoice activity

The intention is that the owner can open the app and act immediately rather than hunt through pages.

## Market evidence

Current Capterra billing/invoicing review data says reviewers rate Quotes/Estimates (56%), Invoice Creation (55%), and Invoice Processing (53%) as critical top-priority features. This supports treating the quote-to-invoice-to-payment chain as the core product, not separate modules. Source: Capterra 2026 billing/invoicing review data.

A verified G2 Zoho Invoice review describes the pre-automation experience as: “manually track payments, send reminders, and create invoices from scratch”, calling it time-consuming and error-prone. This directly supports turning reminders, payment state, and document creation into workflow actions rather than manual administration.

A G2 Zoho Books review says the product “Needs to be more simplified for customer use.” That is a useful benchmark for the UX direction here: expose the simple path first and keep advanced accounting-style controls out of the main quote-building decision path.

Recent G2 billing guidance also notes that invoice creation itself is no longer the only differentiator; the workflow after invoicing, especially reducing manual follow-ups and reconciliation work, is increasingly important.

## What was already strong in the repo

The backend foundation was already ahead of many small-business CRUD apps. The rework keeps these behaviors instead of replacing them with a simpler but unsafe implementation:

1. Server-authoritative pricing
2. Integer minor-unit invoice amounts
3. Immutable accepted quotes
4. Append-only payments with idempotency
5. Optimistic concurrency for editable quotes
6. Soft deletion and restore
7. Revocable public links with hashed/encrypted storage
8. PostgreSQL-backed email outbox with retries and deduplication
9. Scheduled invoice reminders
10. Real PDF generation on the server
11. Railway-friendly migrations

## Deliberate product boundaries

This app should solve quoting and receivables without pretending to be a general ledger.

Not every business needs built-in payroll, bank reconciliation, inventory, tax filing, or a full accounting ledger just to send a quote and collect an invoice.

Customer-facing card/bank payment processing also remains intentionally separate from the app's own SaaS subscription merchant account. The existing model of client payment instructions plus immutable payment recording remains safer than pretending a customer payment rail already exists.

## Next product opportunities

The next high-value capabilities should continue to remove repeated work around the same core flow:

1. Quote follow-up templates with configurable timing
2. Client reply inbox for quote questions and revision requests
3. Saved quote templates by service type
4. Deposit/milestone billing for projects that do not become a single full-balance invoice
5. Business-specific payment links once a supported customer payment provider is selected
6. Multi-user roles for owners, sales staff, and finance staff
7. CSV/financial export packs for accountants
8. Country-specific tax/compliance modules only for markets that are explicitly supported

## Acceptance criteria for future changes

A feature belongs in the core workflow when it does at least one of these things:

1. Removes a repeated data entry step
2. Turns a forgotten task into a visible next action
3. Prevents a likely money/document error
4. Makes client approval or payment state unambiguous
5. Preserves an auditable history

A feature should not be added to the main path merely because a large accounting product has it.
