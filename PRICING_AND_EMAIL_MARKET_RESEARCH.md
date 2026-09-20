# Pricing, packaging and transactional email market research — September 2026

## Objective

Business Quotes is being positioned as a focused quote-to-cash workflow for small businesses and service professionals: quoting, client communication, quote approval, invoice creation, payment tracking and follow-up. The pricing goal supplied for this release is to exceed R50,000 in monthly recurring revenue at 50 customers on the middle plan or higher.

## Market observations

South African accounting suites sit materially above local lightweight quoting tools. Xero South Africa currently lists Starter at R450/month, Standard at R795/month and Premium at R1,095/month, with a published increase from 1 November 2026 to R485, R857 and R1,195 respectively. Xero's Standard and Premium tiers include quoting/invoicing plus accounting, reconciliation and reporting capabilities.

QuipDesk is a lower-priced South African niche competitor: R129/month Starter, R299/month Professional and R599/month Business. Its published feature set includes quotes, invoices, client portal, e-signature, email automation/reminders, recurring invoices and team controls.

Bonsai is a global client-workflow competitor with annual-billing equivalents of $15/user/month Basic, $25 Essentials, $39 Premium and $59 Elite, with higher plans adding proposals, contracts, client portal, reporting, integrations and team controls.

The implication is that a R1,000+ price point needs to be justified by a tightly integrated quote-to-cash workflow, meaningful client communication capacity, automation, reporting, team controls and differentiated reliability rather than by simple PDF quoting alone.

## Email infrastructure

Resend's current free transactional-email plan is 3,000 emails/month with a 100-email/day limit and 3 domains. Its Pro plan is $20/month for 50,000 emails/month and removes the daily limit. This is sufficient for early authentication emails and modest application email volume, provided Business Quotes enforces its own product quotas and anti-abuse controls.

Brevo's current free plan provides 300 email sends/day and includes transactional email. Mailjet's current free plan provides 6,000 emails/month with 200/day. These alternatives were considered, but the repository already uses the Resend SDK and the implementation therefore keeps Resend as the primary provider.

## Implemented pricing

Free: R0. 5 quotes/month, 3 clients, 10 catalog items, 10 client-email credits/month, PDF generation and client-facing quote links. Authentication verification and password-reset email delivery are not counted against the in-app client-email quota.

Growth: R1,099/month. 300 quotes/month, 250 clients, 500 catalog items, 400 client-email credits/month, discounts, CSV export, quote duplication, manual reminders and automated invoice reminders.

Business: R1,699/month. Unlimited quotes/clients/catalog, 2,000 client-email credits/month, all Growth workflow features plus custom reminder schedules and higher-volume client communication capacity.

## Revenue math for the supplied target

At 50 paid customers where every customer is at least on Growth:

50 × R1,099 = R54,950 monthly recurring revenue before VAT, refunds, payment fees, churn and discounts.

If any of those 50 customers are on Business, monthly recurring revenue is higher because Business is R1,699/month.

This is a pricing model, not a sales forecast. It does not imply that 50 customers will be acquired at these prices.

## Backwards compatibility

The database tier key `pro` remains in place and is customer-facing as Growth. Existing subscribers are not silently repriced by the migration. Their previous billing amount is stored in `billingAmountMinor` and the settings UI can show a grandfathered rate. New checkouts use the new Growth and Business prices.

## Sources

Resend pricing: https://resend.com/pricing
Brevo pricing: https://help.brevo.com/hc/en-us/articles/208589409-About-Brevo-s-pricing-plans
Mailjet pricing update: https://documentation.mailjet.com/hc/en-us/articles/25750983876763-Mailjet-Subscription-Pricing-Update-September-9-2026
Xero South Africa pricing: https://www.xero.com/za/pricing-plans/
Xero South Africa price update: https://www.xero.com/za/pricing-plans/update/
QuipDesk pricing: https://quipdesk.co.za/pricing
Bonsai pricing: https://www.hellobonsai.com/pricing
