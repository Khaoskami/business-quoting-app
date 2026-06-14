# Business Quotes App

Multi-user SaaS for creating professional business quotes. Server-side auth, PostgreSQL storage, Stripe billing, admin panel.

## Stack

- **Runtime:** Bun
- **API:** Hono
- **Auth:** Better Auth (email/password, 30-day sessions, httpOnly cookies, rate-limited auth routes)
- **Database:** PostgreSQL + Drizzle ORM
- **Payments:** Stripe (subscriptions + billing portal + webhooks)
- **Frontend:** React 18 + Vite + TanStack Query + React Router
- **Deploy:** Railway (single service, Postgres plugin)

## Local development

```bash
bun install

# Set up DATABASE_URL and BETTER_AUTH_SECRET in .env (copy .env.example)
bun run db:generate
bun run db:migrate

bun run dev
# Server: http://localhost:3000
# Client: http://localhost:5173 (proxies /api and /auth to the server)
```

## Production build

```bash
bun run build   # vite build -> dist/public
bun start       # serves the API + static SPA on $PORT
```

## Railway deploy

1. New Project → connect this repo.
2. Add the **PostgreSQL plugin**. Railway auto-injects `DATABASE_URL`.
3. Set the remaining env vars from `.env.example`:
   - `BETTER_AUTH_SECRET` (`openssl rand -base64 32`)
   - `BETTER_AUTH_URL` and `CLIENT_URL` (your Railway domain)
   - `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`
   - `STRIPE_PRO_PRICE_ID`, `STRIPE_BUSINESS_PRICE_ID`
   - `ADMIN_EMAIL` — default email to promote with the admin script (see [Admin](#admin))
4. Stripe → Developers → Webhooks → endpoint:
   `https://your-app.up.railway.app/api/billing/webhook`
   Events: `checkout.session.completed`, `customer.subscription.created`,
   `customer.subscription.updated`, `customer.subscription.deleted`,
   `invoice.payment_failed`.
5. Push to deploy. Railway runs `bun run db:migrate && bun start`.

Health check: `GET /api/health` → `{"ok": true}`.

## Tiers

| Tier      | Quotes/mo | Clients   | Catalog   | Features                                         |
|-----------|-----------|-----------|-----------|--------------------------------------------------|
| Free      | 5         | 3         | 10        | CSV export                                       |
| Pro       | 50        | 999       | 999       | + Print/PDF, discounts, signatures, client URLs  |
| Business  | ∞         | ∞         | ∞         | All Pro features                                 |

Tiers are server-side truth. Limits enforced in `server/lib/tier.ts` and per-route counts.
Admins can **comp** any user to Pro or Business from the Admin panel.

## Admin

Admins are **not** auto-promoted on registration. Email-verification infra isn't
wired up yet, so rather than trusting a sign-up email we promote admins
explicitly with a one-off script:

```bash
# Promote a specific user
bun run scripts/make-admin.ts someone@example.com

# Or fall back to ADMIN_EMAIL from the environment
bun run scripts/make-admin.ts
```

Once promoted, the admin panel is at `/admin`:

- Stats: total users, pro, business, comped
- User table with: Grant Pro, Grant Business, Revoke, Make/Remove Admin

### Auth hardening

- Email/password sign-up does **not** require email verification yet
  (`requireEmailVerification: false`) — flip it on once an email sender is wired
  into `server/auth.ts`.
- Better Auth's built-in rate limiting is enabled on the auth routes
  (100 requests / 60s window per IP).

## Migrating from the previous local-only build

Settings → **Import from old app** uploads any `bq_*` localStorage data to your account.
AES-encrypted data from after the auth update **cannot** be migrated automatically.

## License

Copyright (c) 2026 Khaoskami. All rights reserved. See [LICENSE](./LICENSE).
