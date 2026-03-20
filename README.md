# Business Quotes App

Free encrypted quoting application for any business in any field.

## Features

- **Quote Builder** — Line items, tax, discounts, custom numbering, client linking
- **Product & Service Catalog** — Reusable items with categories and pricing units
- **Client Management** — Store client details, websites, and notes
- **Multi-Currency** — 18 currencies with proper formatting (ZAR, USD, EUR, GBP, etc.)
- **Print / PDF Export** — Professional quote documents with your business branding
- **CSV Export** — Spreadsheet-compatible exports with IP watermark
- **SHA-256 Signatures** — Cryptographic integrity hashes on every signed quote
- **AES-256-GCM Encryption** — All data encrypted client-side before storage
- **Zero Server** — 100% client-side. No data leaves the user's device
- **PWA** — Installable on phones. Works offline
- **Freemium Model** — Free tier with upgrade gates for Pro ($9.99/mo) and Business ($24.99/mo)

## Security

- AES-256-GCM encryption via Web Crypto API with unique 12-byte IV per record
- Session-scoped encryption keys (destroyed on tab close)
- XSS sanitisation on all inputs (HTML entity encoding)
- URL validation (protocol whitelisting, script injection blocking)
- Content Security Policy headers via vercel.json
- No eval(), no dynamic scripts, no cookies, no tokens

## Two Builds

| File | Purpose |
|------|---------|
| `src/App.jsx` | **Production** — Freemium tiers, payment gates, usage limits |
| `src/AppDev.jsx` | **Dev / Trial** — All features unlocked, no limits, separate storage |

To switch builds, edit `src/main.jsx` and change the import line.

## Setup

```bash
# Install dependencies
npm install

# Run locally
npm run dev

# Build for production
npm run build
```

## Deploy to Vercel

1. Push this repo to GitHub
2. Go to [vercel.com](https://vercel.com) and sign in with GitHub
3. Import this repository
4. Click Deploy
5. Your app is live

## Payment Setup

1. Create products on [Stripe](https://stripe.com) or [PayFast](https://payfast.co.za)
2. Create payment links for Pro and Business plans
3. In `src/App.jsx`, find `PAYMENT_URL` near the top and replace it with your real payment link
4. Commit the change — Vercel auto-deploys

## File Structure

```
├── index.html              Entry point
├── package.json            Dependencies
├── vite.config.js          Build config
├── vercel.json             Security headers
├── LICENSE                 Proprietary license
├── public/
│   ├── manifest.json       PWA manifest
│   ├── sw.js               Service worker (offline support)
│   ├── privacy-policy.html Privacy policy (for app stores)
│   ├── icon-192.png        App icon 192x192 (replace with yours)
│   └── icon-512.png        App icon 512x512 (replace with yours)
└── src/
    ├── main.jsx            React entry point (switch builds here)
    ├── App.jsx             Production build (freemium)
    └── AppDev.jsx          Dev build (all unlocked)
```

## Icons

Replace `public/icon-192.png` and `public/icon-512.png` with your own app icons.
Create them at [canva.com](https://canva.com) — use Custom Size 512x512 and 192x192.

## License

Copyright (c) 2026 Khaoskami. All rights reserved. See [LICENSE](./LICENSE).
