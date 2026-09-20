# Business Quotes — Full Site Vet Report

Date: 2026-09-20

## Production issue reproduced from supplied screenshot

The quote editor at `/quotes/:id/edit` could crash with:

`Cannot read properties of undefined (reading 'quoteNumber')`

### Root cause

The editor previously loaded the entire quote list and derived `existing` from that list. When React Query finished loading, `existing` could become defined during a render while local state `q` was still `undefined`; the `useEffect` that copied `existing` into `q` runs after render. The render then accessed `q.quoteNumber` before `q` existed.

The list-based lookup also limited deep-linked quote editing to the first 250 quotes returned by the API.

## Fixes applied

### Quote loading

* Added an exact authenticated `GET /api/quotes/:id` endpoint with owner scoping.
* Editor now loads a quote directly by ID instead of searching the 250-row list.
* Added explicit loading, API error, missing-quote, and editor-preparation states.
* Added retry handling and a visible retry action.
* Removed the render-time race that caused the `quoteNumber` exception.

### API routing

* Added a JSON 404 boundary for unmatched `/api/*` routes so invalid API URLs cannot fall through to the SPA HTML response.
* Normalized public URLs to remove accidental double slashes when `CLIENT_URL` or `BETTER_AUTH_URL` has a trailing slash.

### Authentication / downloads

* Hardened blob/PDF request handling so authentication failures are handled consistently with normal API requests.

### Service worker / caching

* Updated the service-worker cache version.
* Disabled HTTP cache reuse during service-worker update checks.
* Kept API/authenticated application routes out of static asset caching.

### Responsive UI

* Consolidated the viewport configuration.
* Added `viewport-fit=cover`.
* Added minimum viewport handling around 320px.
* Added mobile styling for public quote and invoice documents.
* Added responsive document headers, metadata, tables, totals and action controls.
* Added narrow-screen and touch-friendly layout handling.

## Automated checks performed

### PASS — relative import audit

Client and server source files were scanned for relative imports. No broken relative import targets were found.

### PASS — route contract audit

Verified that:

* the client has an exact quote GET API method
* the editor uses the exact quote GET method
* the server exposes an owner-scoped `GET /:id` quote route
* unknown `/api/*` requests return JSON 404
* the SPA fallback remains available for browser routes

### PASS — quote editor race-condition audit

Verified the editor cannot render quote properties before the exact quote query has produced usable data and that loading/error/not-found states are handled before the editor UI.

### PASS — static web/security audit

Checked for:

* duplicate viewport metadata
* mobile viewport support
* service-worker API/auth caching
* stale service-worker update behavior
* dangerous `eval`, `new Function`, `document.write`, and `dangerouslySetInnerHTML` usage
* security headers
* responsive CSS coverage for public documents

No issues were found in those checks.

### PASS — pure source tests

The finance and quote utility source was compiled independently and executed against representative cases including currency rounding and HTML escaping.

Representative checks passed for:

* ZAR line/subtotal/tax/total calculations
* JPY minor-unit rounding
* quote total calculation
* HTML attribute escaping used in PDF/print HTML
* print-content CSP presence

## Existing test suite

The repository already contains tests covering document lifecycle, finance, PDF generation, schemas, security, plan tiers, and conditional billing integration.

The complete Bun test suite could not be executed in this environment because Bun is not installed and dependency installation via npm timed out before a usable dependency tree was available. A production build was therefore not claimed as passed.

## Live-site verification limitation

A direct black-box request to `https://businessquoting.com` could not be completed from this environment because outbound access to the deployed site was unavailable. The supplied screenshot was used as the concrete failure symptom, and the repository was audited and patched against that failure path.

## Production smoke test checklist

After deployment, verify:

1. Sign in.
2. Open the quotes list.
3. Open an existing quote from the list.
4. Directly paste `/quotes/<id>/edit` into a new browser tab.
5. Open an older quote beyond the first 250 records.
6. Create a quote and save it.
7. Generate/view its PDF.
8. Send/share the quote and open the public link.
9. Accept/decline the quote from the public page.
10. Convert the accepted quote into an invoice.
11. Open the invoice list and use its invoice actions.
12. Generate/view the invoice PDF.
13. Repeat quote/invoice flows at phone widths around 320–390px, tablet widths and desktop widths.
14. Verify a logged-out browser cannot access another user's private quote URL.

## Recommended production commands

Use the repository's existing scripts:

```text
bun install --frozen-lockfile
bun test
bun run build
bun db:migrate
```

Deploy only after those complete successfully in the Railway build environment.

## Additional findings fixed during the full-site pass

### URL configuration normalization

CORS and authentication trusted-origin configuration now use normalized URL origins. Public URL generation, billing return URLs and invoice/quote email links also strip trailing slashes. This avoids malformed `//path` URLs and avoids a trailing slash in environment configuration causing browser-origin mismatches.

### Defense-in-depth invoice scoping

Invoice write operations that already performed an owner check now also include `userId` in their final SQL update predicates. This reduces the blast radius of future changes and keeps ownership enforcement explicit at the write boundary.

### Public document resilience

Public quote and invoice pages now validate the response shape before rendering item arrays, tolerate missing business profile data, expose response errors to the visitor, and show PDF download failures instead of silently doing nothing.

## Final assessment

The supplied quote-editor error has a specific, fixed root cause. The codebase has also been checked for common SPA routing failures, React render races, API-to-SPA fallback confusion, authentication handling, unsafe DOM sinks, request validation, URL construction, ownership predicates, service-worker caching, responsive viewport configuration, public document rendering, financial calculation consistency, and PDF/print escaping.

The remaining release uncertainty is execution against the real Railway environment and its PostgreSQL database. That cannot be truthfully marked as passed from this container because the production domain did not resolve here and the repository's Bun dependency/runtime stack was not available locally.
