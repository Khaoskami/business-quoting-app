import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const sourceFiles = [];

function walk(dir) {
  for (const entry of fs.readdirSync(path.join(root, dir), { withFileTypes: true })) {
    const rel = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(rel);
    else if (/\.(ts|tsx)$/.test(entry.name)) sourceFiles.push(rel);
  }
}
walk('client/src');
walk('server');

const failures = [];
const pass = (name, ok, detail = '') => {
  if (!ok) failures.push(detail ? `${name}: ${detail}` : name);
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail && !ok ? ` — ${detail}` : ''}`);
};

const clientSrc = sourceFiles.filter((f) => f.startsWith('client/')).map(read).join('\n');
const serverSrc = sourceFiles.filter((f) => f.startsWith('server/')).map(read).join('\n');
const allSrc = `${clientSrc}\n${serverSrc}`;

// 1. Relative import target audit.
let brokenImports = 0;
for (const file of sourceFiles) {
  const text = read(file);
  const dir = path.dirname(file);
  for (const match of text.matchAll(/from\s+['"](\.[^'"]+)['"]/g)) {
    const spec = match[1];
    const base = path.normalize(path.join(dir, spec));
    const candidates = ['.ts', '.tsx', '.js', '.jsx'].map((ext) => base + ext).concat(path.join(base, 'index.ts'), path.join(base, 'index.tsx'));
    if (!candidates.some((candidate) => fs.existsSync(path.join(root, candidate)))) brokenImports++;
  }
}
pass('relative imports', brokenImports === 0, `${brokenImports} unresolved relative imports`);

const indexHtml = read('client/index.html');
const editor = read('client/src/pages/Editor.tsx');
const quoteApi = read('client/src/api.ts');
const quotes = read('server/routes/quotes.ts');
const invoices = read('server/routes/invoices.ts');
const serverIndex = read('server/index.ts');
const auth = read('server/auth.ts');
const sw = read('public/sw.js');
const main = read('client/src/main.tsx');
const styles = read('client/src/styles.css');

const clientsRoute = read('server/routes/clients.ts');
const profileRoute = read('server/routes/profile.ts');
const emailOutbox = read('server/lib/email-outbox.ts');
const pricing = read('shared/pricing.ts');
const settingsPage = read('client/src/pages/Settings.tsx');
const landingPage = read('client/src/pages/Landing.tsx');

pass('transactional email auth wiring',
  auth.includes('sendResetPassword') && auth.includes('sendVerificationEmail') && auth.includes('RESEND_API_KEY') &&
  auth.includes('resetPasswordTokenExpiresIn: 60 * 60'));

pass('direct client email endpoint',
  clientsRoute.includes("clientsRouter.post('/:id/email'") && clientsRoute.includes('enqueueClientEmail') &&
  quoteApi.includes('clients:') && read('client/src/api.ts').includes('email: (id: string, data: { subject: string; message: string })'));

pass('email quota and race protection',
  emailOutbox.includes('emailUsage') && emailOutbox.includes('pg_advisory_xact_lock') && emailOutbox.includes('existingAfterLock'));

pass('json-safe subscription limits',
  profileRoute.includes('quotesPerMonth: rawLimits.quotesPerMonth === Infinity ? null') &&
  profileRoute.includes('maxClients: rawLimits.maxClients === Infinity ? null'));

pass('customer-facing Growth pricing',
  pricing.includes("name: 'Growth'") && pricing.includes('price: 1099') && pricing.includes('price: 1699') &&
  settingsPage.includes('400 client emails/month') && landingPage.includes('R1,099 / month'));

pass('quote exact deep-link lookup',
  quoteApi.includes("get: (id: string) => request<any>(`/quotes/${encodeURIComponent(id)}`)") &&
  editor.includes("queryFn: () => api.quotes.get(id!)") &&
  quotes.includes("quotesRouter.get('/:id'") &&
  quotes.includes('eq(quotes.id, id), eq(quotes.userId, userId)'));

pass('quote render race is gated',
  editor.includes("if (!isNew && !q) return <div className=\"page-loading\">Preparing quote editor...</div>"));

pass('JSON API 404 boundary', serverIndex.includes("app.all('/api/*', (c) => c.json({ error: 'Not found' }, 404));"));

pass('authenticated invoice write scoping',
  invoices.includes("eq(invoices.id, c.req.param('id')), eq(invoices.userId, userId)") &&
  invoices.includes("eq(invoices.id, invoice.id), eq(invoices.userId, userId)"));

pass('normalized browser origins',
  serverIndex.includes('new URL(process.env.CLIENT_URL!).origin') &&
  auth.includes("new URL(process.env.CLIENT_URL ?? 'http://localhost:5173').origin") &&
  auth.includes("new URL(process.env.BETTER_AUTH_URL ?? 'http://localhost:3000').origin"));

pass('single responsive viewport declaration',
  (indexHtml.match(/name=["']viewport["']/g) || []).length === 1 && indexHtml.includes('viewport-fit=cover'));

pass('service worker bypasses API and auth',
  /url\.pathname\.startsWith\('\/api\/'\)\s*\|\|\s*url\.pathname\.startsWith\('\/auth\/'\)/.test(sw) &&
  sw.includes("CACHE_VERSION = 'bq-saas-v2'"));

pass('service worker update bypass', main.includes("updateViaCache: 'none'"));

pass('public pages validate response shape',
  read('client/src/pages/PublicQuote.tsx').includes('Array.isArray(data.quote.items)') &&
  read('client/src/pages/PublicInvoice.tsx').includes('Array.isArray(data.invoice.items)'));

pass('dangerous DOM sinks absent',
  !/(dangerouslySetInnerHTML|document\.write|eval\(|new Function)/.test(allSrc));
pass('raw innerHTML absent', !/\binnerHTML\b/.test(allSrc));
pass('responsive public document styles present',
  styles.includes('.public-document') && styles.includes('@media (max-width: 720px)') && styles.includes('safe-area-inset-bottom'));
pass('security headers present',
  serverIndex.includes("X-Content-Type-Options") &&
  serverIndex.includes("X-Frame-Options") &&
  serverIndex.includes("Referrer-Policy") &&
  serverIndex.includes("Permissions-Policy"));

if (failures.length) {
  console.error(`\n${failures.length} vet check(s) failed.`);
  process.exit(1);
}
console.log(`\nAll ${19} site vet checks passed.`);
