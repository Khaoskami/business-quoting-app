import { mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fromMinor, currencyDigits } from './finance';

const CURRENCY_SYMBOLS: Record<string, string> = {
  ZAR: 'R', USD: '$', EUR: '€', GBP: '£', AUD: 'A$', CAD: 'C$', JPY: '¥', INR: '₹',
  BRL: 'R$', NGN: '₦', KES: 'KSh', AED: 'د.إ', CNY: '¥', CHF: 'CHF', NZD: 'NZ$', MXN: 'MX$',
  SEK: 'kr', SGD: 'S$',
};


function cleanText(value: unknown): string {
  let text = String(value ?? '');
  if (/[ÃÂâð]/.test(text)) {
    try {
      const repaired = Buffer.from(text, 'latin1').toString('utf8');
      if (!repaired.includes('\uFFFD')) text = repaired;
    } catch {
      // Keep the original value if it was not valid mojibake.
    }
  }
  return text.replace(/[\u2013\u2014]/g, '-');
}

function esc(value: unknown): string {
  return cleanText(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function money(value: number, currency: string): string {
  const code = String(currency || 'ZAR').toUpperCase();
  const digits = currencyDigits(code);
  const locale = 'en-US';
  const symbol = CURRENCY_SYMBOLS[code] || code;
  const safe = Number.isFinite(value) ? value : 0;
  const amount = new Intl.NumberFormat(locale, {
    useGrouping: true,
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }).format(Math.abs(safe));
  return `${safe < 0 ? '-' : ''}<span class="currency-symbol">${esc(symbol)}</span><span class="currency-space"> </span><span class="currency-number">${amount}</span>`;
}

function num(value: unknown): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function fmtDate(value?: string | Date | null): string {
  if (!value) return 'Not set';
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.valueOf())) return 'Not set';
  return new Intl.DateTimeFormat('en', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }).format(d);
}

function safeFilename(parts: string[]): string {
  const value = parts.map(cleanText).join('-').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
  return value || 'document';
}

function logoHtml(biz: any): string {
  const logo = typeof biz?.logo === 'string' && /^data:image\/(png|jpeg);base64,[A-Za-z0-9+/]+={0,2}$/.test(biz.logo) ? biz.logo : '';
  return logo ? `<img src="${esc(logo)}" alt="Business logo" class="logo">` : '';
}

function documentHtml(input: { kind: 'quote' | 'invoice'; document: any; business: any; payments?: any[] }): string {
  const d = input.document || {};
  const biz = input.business || {};
  const cur = String(d.currency || 'ZAR').toUpperCase();
  const items = Array.isArray(d.items) ? d.items : [];
  const taxPercent = num(d.taxPercent);
  const discountPercent = num(d.discountPercent);
  const digits = currencyDigits(cur);
  const round = (v: number) => {
    const factor = 10 ** digits;
    return Math.round((v + Number.EPSILON) * factor) / factor;
  };
  const line = round(items.reduce((sum: number, item: any) => sum + round(num(item.quantity) * num(item.unitPrice)), 0));
  const discountAmount = round(line * discountPercent / 100);
  const subtotal = round(line - discountAmount);
  const tax = round(subtotal * taxPercent / 100);
  const total = round(subtotal + tax);
  const amountPaid = input.kind === 'invoice' ? fromMinor(Number(d.amountPaidMinor ?? 0), cur) : 0;
  const balance = input.kind === 'invoice' ? fromMinor(Math.max(0, Number(d.amountMinor ?? total * (10 ** digits)) - Number(d.amountPaidMinor ?? 0)), cur) : total;
  const title = input.kind === 'invoice'
    ? `Invoice ${cleanText(d.invoiceNumber || 'Invoice')}${d.title ? ` - ${cleanText(d.title)}` : ''}`
    : `Quote ${cleanText(d.quoteNumber || 'Quote')}${d.title ? ` - ${cleanText(d.title)}` : ''}`;
  const issued = d.issuedAt || d.createdAt;
  const validUntil = d.validUntil;
  const dueAt = d.dueAt || (d.paymentTermsDays != null && issued ? (() => { const x = new Date(issued); x.setDate(x.getDate() + Number(d.paymentTermsDays)); return x.toISOString(); })() : '');
  const paymentRows = (input.payments ?? []).map((p: any) => `<tr><td>${esc(fmtDate(p.receivedAt))}</td><td>${esc(p.method || 'Other')}</td><td class="amount">${money(fromMinor(Number(p.amountMinor || 0), cur), cur)}</td><td>${esc(p.note || '')}</td></tr>`).join('');
  const itemRows = items.map((item: any) => {
    const qty = num(item.quantity);
    const unitPrice = num(item.unitPrice);
    return `<tr><td class="description">${esc(item.description)}</td><td class="qty">${esc(qty)}</td><td class="amount">${money(unitPrice, cur)}</td><td class="amount">${money(qty * unitPrice, cur)}</td></tr>`;
  }).join('');
  const contact = [biz.email, biz.phone, biz.address].filter(Boolean).map(esc).join('<br>');
  const signature = d.signature ? `<section class="signature"><div class="label">Integrity signature</div><div class="hash">${esc(d.signature)}</div>${d.signedAt ? `<div class="muted">Signed: ${esc(d.signedAt)}</div>` : ''}</section>` : '';
  const invoicePayments = input.kind === 'invoice' && paymentRows ? `<section class="section"><h2>Payment history</h2><table><thead><tr><th>Date</th><th>Method</th><th class="amount">Amount</th><th>Reference</th></tr></thead><tbody>${paymentRows}</tbody></table></section>` : '';
  const invoiceBalance = input.kind === 'invoice' ? `<tr><td class="muted">Paid</td><td class="amount">${money(amountPaid, cur)}</td></tr><tr class="grand"><td>Balance due</td><td class="amount">${money(balance, cur)}</td></tr>` : `<tr class="grand"><td>Total due</td><td class="amount">${money(total, cur)}</td></tr>`;
  const notes = d.notes || (input.kind === 'invoice' ? biz.paymentInstructions : '');
  const terms = input.kind === 'invoice' ? biz.terms : '';
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; object-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src 'none';">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>
@page{size:A4;margin:16mm 15mm}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:#fff;color:#1f2937;font-family:"Noto Sans","Noto Sans Symbols 2","Noto Sans Arabic",Arial,sans-serif;font-size:12px;line-height:1.45;-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{padding:0}
.header{display:grid;grid-template-columns:1fr auto;gap:28px;border-bottom:2px solid #1f2937;padding-bottom:16px;align-items:start}
.logo{display:block;max-width:180px;max-height:58px;object-fit:contain;margin-bottom:10px}
h1{font-size:24px;line-height:1.15;margin:0 0 5px;color:#111827}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.04em;margin:0 0 9px;color:#374151}
.business{font-size:12px;text-align:right;color:#4b5563;max-width:260px;overflow-wrap:anywhere}
.muted{color:#6b7280}
.meta{display:grid;grid-template-columns:1fr 1fr;gap:14px 30px;margin:20px 0 18px}
.meta-block .label,.label{font-size:10px;text-transform:uppercase;letter-spacing:.05em;font-weight:700;color:#6b7280;margin-bottom:3px}
.meta-block{min-width:0;overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse;table-layout:fixed}
th,td{padding:8px 7px;border-bottom:1px solid #e5e7eb;vertical-align:top;overflow-wrap:anywhere}
th{font-size:10px;text-transform:uppercase;letter-spacing:.04em;color:#4b5563;text-align:left;border-bottom:2px solid #111827}
th:nth-child(1),td:nth-child(1){width:46%}
th:nth-child(2),td:nth-child(2){width:10%}
th:nth-child(3),td:nth-child(3),th:nth-child(4),td:nth-child(4){width:22%}
.qty{text-align:center;white-space:nowrap}.amount{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}.description{white-space:pre-wrap}
.totals{width:330px;max-width:100%;margin:18px 0 0 auto}.totals td{border-bottom:0;padding:5px 7px}.totals .grand td{border-top:2px solid #111827;font-size:14px;font-weight:700;padding-top:8px}
.currency-symbol,.currency-number{display:inline;unicode-bidi:isolate;direction:ltr}.currency-space{display:inline}
.section{margin-top:24px;break-inside:avoid}.notes{margin-top:24px;border-top:1px solid #e5e7eb;padding-top:14px;white-space:pre-wrap;overflow-wrap:anywhere}.notes h2{margin-bottom:6px}
.signature{margin-top:28px;border:1px solid #d1d5db;border-radius:5px;padding:12px;break-inside:avoid}.hash{font-family:"Noto Sans Mono","DejaVu Sans Mono",monospace;font-size:9px;word-break:break-all;margin:3px 0 2px;color:#4b5563}
.footer{margin-top:30px;padding-top:10px;border-top:1px solid #d1d5db;text-align:center;color:#6b7280;font-size:10px}
@media print{a{text-decoration:none;color:inherit}}
</style>
</head>
<body>
<header class="header">
<div>${logoHtml(biz)}<h1>${esc(title)}</h1><div class="muted">${input.kind === 'invoice' ? `Invoice #${esc(d.invoiceNumber || '')}` : `Quote #${esc(d.quoteNumber || '')}`}</div></div>
<div class="business"><strong>${esc(biz.name || 'Business Quotes')}</strong>${contact ? `<br>${contact}` : ''}${biz.taxId ? `<br>${esc(biz.taxId)}` : ''}</div>
</header>
<section class="meta">
<div class="meta-block"><div class="label">Client</div>${esc(d.clientName || 'Not specified')}${d.clientEmail ? `<br><span class="muted">${esc(d.clientEmail)}</span>` : ''}</div>
<div class="meta-block"><div class="label">Issued</div>${esc(fmtDate(issued))}</div>
${input.kind === 'quote' ? `<div class="meta-block"><div class="label">Valid until</div>${esc(fmtDate(validUntil))}</div><div class="meta-block"><div class="label">Status</div>${esc(d.status || 'Draft')}</div>` : `<div class="meta-block"><div class="label">Due</div>${esc(fmtDate(dueAt))}</div><div class="meta-block"><div class="label">Status</div>${esc(d.status || 'Unpaid')}</div>`}
</section>
<table>
<thead><tr><th>Description</th><th class="qty">Qty</th><th class="amount">Unit price</th><th class="amount">Line total</th></tr></thead>
<tbody>${itemRows || `<tr><td colspan="4" class="muted">No line items.</td></tr>`}</tbody>
</table>
<table class="totals">
<tr><td class="muted">Line total</td><td class="amount">${money(line, cur)}</td></tr>
${discountPercent > 0 ? `<tr><td class="muted">Discount (${esc(discountPercent)}%)</td><td class="amount">-${money(discountAmount, cur)}</td></tr>` : ''}
<tr><td class="muted">Subtotal</td><td class="amount">${money(subtotal, cur)}</td></tr>
<tr><td class="muted">Tax (${esc(taxPercent)}%)</td><td class="amount">${money(tax, cur)}</td></tr>
${invoiceBalance}
</table>
${notes ? `<section class="notes"><h2>${input.kind === 'invoice' ? 'Payment instructions' : 'Notes / terms'}</h2><div>${esc(notes)}</div></section>` : ''}
${terms ? `<section class="notes"><h2>Terms</h2><div>${esc(terms)}</div></section>` : ''}
${invoicePayments}
${signature}
<footer class="footer">${esc(biz.name || 'Business Quotes')} - ${new Date().getUTCFullYear()}</footer>
</body></html>`;
}

let active = 0;
const waiters: Array<() => void> = [];
const maxConcurrent = Math.max(1, Math.min(4, Number(process.env.PDF_CONCURRENCY ?? 2) || 2));

async function acquireSlot(): Promise<() => void> {
  if (active >= maxConcurrent) await new Promise<void>((resolve) => waiters.push(resolve));
  active += 1;
  return () => {
    active -= 1;
    waiters.shift()?.();
  };
}

async function chromiumPdf(html: string): Promise<Uint8Array> {
  const release = await acquireSlot();
  const id = randomUUID();
  const dir = join('/tmp', `quote-pdf-${id}`);
  const htmlPath = join(dir, 'document.html');
  const pdfPath = join(dir, 'document.pdf');
  const chromium = process.env.CHROMIUM_PATH || '/usr/bin/chromium';
  try {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    await Bun.write(htmlPath, `\ufeff${html}`);
    const proc = Bun.spawn([
      chromium,
      '--headless=new',
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--disable-extensions',
      '--disable-background-networking',
      '--disable-features=UseDBus',
      '--no-first-run',
      '--no-default-browser-check',
      `--user-data-dir=${join(dir, 'profile')}`,
      '--no-pdf-header-footer',
      '--run-all-compositor-stages-before-draw',
      `--print-to-pdf=${pdfPath}`,
      `file://${htmlPath}`,
    ], { stdout: 'pipe', stderr: 'pipe' });
    const timeout = setTimeout(() => { try { proc.kill(); } catch {} }, 20_000);
    const exitCode = await proc.exited;
    clearTimeout(timeout);
    if (exitCode !== 0) {
      const stderr = await new Response(proc.stderr).text();
      throw new Error(`Chromium PDF generation failed: ${stderr.slice(-2_000)}`);
    }
    return new Uint8Array(await Bun.file(pdfPath).arrayBuffer());
  } finally {
    release();
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

export async function renderQuotePdf(quote: any, business: any): Promise<{ pdf: Uint8Array; filename: string }> {
  const pdf = await chromiumPdf(documentHtml({ kind: 'quote', document: quote, business }));
  return { pdf, filename: `${safeFilename(['Quote', quote.quoteNumber || 'document', quote.title || ''])}.pdf` };
}

export async function renderInvoicePdf(invoice: any, business: any, payments: any[] = []): Promise<{ pdf: Uint8Array; filename: string }> {
  const document = { ...(invoice.data || {}), invoiceNumber: invoice.invoiceNumber, currency: invoice.currency, status: invoice.status, amountMinor: invoice.amountMinor, amountPaidMinor: invoice.amountPaidMinor, dueAt: invoice.dueAt, createdAt: invoice.createdAt };
  const pdf = await chromiumPdf(documentHtml({ kind: 'invoice', document, business, payments }));
  return { pdf, filename: `${safeFilename(['Invoice', invoice.invoiceNumber || 'document', document.title || ''])}.pdf` };
}
