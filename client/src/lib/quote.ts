// Shared business logic — carried over from the prior client app.

export const CURRENCIES = [
  { code: 'ZAR', symbol: 'R' }, { code: 'USD', symbol: '$' }, { code: 'EUR', symbol: '€' }, { code: 'GBP', symbol: '£' },
  { code: 'AUD', symbol: 'A$' }, { code: 'CAD', symbol: 'C$' }, { code: 'JPY', symbol: '¥' }, { code: 'INR', symbol: '₹' },
  { code: 'BRL', symbol: 'R$' }, { code: 'NGN', symbol: '₦' }, { code: 'KES', symbol: 'KSh' }, { code: 'AED', symbol: 'د.إ' },
  { code: 'CNY', symbol: '¥' }, { code: 'CHF', symbol: 'CHF' }, { code: 'NZD', symbol: 'NZ$' }, { code: 'MXN', symbol: 'MX$' },
  { code: 'SEK', symbol: 'kr' }, { code: 'SGD', symbol: 'S$' },
];

export const STATUSES = {
  draft:    { label: 'Draft',    cls: 'badge--draft' },
  sent:     { label: 'Sent',     cls: 'badge--sent' },
  accepted: { label: 'Accepted', cls: 'badge--accepted' },
  declined: { label: 'Declined', cls: 'badge--declined' },
  expired:  { label: 'Expired',  cls: 'badge--expired' },
};

export const UNITS = [
  { value: 'each', label: 'Each' }, { value: 'hour', label: 'Hour' }, { value: 'day', label: 'Day' },
  { value: 'sqm', label: 'Per m²' }, { value: 'sqft', label: 'Per ft²' }, { value: 'kg', label: 'Per kg' },
  { value: 'km', label: 'Per km' }, { value: 'unit', label: 'Unit' }, { value: 'lot', label: 'Lot' },
  { value: 'month', label: 'Month' }, { value: 'project', label: 'Project' }, { value: 'session', label: 'Session' },
  { value: 'page', label: 'Page' }, { value: 'word', label: 'Word' }, { value: 'metre', label: 'Metre' }, { value: 'litre', label: 'Litre' },
];

export const uid = () =>
  (typeof crypto !== 'undefined' && crypto.randomUUID)
    ? crypto.randomUUID()
    : Date.now().toString(36) + Math.random().toString(36).slice(2);

export function money(a: number, c = 'ZAR') {
  try { return new Intl.NumberFormat('en', { style: 'currency', currency: c }).format(a || 0); }
  catch { return (CURRENCIES.find(x => x.code === c)?.symbol || '') + (a || 0).toFixed(2); }
}

export function fmtDate(iso?: string) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en', { day: 'numeric', month: 'short', year: 'numeric' });
}

export function calcTotals(items: any[], tax: number, disc = 0) {
  const line = items.reduce((s, i) => s + i.quantity * i.unitPrice, 0);
  const da = line * (disc / 100), sub = line - da, t = sub * (tax / 100);
  return { line, discountAmt: da, sub, tax: t, total: sub + t };
}

export function newQuote(cur?: string) {
  return {
    quoteNumber: '', title: '', clientId: '', clientName: '', clientUrl: '',
    status: 'draft', currency: cur || 'ZAR', taxPercent: 15, discountPercent: 0,
    validityDays: 30, notes: '', createdAt: new Date().toISOString(),
    items: [{ id: uid(), description: '', quantity: 1, unitPrice: 0, catalogId: '' }],
    signature: '', signedAt: '',
  };
}
export function newClient() { return { name: '', company: '', email: '', phone: '', address: '', website: '', notes: '' }; }
export function newProduct() { return { name: '', category: '', description: '', unitPrice: 0, unit: 'each' }; }

export function validateUrl(url?: string) {
  if (!url || typeof url !== 'string') return '';
  const t = url.trim();
  if (!t) return '';
  try {
    const p = new URL(t.startsWith('http') ? t : 'https://' + t);
    if (!['http:', 'https:'].includes(p.protocol)) return '';
    if (p.hostname.includes('javascript')) return '';
    if (/[<>"'`]/.test(p.href)) return '';
    return p.href;
  } catch { return ''; }
}

export function esc(s: any) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

export async function signQuote(quote: any, owner: any) {
  const payload = JSON.stringify({
    id: quote.id, title: quote.title, items: quote.items,
    total: calcTotals(quote.items, quote.taxPercent, quote.discountPercent).total,
    created: quote.createdAt, owner: owner.name || 'Business Quotes App',
    ownerContact: owner.email || '', timestamp: new Date().toISOString(),
  });
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload));
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function buildPrintHtml(q: any, biz: any) {
  const cur = q.currency;
  const { line, discountAmt, sub, tax, total } = calcTotals(q.items, q.taxPercent, q.discountPercent);
  const itemRows = q.items.map((i: any) =>
    `<tr><td style="padding:8px;border-bottom:1px solid #e5e5e5">${esc(i.description)}</td><td style="padding:8px;border-bottom:1px solid #e5e5e5;text-align:center">${i.quantity}</td><td style="padding:8px;border-bottom:1px solid #e5e5e5;text-align:right">${money(i.unitPrice, cur)}</td><td style="padding:8px;border-bottom:1px solid #e5e5e5;text-align:right">${money(i.quantity * i.unitPrice, cur)}</td></tr>`
  ).join('');
  const sigBlock = q.signature
    ? `<div style="margin-top:24px;padding:12px;background:#f8f8f8;border:1px solid #ddd;border-radius:4px;font-size:11px;color:#666"><strong>INTEGRITY SIGNATURE</strong><br/><code style="font-size:10px;word-break:break-all">${esc(q.signature)}</code><br/>Signed: ${esc(q.signedAt)}</div>` : '';
  const copyright = `<div style="margin-top:32px;padding-top:12px;border-top:1px solid #ddd;font-size:10px;color:#999;text-align:center">© ${new Date().getFullYear()} ${esc(biz.name || 'Business Quotes')}</div>`;
  return `<!DOCTYPE html><html><head><title>${esc(q.title || 'Quote')}</title><style>body{font-family:-apple-system,sans-serif;padding:40px;color:#1a1a1a;max-width:800px;margin:0 auto}h1{font-size:24px;margin-bottom:4px}table{width:100%;border-collapse:collapse;margin:20px 0}th{text-align:left;padding:8px;border-bottom:2px solid #333;font-size:11px;text-transform:uppercase}td{font-size:13px}.totals{margin-left:auto;width:280px}.totals td{padding:4px 8px}.totals .grand{font-weight:700;font-size:16px;border-top:2px solid #333;padding-top:8px}.meta{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:20px 0;font-size:13px}.meta strong{display:block;font-size:10px;text-transform:uppercase;color:#666;margin-bottom:2px}@media print{body{padding:20px}}</style></head><body><h1>${esc(q.title || 'Quote')}</h1>${q.quoteNumber ? `<div style="color:#666;margin-bottom:16px">Quote #${esc(q.quoteNumber)}</div>` : ''}<div class="meta"><div><strong>Client</strong>${esc(q.clientName || '—')}</div><div><strong>Date</strong>${fmtDate(q.createdAt)}</div><div><strong>Valid For</strong>${q.validityDays} days</div><div><strong>Status</strong>${esc((STATUSES as any)[q.status]?.label || 'Draft')}</div></div><table><thead><tr><th>Description</th><th style="text-align:center">Qty</th><th style="text-align:right">Unit Price</th><th style="text-align:right">Total</th></tr></thead><tbody>${itemRows}</tbody></table><table class="totals"><tr><td style="color:#666">Line Total</td><td style="text-align:right">${money(line, cur)}</td></tr>${q.discountPercent > 0 ? `<tr><td style="color:#666">Discount (${q.discountPercent}%)</td><td style="text-align:right;color:#c00">-${money(discountAmt, cur)}</td></tr>` : ''}<tr><td style="color:#666">Subtotal</td><td style="text-align:right">${money(sub, cur)}</td></tr><tr><td style="color:#666">Tax (${q.taxPercent}%)</td><td style="text-align:right">${money(tax, cur)}</td></tr><tr class="grand"><td>Total Due</td><td style="text-align:right">${money(total, cur)}</td></tr></table>${q.notes ? `<div style="margin-top:24px;padding-top:16px;border-top:1px solid #ddd"><strong style="font-size:10px;text-transform:uppercase;color:#666;display:block;margin-bottom:4px">Notes / Terms</strong><div style="font-size:12px;white-space:pre-wrap">${esc(q.notes)}</div></div>` : ''}${sigBlock}${copyright}</body></html>`;
}

function csvCell(v: any) { return `"${String(v ?? '').replace(/"/g, '""')}"`; }
export function buildCsv(q: any, biz: any) {
  const { line, discountAmt, sub, tax, total } = calcTotals(q.items, q.taxPercent, q.discountPercent);
  const rows: (any[] | null)[] = [
    ['Quote', q.title, 'Number', q.quoteNumber, 'Date', fmtDate(q.createdAt)],
    ['Client', q.clientName], q.clientUrl ? ['Client Website', q.clientUrl] : null, [],
    ['Description', 'Qty', 'Unit Price', 'Line Total'],
    ...q.items.map((i: any) => [i.description, i.quantity, i.unitPrice, i.quantity * i.unitPrice]),
    [], ['', '', 'Line Total', line],
    q.discountPercent > 0 ? ['', '', `Discount (${q.discountPercent}%)`, -discountAmt] : null,
    ['', '', 'Subtotal', sub], ['', '', `Tax (${q.taxPercent}%)`, tax], ['', '', 'TOTAL', total],
    [], [`© ${new Date().getFullYear()} ${biz.name || 'Business Quotes'}`],
  ];
  return rows.filter(Boolean).map(r => (r as any[]).map(csvCell).join(',')).join('\n');
}
