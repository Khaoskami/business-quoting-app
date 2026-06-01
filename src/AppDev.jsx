import { useState, useEffect, useCallback, useMemo, useRef } from "react";

/* ==========================================================================
   BUSINESS QUOTING APPLICATION — DEV BUILD (ALL ACCESS)
   Same auth + UI as production, but tier locked to Business (all features).
   Separate storage namespace (bqd_) so dev data does not collide with prod.
   Copyright (c) 2026 Khaos / Khaoskami. All rights reserved.
   ========================================================================== */

// ---------------------------------------------------------------------------
// AUTH ENGINE — PBKDF2 + AES-256-GCM
// ---------------------------------------------------------------------------

const AUTH = {
  PREFIX: "bqd_",
  SALT_KEY: "bqd_auth_salt",
  HASH_KEY: "bqd_auth_hash",
  LOCKOUT_KEY: "bqd_auth_lockout",
  PBKDF2_ITERATIONS: 600_000,
  KEY_LENGTH: 256,
  IV_LENGTH: 12,
  LOCK_TIMEOUT_MS: 15 * 60 * 1000,

  generateSalt() {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    return btoa(String.fromCharCode(...salt));
  },

  async deriveKey(password, saltB64) {
    const encoder = new TextEncoder();
    const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
    const baseKey = await crypto.subtle.importKey(
      "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: this.PBKDF2_ITERATIONS, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: this.KEY_LENGTH },
      false,
      ["encrypt", "decrypt"]
    );
  },

  async createVerifyHash(password, saltB64) {
    const encoder = new TextEncoder();
    const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
    const purposeSalt = new Uint8Array([...salt, ...encoder.encode("verify")]);
    const baseKey = await crypto.subtle.importKey(
      "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: purposeSalt, iterations: this.PBKDF2_ITERATIONS, hash: "SHA-256" },
      baseKey, 256
    );
    return btoa(String.fromCharCode(...new Uint8Array(bits)));
  },

  async encrypt(key, data) {
    const iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));
    const encoded = new TextEncoder().encode(JSON.stringify(data));
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
    return JSON.stringify({
      iv: btoa(String.fromCharCode(...iv)),
      d: btoa(String.fromCharCode(...new Uint8Array(cipher))),
    });
  },

  async decrypt(key, encStr) {
    try {
      const { iv, d } = JSON.parse(encStr);
      const ivArr = Uint8Array.from(atob(iv), c => c.charCodeAt(0));
      const dataArr = Uint8Array.from(atob(d), c => c.charCodeAt(0));
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivArr }, key, dataArr);
      return JSON.parse(new TextDecoder().decode(plain));
    } catch {
      return null;
    }
  },

  isSetUp() {
    return localStorage.getItem(this.SALT_KEY) !== null && localStorage.getItem(this.HASH_KEY) !== null;
  },

  async setup(password) {
    const salt = this.generateSalt();
    const hash = await this.createVerifyHash(password, salt);
    const key = await this.deriveKey(password, salt);
    localStorage.setItem(this.SALT_KEY, salt);
    localStorage.setItem(this.HASH_KEY, hash);
    return key;
  },

  async login(password) {
    const salt = localStorage.getItem(this.SALT_KEY);
    const storedHash = localStorage.getItem(this.HASH_KEY);
    if (!salt || !storedHash) return null;
    const hash = await this.createVerifyHash(password, salt);
    if (hash !== storedHash) return null;
    return this.deriveKey(password, salt);
  },

  async changePassword(oldKey, newPassword) {
    const salt = this.generateSalt();
    const hash = await this.createVerifyHash(newPassword, salt);
    const newKey = await this.deriveKey(newPassword, salt);
    const dataKeys = Object.keys(localStorage).filter(
      k => k.startsWith(this.PREFIX) && k !== this.SALT_KEY && k !== this.HASH_KEY && k !== this.LOCKOUT_KEY
    );
    for (const k of dataKeys) {
      const raw = localStorage.getItem(k);
      if (!raw) continue;
      const decrypted = await this.decrypt(oldKey, raw);
      if (decrypted === null) continue;
      const reEncrypted = await this.encrypt(newKey, decrypted);
      localStorage.setItem(k, reEncrypted);
    }
    localStorage.setItem(this.SALT_KEY, salt);
    localStorage.setItem(this.HASH_KEY, hash);
    return newKey;
  },

  destroyAll() {
    Object.keys(localStorage)
      .filter(k => k.startsWith(this.PREFIX) || k === this.SALT_KEY || k === this.HASH_KEY)
      .forEach(k => localStorage.removeItem(k));
    sessionStorage.removeItem(this.LOCKOUT_KEY);
  },
};

// ---------------------------------------------------------------------------
// LICENSE KEY SYSTEM
// ---------------------------------------------------------------------------

function verifyLicenseKey(key) {
  const parts = String(key || "").trim().toUpperCase().split("-");
  if (parts.length !== 4 || parts[0] !== "BQ") return null;
  const [, tier, timestamp, checksum] = parts;
  if (!["PRO", "BUSINESS"].includes(tier)) return null;
  const body = `BQ${tier}${timestamp}`;
  const sum = body.split("").reduce((a, c) => a + c.charCodeAt(0), 0);
  const expected = sum.toString(36).toUpperCase().slice(-6).padStart(6, "0");
  if (checksum !== expected) return null;
  return tier.toLowerCase();
}

// ---------------------------------------------------------------------------
// URL VALIDATION + HTML ESCAPE
// ---------------------------------------------------------------------------

function validateUrl(url) {
  if (!url || typeof url !== "string") return "";
  const t = url.trim();
  if (!t) return "";
  try {
    const p = new URL(t.startsWith("http") ? t : "https://" + t);
    if (!["http:", "https:"].includes(p.protocol) || p.hostname.includes("javascript") || /[<>"'`]/.test(p.href)) return "";
    return p.href;
  } catch { return ""; }
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// ---------------------------------------------------------------------------
// SIGNATURES + STORE HOOK
// ---------------------------------------------------------------------------

async function signQuote(quote, owner) {
  const payload = JSON.stringify({
    id: quote.id, title: quote.title, items: quote.items,
    total: calcTotals(quote.items, quote.taxPercent, quote.discountPercent).total,
    created: quote.createdAt, owner: owner.name || "Business Quotes App",
    ownerContact: owner.email || "",
    copyright: `© ${new Date().getFullYear()} ${owner.name || "Khaoskami"}. All rights reserved.`,
    timestamp: new Date().toISOString(),
  });
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload));
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function useStore(key, fallback, cryptoKey) {
  const [data, setData] = useState(fallback);
  const [ok, setOk] = useState(false);
  const fk = AUTH.PREFIX + key;

  useEffect(() => {
    if (!cryptoKey) return;
    let stop = false;
    (async () => {
      try {
        const raw = localStorage.getItem(fk);
        if (raw) {
          const d = await AUTH.decrypt(cryptoKey, raw);
          if (!stop && d !== null) setData(d);
        }
      } catch {}
      if (!stop) setOk(true);
    })();
    return () => { stop = true; };
  }, [fk, cryptoKey]);

  const save = useCallback(async (next) => {
    if (!cryptoKey) return;
    setData(next);
    try {
      const enc = await AUTH.encrypt(cryptoKey, next);
      localStorage.setItem(fk, enc);
    } catch (e) {
      if (e?.name === "QuotaExceededError" || e?.code === 22) {
        window.dispatchEvent(new CustomEvent("bqd:storage-full"));
      }
    }
  }, [fk, cryptoKey]);

  return [data, save, ok];
}

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------

const uid = () => crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2);

const CURRENCIES = [
  { code: "ZAR", symbol: "R" }, { code: "USD", symbol: "$" }, { code: "EUR", symbol: "€" }, { code: "GBP", symbol: "£" },
  { code: "AUD", symbol: "A$" }, { code: "CAD", symbol: "C$" }, { code: "JPY", symbol: "¥" }, { code: "INR", symbol: "₹" },
  { code: "BRL", symbol: "R$" }, { code: "NGN", symbol: "₦" }, { code: "KES", symbol: "KSh" }, { code: "AED", symbol: "د.إ" },
  { code: "CNY", symbol: "¥" }, { code: "CHF", symbol: "CHF" }, { code: "NZD", symbol: "NZ$" }, { code: "MXN", symbol: "MX$" },
  { code: "SEK", symbol: "kr" }, { code: "SGD", symbol: "S$" },
];

function money(a, c = "ZAR") {
  try { return new Intl.NumberFormat("en", { style: "currency", currency: c }).format(a || 0); }
  catch { return (CURRENCIES.find(x => x.code === c)?.symbol || "") + (a || 0).toFixed(2); }
}
function fmtDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en", { day: "numeric", month: "short", year: "numeric" });
}

function calcTotals(items, tax, disc = 0) {
  const line = items.reduce((s, i) => s + i.quantity * i.unitPrice, 0);
  const da = line * (disc / 100), sub = line - da, t = sub * (tax / 100);
  return { line, discountAmt: da, sub, tax: t, total: sub + t };
}

const STATUSES = {
  draft:    { label: "Draft",    cls: "badge--draft" },
  sent:     { label: "Sent",     cls: "badge--sent" },
  accepted: { label: "Accepted", cls: "badge--accepted" },
  declined: { label: "Declined", cls: "badge--declined" },
  expired:  { label: "Expired",  cls: "badge--expired" },
};

const TIERS = {
  free:     { name: "Free",     quotesPerMonth: 3,        maxClients: 5,        maxCatalog: 10,       features: { discount: false, print: false, csv: true, signature: false, clientUrl: false, duplicate: false } },
  pro:      { name: "Pro",      price: "$9.99/mo",  quotesPerMonth: 50,       maxClients: 999,      maxCatalog: 999,      features: { discount: true,  print: true,  csv: true, signature: true,  clientUrl: true,  duplicate: true } },
  business: { name: "Business", price: "$24.99/mo", quotesPerMonth: Infinity, maxClients: Infinity, maxCatalog: Infinity, features: { discount: true,  print: true,  csv: true, signature: true,  clientUrl: true,  duplicate: true } },
};

function getMonthKey() { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`; }
function quotesThisMonth(quotes) { const mk = getMonthKey(); return quotes.filter(q => q.createdAt && q.createdAt.startsWith(mk)).length; }

function newQuote(cur) {
  return { id: uid(), quoteNumber: "", title: "", clientId: "", clientName: "", clientUrl: "", status: "draft",
    currency: cur || "ZAR", taxPercent: 15, discountPercent: 0, validityDays: 30, notes: "",
    createdAt: new Date().toISOString(),
    items: [{ id: uid(), description: "", quantity: 1, unitPrice: 0, catalogId: "" }],
    signature: "", signedAt: "" };
}
function newClient() { return { id: "", name: "", company: "", email: "", phone: "", address: "", website: "", notes: "" }; }
function newProduct() { return { id: "", name: "", category: "", description: "", unitPrice: 0, unit: "each" }; }

const PAYMENT_URL = "https://your-payment-link.com";

// ---------------------------------------------------------------------------
// ICONS
// ---------------------------------------------------------------------------

const Icon = {
  dashboard: () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>,
  quotes: () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="14 3 14 9 20 9"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="13" y2="17"/></svg>,
  clients: () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>,
  catalog: () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>,
  settings: () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>,
  lock: () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
  plus: () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>,
  back: () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>,
  emptyDoc: () => <svg width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></svg>,
  emptyUsers: () => <svg width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg>,
  emptyBox: () => <svg width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>,
};

// ---------------------------------------------------------------------------
// PRINT + CSV
// ---------------------------------------------------------------------------

function buildPrintHtml(q, biz) {
  const cur = q.currency;
  const { line, discountAmt, sub, tax, total } = calcTotals(q.items, q.taxPercent, q.discountPercent);
  const itemRows = q.items.map(i => `<tr><td style="padding:8px;border-bottom:1px solid #e5e5e5">${esc(i.description)}</td><td style="padding:8px;border-bottom:1px solid #e5e5e5;text-align:center">${i.quantity}</td><td style="padding:8px;border-bottom:1px solid #e5e5e5;text-align:right">${money(i.unitPrice, cur)}</td><td style="padding:8px;border-bottom:1px solid #e5e5e5;text-align:right">${money(i.quantity * i.unitPrice, cur)}</td></tr>`).join("");
  const sigBlock = q.signature ? `<div style="margin-top:24px;padding:12px;background:#f8f8f8;border:1px solid #ddd;border-radius:4px;font-size:11px;color:#666"><strong>INTEGRITY SIGNATURE</strong><br/><code style="font-size:10px;word-break:break-all">${esc(q.signature)}</code><br/>Signed: ${esc(q.signedAt)}<br/>Any modification invalidates this hash.</div>` : "";
  const copyright = `<div style="margin-top:32px;padding-top:12px;border-top:1px solid #ddd;font-size:10px;color:#999;text-align:center">© ${new Date().getFullYear()} ${esc(biz.name || "Khaoskami")} · Business Quotes App</div>`;
  const clientUrlLine = q.clientUrl ? `<div><strong>Website</strong><a href="${esc(q.clientUrl)}" style="color:#3b6b8a;text-decoration:none"> ${esc(q.clientUrl)}</a></div>` : "";
  return `<!DOCTYPE html><html><head><title>${esc(q.title || "Quote")}</title><style>body{font-family:-apple-system,sans-serif;padding:40px;color:#1a1a1a;max-width:800px;margin:0 auto}h1{font-size:24px;margin-bottom:4px}table{width:100%;border-collapse:collapse;margin:20px 0}th{text-align:left;padding:8px;border-bottom:2px solid #333;font-size:11px;text-transform:uppercase;letter-spacing:0.05em}td{font-size:13px}.totals{margin-left:auto;width:280px}.totals td{padding:4px 8px}.totals .grand{font-weight:700;font-size:16px;border-top:2px solid #333;padding-top:8px}.meta{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:20px 0;font-size:13px}.meta strong{display:block;font-size:10px;text-transform:uppercase;color:#666;margin-bottom:2px}@media print{body{padding:20px}}</style></head><body><h1>${esc(q.title || "Quote")}</h1>${q.quoteNumber ? `<div style="color:#666;margin-bottom:16px">Quote #${esc(q.quoteNumber)}</div>` : ""}<div class="meta"><div><strong>Client</strong>${esc(q.clientName || "—")}</div><div><strong>Date</strong>${fmtDate(q.createdAt)}</div>${clientUrlLine}<div><strong>Valid For</strong>${q.validityDays} days</div><div><strong>Status</strong>${(STATUSES[q.status] || STATUSES.draft).label}</div></div><table><thead><tr><th>Description</th><th style="text-align:center">Qty</th><th style="text-align:right">Unit Price</th><th style="text-align:right">Total</th></tr></thead><tbody>${itemRows}</tbody></table><table class="totals"><tr><td style="color:#666">Line Total</td><td style="text-align:right">${money(line, cur)}</td></tr>${q.discountPercent > 0 ? `<tr><td style="color:#666">Discount (${q.discountPercent}%)</td><td style="text-align:right;color:#c00">-${money(discountAmt, cur)}</td></tr>` : ""}<tr><td style="color:#666">Subtotal</td><td style="text-align:right">${money(sub, cur)}</td></tr><tr><td style="color:#666">Tax (${q.taxPercent}%)</td><td style="text-align:right">${money(tax, cur)}</td></tr><tr class="grand"><td>Total Due</td><td style="text-align:right">${money(total, cur)}</td></tr></table>${q.notes ? `<div style="margin-top:24px;padding-top:16px;border-top:1px solid #ddd"><strong style="font-size:10px;text-transform:uppercase;color:#666;display:block;margin-bottom:4px">Notes / Terms</strong><div style="font-size:12px;white-space:pre-wrap">${esc(q.notes)}</div></div>` : ""}${sigBlock}${copyright}</body></html>`;
}

function buildCsvRows(q, biz) {
  const { line, discountAmt, sub, tax, total } = calcTotals(q.items, q.taxPercent, q.discountPercent);
  return [
    ["GENERATED BY", "Business Quotes App"],
    [`© ${new Date().getFullYear()} ${biz.name || "Khaoskami"}`, "All rights reserved."],
    q.signature ? ["INTEGRITY SIGNATURE", q.signature] : null,
    q.signature ? ["SIGNED AT", q.signedAt] : null,
    [], ["Quote", q.title, "Number", q.quoteNumber, "Date", fmtDate(q.createdAt)],
    ["Client", q.clientName], q.clientUrl ? ["Client Website", q.clientUrl] : null, [],
    ["Description", "Qty", "Unit Price", "Line Total"],
    ...q.items.map(i => [i.description, i.quantity, i.unitPrice, i.quantity * i.unitPrice]),
    [], ["", "", "Line Total", line],
    q.discountPercent > 0 ? ["", "", `Discount (${q.discountPercent}%)`, -discountAmt] : null,
    ["", "", "Subtotal", sub], ["", "", `Tax (${q.taxPercent}%)`, tax], ["", "", "TOTAL", total],
  ].filter(Boolean);
}

function csvCell(v) { return `"${String(v ?? "").replace(/"/g, '""')}"`; }

// ---------------------------------------------------------------------------
// SHARED COMPONENTS
// ---------------------------------------------------------------------------

function Badge({ status }) {
  const s = STATUSES[status] || STATUSES.draft;
  return <span className={`badge ${s.cls}`}>{s.label}</span>;
}

function TierBadge({ tier }) {
  const t = TIERS[tier];
  const cls = tier === "pro" ? "tier-badge--pro" : tier === "business" ? "tier-badge--business" : "";
  return <span className={`tier-badge ${cls}`}>{t.name}</span>;
}

function Field({ label, value, onChange, placeholder, type = "text", span, min, max, step, id }) {
  const inputId = id || `f-${label?.replace(/\s+/g, "-").toLowerCase()}`;
  return (
    <div className={`field-group ${span ? "field-group--span" : ""}`}>
      <label htmlFor={inputId} className="field-label">{label}</label>
      <input id={inputId} type={type} value={value} onChange={e => onChange(e.target.value)}
             placeholder={placeholder} min={min} max={max} step={step} className="field-input" />
    </div>
  );
}

function Sel({ label, value, onChange, options, span }) {
  const inputId = `s-${label?.replace(/\s+/g, "-").toLowerCase()}`;
  return (
    <div className={`field-group ${span ? "field-group--span" : ""}`}>
      <label htmlFor={inputId} className="field-label">{label}</label>
      <select id={inputId} value={value} onChange={e => onChange(e.target.value)} className="field-select">
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </div>
  );
}

function ConfirmBtn({ label, confirmLabel, onConfirm, className = "btn btn--danger btn--sm" }) {
  const [armed, setArmed] = useState(false);
  useEffect(() => { if (!armed) return; const t = setTimeout(() => setArmed(false), 3000); return () => clearTimeout(t); }, [armed]);
  return armed
    ? <button onClick={onConfirm} className={className} style={{ fontWeight: 700 }}>{confirmLabel || "Confirm?"}</button>
    : <button onClick={() => setArmed(true)} className={className}>{label}</button>;
}

function UsageMeter({ current, max, label }) {
  const isInf = max === Infinity;
  const pct = isInf ? 0 : Math.min(100, (current / max) * 100);
  const over = !isInf && current >= max;
  const cls = over ? "meter-fill--over" : pct > 80 ? "meter-fill--warn" : "";
  return (
    <div className="meter">
      <div className="meter-head">
        <span>{label}</span>
        <span style={{ color: over ? "var(--danger)" : undefined, fontWeight: 500 }}>
          {current} / {isInf ? "∞" : max}
        </span>
      </div>
      <div className="meter-track">
        <div className={`meter-fill ${cls}`} style={{ width: isInf ? "0%" : `${pct}%` }} />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// LOCK SCREEN — handles both setup and login
// ---------------------------------------------------------------------------

function LockScreen({ onUnlock }) {
  const isSetup = !AUTH.isSetUp();
  const [mode, setMode] = useState(isSetup ? "setup" : "login");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  const initialLockout = (() => {
    try {
      const raw = sessionStorage.getItem(AUTH.LOCKOUT_KEY);
      if (!raw) return { attempts: 0, lockedUntil: null };
      const p = JSON.parse(raw);
      return { attempts: p.attempts || 0, lockedUntil: p.lockedUntil || null };
    } catch { return { attempts: 0, lockedUntil: null }; }
  })();
  const [attempts, setAttempts] = useState(initialLockout.attempts);
  const [lockedUntil, setLockedUntil] = useState(initialLockout.lockedUntil);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    if (!lockedUntil || lockedUntil <= Date.now()) return;
    const id = setInterval(() => {
      const t = Date.now();
      setNow(t);
      if (t >= lockedUntil) {
        setLockedUntil(null);
        setAttempts(0);
        sessionStorage.removeItem(AUTH.LOCKOUT_KEY);
        clearInterval(id);
      }
    }, 1000);
    return () => clearInterval(id);
  }, [lockedUntil]);

  const isLocked = lockedUntil && lockedUntil > now;
  const remaining = isLocked ? Math.ceil((lockedUntil - now) / 1000) : 0;

  function persistLockout(a, lu) {
    sessionStorage.setItem(AUTH.LOCKOUT_KEY, JSON.stringify({ attempts: a, lockedUntil: lu }));
  }

  async function handleSetup() {
    setErr("");
    if (pw.length < 8) { setErr("Minimum 8 characters."); return; }
    if (pw !== pw2) { setErr("Passwords do not match."); return; }
    if (!/[A-Z]/.test(pw) || !/[0-9]/.test(pw)) { setErr("Must include at least one uppercase letter and one number."); return; }
    setLoading(true);
    try {
      const key = await AUTH.setup(pw);
      onUnlock(key);
    } catch {
      setErr("Setup failed. Try again.");
      setLoading(false);
    }
  }

  async function handleLogin() {
    setErr("");
    if (isLocked) return;
    setLoading(true);
    try {
      const key = await AUTH.login(pw);
      if (!key) {
        const newAttempts = attempts + 1;
        const newLock = newAttempts >= 5 ? Date.now() + 30_000 : null;
        setAttempts(newAttempts);
        setLockedUntil(newLock);
        persistLockout(newAttempts, newLock);
        setErr(newLock ? "Too many attempts. Locked for 30 seconds." : `Wrong password. ${5 - newAttempts} attempts remaining.`);
        setPw("");
        setLoading(false);
        return;
      }
      sessionStorage.removeItem(AUTH.LOCKOUT_KEY);
      onUnlock(key);
    } catch {
      setErr("Login failed.");
      setLoading(false);
    }
  }

  const submit = mode === "setup" ? handleSetup : handleLogin;

  return (
    <div className="lock-screen">
      <div className="lock-card" role="dialog" aria-labelledby="lock-title">
        <div className="lock-logo">BQ</div>
        <h1 id="lock-title" className="lock-title">Business Quotes</h1>
        <p className="lock-subtitle">
          {mode === "setup"
            ? "Create a master password. This encrypts all your data."
            : "Enter your master password to unlock."}
        </p>

        {isSetup ? null : (
          <div className="lock-tabs" role="tablist">
            <button className={`lock-tab ${mode === "login" ? "active" : ""}`} role="tab"
                    aria-selected={mode === "login"} onClick={() => { setMode("login"); setErr(""); }}>Unlock</button>
            <button className="lock-tab" role="tab" aria-selected="false"
                    onClick={() => {
                      if (confirm("This will permanently delete ALL data and reset your password. Continue?")) {
                        AUTH.destroyAll(); window.location.reload();
                      }
                    }}>Reset</button>
          </div>
        )}

        <div className="field-group" style={{ marginBottom: 12 }}>
          <label htmlFor="pw" className="field-label">{mode === "setup" ? "New Password" : "Master Password"}</label>
          <input id="pw" type="password" value={pw} onChange={e => setPw(e.target.value)}
                 disabled={loading || isLocked} autoFocus className="field-input"
                 onKeyDown={e => e.key === "Enter" && submit()}
                 placeholder={mode === "setup" ? "Minimum 8 characters" : "Enter password"} />
        </div>

        {mode === "setup" && (
          <>
            <div className="field-group" style={{ marginBottom: 12 }}>
              <label htmlFor="pw2" className="field-label">Confirm Password</label>
              <input id="pw2" type="password" value={pw2} onChange={e => setPw2(e.target.value)}
                     disabled={loading} className="field-input"
                     onKeyDown={e => e.key === "Enter" && submit()} placeholder="Re-enter password" />
            </div>
            <p className="field-hint" style={{ marginBottom: 12 }}>
              Requires 8+ characters, one uppercase letter, one number. If forgotten, your data cannot be recovered.
            </p>
          </>
        )}

        {err && <div role="alert" className="field-error" style={{ marginBottom: 12 }}>{err}</div>}
        {isLocked && <div role="alert" className="field-error" style={{ marginBottom: 12 }}>Locked for {remaining}s.</div>}

        <button onClick={submit} disabled={loading || isLocked}
                className={`btn btn--primary btn--full btn--lg ${loading ? "btn--loading" : ""}`}>
          {mode === "setup" ? "Create Password & Enter" : "Unlock"}
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// SIDEBAR
// ---------------------------------------------------------------------------

const NAV = [
  { id: "dashboard", label: "Dashboard", icon: Icon.dashboard },
  { id: "quotes",    label: "Quotes",    icon: Icon.quotes },
  { id: "clients",   label: "Clients",   icon: Icon.clients },
  { id: "catalog",   label: "Catalog",   icon: Icon.catalog },
];

function Sidebar({ page, setPage, biz, tier, onLock }) {
  return (
    <aside className="sidebar" aria-label="Primary navigation">
      <div className="sidebar-brand">
        <div className="brand-mark" aria-hidden>BQ</div>
        <div style={{ minWidth: 0 }}>
          <div className="brand-name">{biz.name || "Business Quotes"}</div>
          <div className="brand-sub">{biz.email || "Set up in Settings"}</div>
        </div>
      </div>
      <nav className="sidebar-nav">
        {NAV.map(n => {
          const I = n.icon;
          const active = page === n.id || (page === "editor" && n.id === "quotes");
          return (
            <button key={n.id} className={`nav-item ${active ? "active" : ""}`}
                    onClick={() => setPage(n.id)} aria-current={active ? "page" : undefined}>
              <I /><span>{n.label}</span>
            </button>
          );
        })}
      </nav>
      <div className="sidebar-footer">
        <TierBadge tier={tier} />
        <button className={`nav-item ${page === "settings" ? "active" : ""}`} onClick={() => setPage("settings")}>
          <Icon.settings /><span>Settings</span>
        </button>
        <button className="nav-item nav-item--danger" onClick={onLock} aria-label="Lock app">
          <Icon.lock /><span>Lock</span>
        </button>
      </div>
    </aside>
  );
}

function BottomNav({ page, setPage }) {
  return (
    <nav className="bottom-nav" aria-label="Primary navigation">
      <div className="bottom-nav-inner">
        {NAV.map(n => {
          const I = n.icon;
          const active = page === n.id || (page === "editor" && n.id === "quotes");
          return (
            <button key={n.id} className={`bottom-nav-item ${active ? "active" : ""}`}
                    onClick={() => setPage(n.id)} aria-label={n.label}>
              <I /><span>{n.label}</span>
            </button>
          );
        })}
      </div>
    </nav>
  );
}

function MobileBar({ biz, onSettings, onLock }) {
  return (
    <header className="mobile-bar">
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <div className="brand-mark" aria-hidden>BQ</div>
        <span className="brand-name">{biz.name || "Business Quotes"}</span>
      </div>
      <div className="mobile-bar-actions">
        <button onClick={onSettings} aria-label="Settings" className="btn btn--ghost btn--sm" style={{ padding: 8 }}>
          <Icon.settings />
        </button>
        <button onClick={onLock} aria-label="Lock" className="btn btn--ghost btn--sm" style={{ padding: 8 }}>
          <Icon.lock />
        </button>
      </div>
    </header>
  );
}

// ---------------------------------------------------------------------------
// DASHBOARD
// ---------------------------------------------------------------------------

function Dashboard({ quotes, currency, tier, onNew, onEdit }) {
  const accepted = quotes.filter(q => q.status === "accepted");
  const revenue = accepted.reduce((s, q) => s + calcTotals(q.items, q.taxPercent, q.discountPercent).total, 0);
  const pending = quotes.filter(q => q.status === "sent").length;
  const mu = quotesThisMonth(quotes), mMax = TIERS[tier].quotesPerMonth;
  const atLimit = mMax !== Infinity && mu >= mMax;

  const recent = [...quotes].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 10);

  const stats = [
    { label: "Total Quotes", value: quotes.length, cls: "" },
    { label: "Pending",      value: pending,       cls: "stat-card--warning" },
    { label: "Accepted",     value: accepted.length, cls: "stat-card--success" },
    { label: "Total Value",  value: money(revenue, currency), cls: "stat-card--accent" },
  ];

  return (
    <div className="page-enter">
      <div className="page-header">
        <h1 className="page-title">Dashboard</h1>
        <button onClick={onNew} disabled={atLimit} className="btn btn--primary">
          <Icon.plus /> New Quote
        </button>
      </div>

      {atLimit && (
        <div className="upgrade-banner">
          <div>
            <div className="upgrade-banner-title">Monthly limit reached</div>
            <div className="upgrade-banner-sub">You have used all {mMax} quotes this month.</div>
          </div>
          <button onClick={() => window.open(PAYMENT_URL, "_blank")} className="btn btn--primary btn--sm">
            Upgrade to Pro
          </button>
        </div>
      )}

      <div className="stat-grid">
        {stats.map(s => (
          <div key={s.label} className={`stat-card ${s.cls}`}>
            <div className="stat-label">{s.label}</div>
            <div className="stat-value">{s.value}</div>
          </div>
        ))}
      </div>

      <section>
        <div className="page-header">
          <h2 className="section-title" style={{ margin: 0 }}>Recent Quotes</h2>
        </div>
        {quotes.length === 0 ? (
          <div className="empty-state">
            <Icon.emptyDoc />
            <h3>No quotes yet</h3>
            <p>Create your first quote to get started.</p>
            <button className="btn btn--primary" onClick={onNew}><Icon.plus /> New Quote</button>
          </div>
        ) : (
          <div className="list">
            <div className="list-header">
              <span>Quote #</span><span>Title</span><span>Client</span><span>Date</span><span>Value</span><span>Status</span>
            </div>
            {recent.map(q => {
              const { total } = calcTotals(q.items, q.taxPercent, q.discountPercent);
              return (
                <div key={q.id} className="list-row" onClick={() => onEdit(q)}
                     onKeyDown={e => (e.key === "Enter" || e.key === " ") && onEdit(q)}
                     role="button" tabIndex={0}>
                  <span className="num">{q.quoteNumber || "—"}</span>
                  <span className="title">{q.title || "Untitled"}</span>
                  <span className="client">{q.clientName || "—"}</span>
                  <span className="date">{fmtDate(q.createdAt)}</span>
                  <span className="value">{money(total, q.currency)}</span>
                  <span className="status-cell"><Badge status={q.status} /></span>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}

// ---------------------------------------------------------------------------
// QUOTES LIST
// ---------------------------------------------------------------------------

function QuotesList({ quotes, tier, onNew, onEdit }) {
  const [search, setSearch] = useState("");
  const mu = quotesThisMonth(quotes), mMax = TIERS[tier].quotesPerMonth;
  const atLimit = mMax !== Infinity && mu >= mMax;
  const filtered = quotes
    .filter(q => {
      if (!search) return true;
      const t = search.toLowerCase();
      return (q.title || "").toLowerCase().includes(t) ||
             (q.clientName || "").toLowerCase().includes(t) ||
             (q.quoteNumber || "").toLowerCase().includes(t);
    })
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  return (
    <div className="page-enter">
      <div className="page-header">
        <h1 className="page-title">Quotes</h1>
        <button onClick={onNew} disabled={atLimit} className="btn btn--primary">
          <Icon.plus /> New Quote
        </button>
      </div>
      <UsageMeter current={mu} max={mMax} label="Quotes this month" />
      <input value={search} onChange={e => setSearch(e.target.value)}
             placeholder="Search quotes..." className="field-input" style={{ marginBottom: 16 }} />
      {filtered.length === 0 ? (
        <div className="empty-state">
          <Icon.emptyDoc />
          <h3>{quotes.length === 0 ? "No quotes yet" : "No results"}</h3>
          {quotes.length === 0 && <p>Create your first quote to get started.</p>}
          {quotes.length === 0 && <button className="btn btn--primary" onClick={onNew}><Icon.plus /> New Quote</button>}
        </div>
      ) : (
        <div className="list">
          <div className="list-header">
            <span>Quote #</span><span>Title</span><span>Client</span><span>Date</span><span>Value</span><span>Status</span>
          </div>
          {filtered.map(q => {
            const { total } = calcTotals(q.items, q.taxPercent, q.discountPercent);
            return (
              <div key={q.id} className="list-row" onClick={() => onEdit(q)} role="button" tabIndex={0}
                   onKeyDown={e => (e.key === "Enter" || e.key === " ") && onEdit(q)}>
                <span className="num">{q.quoteNumber || "—"}</span>
                <span className="title">{q.title || "Untitled"}{q.signature && <span title="Signed" style={{ marginLeft: 6, color: "var(--success)" }}>✓</span>}</span>
                <span className="client">{q.clientName || "—"}</span>
                <span className="date">{fmtDate(q.createdAt)}</span>
                <span className="value">{money(total, q.currency)}</span>
                <span className="status-cell"><Badge status={q.status} /></span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// EDITOR
// ---------------------------------------------------------------------------

function Editor({ initial, clients, catalog, allQuotes, tier, biz, onSave, onDelete, onBack, notify }) {
  const [q, setQ] = useState({ ...initial });
  const isEx = allQuotes.some(x => x.id === q.id);
  const { line, discountAmt, sub, tax, total } = calcTotals(q.items, q.taxPercent, q.discountPercent);
  const tf = TIERS[tier].features;
  const cats = useMemo(() => [...new Set(catalog.map(p => p.category).filter(Boolean))], [catalog]);
  const [catF, setCatF] = useState("");
  const [showCat, setShowCat] = useState(false);

  function set(f, v) { setQ(p => ({ ...p, [f]: v })); }
  function setI(idx, f, v) {
    setQ(p => {
      const it = [...p.items];
      const value = (f === "quantity" || f === "unitPrice") ? Math.max(0, Number(v) || 0) : v;
      it[idx] = { ...it[idx], [f]: value };
      return { ...p, items: it };
    });
  }
  function addBlank() { setQ(p => ({ ...p, items: [...p.items, { id: uid(), description: "", quantity: 1, unitPrice: 0, catalogId: "" }] })); }
  function addCat(pr) { setQ(p => ({ ...p, items: [...p.items, { id: uid(), description: pr.name + (pr.description ? ` — ${pr.description}` : ""), quantity: 1, unitPrice: pr.unitPrice, catalogId: pr.id }] })); setShowCat(false); }
  function rmI(idx) { if (q.items.length > 1) setQ(p => ({ ...p, items: p.items.filter((_, i) => i !== idx) })); }

  function handlePrint() {
    const html = buildPrintHtml(q, biz);
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const w = window.open(url, "_blank");
    if (w) w.addEventListener("load", () => URL.revokeObjectURL(url), { once: true });
  }

  function handleCSV() {
    const csv = buildCsvRows(q, biz).map(r => r.map(csvCell).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement("a"), { href: url, download: `${q.quoteNumber || q.title || "quote"}.csv` });
    a.click(); URL.revokeObjectURL(url); notify("CSV exported.");
  }

  const fc = catalog.filter(p => !catF || p.category === catF);

  return (
    <div className="page-enter">
      <div className="page-header">
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <button onClick={onBack} className="btn btn--ghost btn--sm" aria-label="Back"><Icon.back /></button>
          <h1 className="page-title">{isEx ? "Edit Quote" : "New Quote"}</h1>
        </div>
      </div>

      <div className="editor-shell">
        <div className="editor-main">
          <div className="card">
            <div className="form-grid">
              <Field label="Quote Title" value={q.title} onChange={v => set("title", v)} placeholder="e.g. Roof Repair" span />
              <Field label="Quote Number" value={q.quoteNumber} onChange={v => set("quoteNumber", v)} placeholder="QT-001" />
              <div className="field-group">
                <label className="field-label" htmlFor="client-sel">Client</label>
                <select id="client-sel" value={q.clientId} className="field-select"
                        onChange={e => {
                          const c = clients.find(x => x.id === e.target.value);
                          set("clientId", e.target.value);
                          set("clientName", c?.name || "");
                          set("clientUrl", c?.website || "");
                        }}>
                  <option value="">— Select —</option>
                  {clients.map(c => <option key={c.id} value={c.id}>{c.name}{c.company ? ` (${c.company})` : ""}</option>)}
                </select>
              </div>
              <Sel label="Status" value={q.status} onChange={v => set("status", v)}
                   options={Object.entries(STATUSES).map(([k, v]) => ({ value: k, label: v.label }))} />
              <Sel label="Currency" value={q.currency} onChange={v => set("currency", v)}
                   options={CURRENCIES.map(c => ({ value: c.code, label: `${c.code} (${c.symbol})` }))} />
              <Field label="Tax %" type="number" value={q.taxPercent}
                     onChange={v => set("taxPercent", Math.min(100, Math.max(0, Number(v) || 0)))} min={0} max={100} />
              {tf.discount
                ? <Field label="Discount %" type="number" value={q.discountPercent}
                         onChange={v => set("discountPercent", Math.min(100, Math.max(0, Number(v) || 0)))} min={0} max={100} />
                : <div className="field-group"><label className="field-label">Discount %</label><div className="field-hint" style={{ padding: "10px 0" }}>Pro feature</div></div>}
              <Field label="Valid (days)" type="number" value={q.validityDays}
                     onChange={v => set("validityDays", Math.max(1, Number(v) || 1))} min={1} />
              {tf.clientUrl
                ? <Field label="Client Website" value={q.clientUrl} onChange={v => set("clientUrl", v)} placeholder="https://clientsite.com" span />
                : <div className="field-group field-group--span"><label className="field-label">Client Website</label><div className="field-hint" style={{ padding: "10px 0" }}>Pro feature</div></div>}
            </div>
          </div>

          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span className="field-label">Line Items</span>
              <div style={{ display: "flex", gap: 6 }}>
                {catalog.length > 0 && <button onClick={() => setShowCat(!showCat)} className="btn btn--ghost btn--sm">
                  {showCat ? "Close" : "From catalog"}
                </button>}
                <button onClick={addBlank} className="btn btn--secondary btn--sm"><Icon.plus /> Item</button>
              </div>
            </div>

            {showCat && (
              <div className="catalog-drawer" style={{ marginBottom: 10 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                  <span className="field-label">Catalog</span>
                  <select value={catF} onChange={e => setCatF(e.target.value)} className="field-select" style={{ width: "auto", minHeight: 30, padding: "4px 8px", fontSize: 12 }}>
                    <option value="">All</option>
                    {cats.map(c => <option key={c} value={c}>{c}</option>)}
                  </select>
                </div>
                {fc.length === 0
                  ? <div className="field-hint" style={{ padding: 8 }}>Empty.</div>
                  : fc.map(p => (
                    <div key={p.id} className="catalog-pick" onClick={() => addCat(p)} role="button" tabIndex={0}
                         onKeyDown={e => (e.key === "Enter" || e.key === " ") && addCat(p)}>
                      <span>{p.name}{p.category && <span style={{ marginLeft: 6, fontSize: 11, color: "var(--text-tertiary)" }}>({p.category})</span>}</span>
                      <span className="price">{money(p.unitPrice, q.currency)}/{p.unit}</span>
                    </div>
                  ))}
              </div>
            )}

            <div className="line-items">
              <div className="line-items-header">
                <span>Description</span><span style={{ textAlign: "center" }}>Qty</span><span>Unit Price</span><span style={{ textAlign: "right" }}>Total</span><span />
              </div>
              {q.items.map((item, idx) => (
                <div key={item.id} className="line-items-row">
                  <input className="li-input" value={item.description} onChange={e => setI(idx, "description", e.target.value)} placeholder="Description" aria-label="Description" />
                  <input className="li-input li-input--num" type="number" min={0} value={item.quantity} onChange={e => setI(idx, "quantity", e.target.value)} aria-label="Quantity" />
                  <input className="li-input li-input--num" type="number" min={0} step={0.01} value={item.unitPrice} onChange={e => setI(idx, "unitPrice", e.target.value)} aria-label="Unit price" />
                  <div className="li-total">{money(item.quantity * item.unitPrice, q.currency)}</div>
                  <button className="li-remove" onClick={() => rmI(idx)} disabled={q.items.length <= 1} aria-label="Remove item">×</button>
                </div>
              ))}
            </div>
          </div>

          <div className="field-group">
            <label className="field-label" htmlFor="notes">Notes / Terms</label>
            <textarea id="notes" className="field-textarea" value={q.notes} onChange={e => set("notes", e.target.value)} rows={4} placeholder="Payment terms, delivery, warranty..." />
          </div>
        </div>

        <aside>
          <div className="totals-card">
            <div className="totals-row"><span>Line Total</span><span className="totals-value">{money(line, q.currency)}</span></div>
            {q.discountPercent > 0 && (
              <div className="totals-row discount"><span>Discount ({q.discountPercent}%)</span><span className="totals-value">-{money(discountAmt, q.currency)}</span></div>
            )}
            <div className="totals-row"><span>Subtotal</span><span className="totals-value">{money(sub, q.currency)}</span></div>
            <div className="totals-row"><span>Tax ({q.taxPercent}%)</span><span className="totals-value">{money(tax, q.currency)}</span></div>
            <div className="totals-row grand"><span>Total</span><span className="totals-value">{money(total, q.currency)}</span></div>

            {q.signature ? (
              <div style={{ background: "var(--success-bg)", border: "1px solid var(--success)", borderRadius: "var(--radius)", padding: 10, marginTop: 4 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--success)", marginBottom: 4 }}>Signed ✓</div>
                <div style={{ fontSize: 10, color: "var(--text-secondary)", fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>{q.signature.slice(0, 32)}…</div>
              </div>
            ) : tf.signature ? (
              <button onClick={async () => { const sig = await signQuote(q, biz); setQ(p => ({ ...p, signature: sig, signedAt: new Date().toISOString() })); notify("Signed."); }}
                      className="btn btn--secondary btn--full">Sign Quote (SHA-256)</button>
            ) : null}

            <div className="action-bar" style={{ marginTop: 4 }}>
              <button onClick={() => onSave({ ...q, clientUrl: validateUrl(q.clientUrl) })} className="btn btn--primary btn--full">Save</button>
            </div>
            <div className="action-bar">
              {tf.print
                ? <button onClick={handlePrint} className="btn btn--secondary">Print / PDF</button>
                : <button disabled className="btn btn--secondary">Print (Pro)</button>}
              <button onClick={handleCSV} className="btn btn--secondary">CSV</button>
              {tf.duplicate && (
                <button onClick={() => { setQ({ ...q, id: uid(), title: q.title + " (copy)", quoteNumber: "", status: "draft", createdAt: new Date().toISOString(), signature: "", signedAt: "" }); notify("Duplicated."); }} className="btn btn--ghost">Duplicate</button>
              )}
            </div>
            {isEx && (
              <ConfirmBtn label="Delete Quote" confirmLabel="Confirm delete?" onConfirm={() => onDelete(q.id)}
                          className="btn btn--danger btn--full" />
            )}
          </div>
        </aside>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// CLIENTS
// ---------------------------------------------------------------------------

function Clients({ clients, tier, onSave, onDelete, notify }) {
  const [form, setForm] = useState(null);
  const [search, setSearch] = useState("");
  const maxC = TIERS[tier].maxClients;
  const tf = TIERS[tier].features;
  const fields = [
    { key: "name", l: "Name *", ph: "Jane Doe" },
    { key: "company", l: "Company", ph: "Acme Pty Ltd" },
    { key: "email", l: "Email", ph: "jane@acme.co" },
    { key: "phone", l: "Phone", ph: "+27 12 345 6789" },
    { key: "website", l: "Website", ph: "https://clientsite.com" },
    { key: "address", l: "Address", ph: "123 Long St, Cape Town", span: true },
    { key: "notes", l: "Notes", ph: "Account terms...", span: true },
  ];
  const filtered = clients.filter(c => {
    if (!search) return true;
    const t = search.toLowerCase();
    return (c.name || "").toLowerCase().includes(t) || (c.company || "").toLowerCase().includes(t);
  });

  return (
    <div className="page-enter">
      <div className="page-header">
        <h1 className="page-title">Clients</h1>
        <button onClick={() => {
          if (maxC !== Infinity && clients.length >= maxC) { notify("Limit reached. Upgrade.", "error"); return; }
          setForm(newClient());
        }} className="btn btn--primary"><Icon.plus /> Add Client</button>
      </div>

      <UsageMeter current={clients.length} max={maxC} label="Clients" />

      {form && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="form-grid">
            {fields.map(f => {
              if (f.key === "website" && !tf.clientUrl) {
                return <div key={f.key} className="field-group"><label className="field-label">Website</label><div className="field-hint" style={{ padding: "10px 0" }}>Pro feature</div></div>;
              }
              return <Field key={f.key} label={f.l} value={form[f.key]}
                            onChange={v => setForm(p => ({ ...p, [f.key]: v }))}
                            placeholder={f.ph} span={f.span} />;
            })}
          </div>
          <div className="action-bar" style={{ marginTop: 16 }}>
            <button onClick={() => {
              if (!form.name.trim()) { notify("Name required.", "error"); return; }
              onSave({ ...form, id: form.id || uid(), website: validateUrl(form.website) });
              setForm(null);
            }} className="btn btn--primary">Save</button>
            <button onClick={() => setForm(null)} className="btn btn--ghost">Cancel</button>
          </div>
        </div>
      )}

      <input value={search} onChange={e => setSearch(e.target.value)}
             placeholder="Search clients..." className="field-input" style={{ marginBottom: 12 }} />

      {filtered.length === 0 ? (
        <div className="empty-state">
          <Icon.emptyUsers />
          <h3>{clients.length === 0 ? "No clients yet" : "No results"}</h3>
          {clients.length === 0 && <p>Add your first client to link them to quotes.</p>}
        </div>
      ) : (
        <div className="simple-list">
          {filtered.map(c => (
            <div key={c.id} className="simple-row">
              <div style={{ minWidth: 0 }}>
                <div className="name">{c.name}{c.company && <span style={{ fontWeight: 400, color: "var(--text-secondary)" }}> — {c.company}</span>}</div>
                <div className="meta">{[c.email, c.phone, c.website].filter(Boolean).join(" · ") || "—"}</div>
              </div>
              <div className="simple-row-actions">
                <button onClick={() => setForm({ ...c })} className="btn btn--ghost btn--sm">Edit</button>
                <ConfirmBtn label="Delete" confirmLabel="Confirm?" onConfirm={() => onDelete(c.id)} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// CATALOG
// ---------------------------------------------------------------------------

const UNITS = [
  { value: "each", label: "Each" }, { value: "hour", label: "Hour" }, { value: "day", label: "Day" },
  { value: "sqm", label: "Per m²" }, { value: "sqft", label: "Per ft²" }, { value: "kg", label: "Per kg" },
  { value: "km", label: "Per km" }, { value: "unit", label: "Unit" }, { value: "lot", label: "Lot" },
  { value: "month", label: "Month" }, { value: "project", label: "Project" }, { value: "session", label: "Session" },
  { value: "page", label: "Page" }, { value: "word", label: "Word" }, { value: "metre", label: "Metre" }, { value: "litre", label: "Litre" },
];

function Catalog({ catalog, tier, onSave, onDelete, notify }) {
  const [form, setForm] = useState(null);
  const [search, setSearch] = useState("");
  const [fCat, setFCat] = useState("");
  const maxP = TIERS[tier].maxCatalog;
  const categories = useMemo(() => [...new Set(catalog.map(p => p.category).filter(Boolean))].sort(), [catalog]);
  const filtered = catalog.filter(p => {
    const ms = !search || (p.name || "").toLowerCase().includes(search.toLowerCase());
    const mc = !fCat || p.category === fCat;
    return ms && mc;
  });

  return (
    <div className="page-enter">
      <div className="page-header">
        <h1 className="page-title">Catalog</h1>
        <button onClick={() => {
          if (maxP !== Infinity && catalog.length >= maxP) { notify("Limit reached. Upgrade.", "error"); return; }
          setForm(newProduct());
        }} className="btn btn--primary"><Icon.plus /> Add Item</button>
      </div>

      <UsageMeter current={catalog.length} max={maxP} label="Catalog items" />

      {form && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="form-grid">
            <Field label="Name *" value={form.name} onChange={v => setForm(p => ({ ...p, name: v }))} placeholder="Consultation, Logo Design" />
            <Field label="Category" value={form.category} onChange={v => setForm(p => ({ ...p, category: v }))} placeholder="Labour, Materials" />
            <Field label="Description" value={form.description} onChange={v => setForm(p => ({ ...p, description: v }))} placeholder="Detail" span />
            <Field label="Price" type="number" value={form.unitPrice} onChange={v => setForm(p => ({ ...p, unitPrice: v }))} min={0} step={0.01} />
            <Sel label="Unit" value={form.unit} onChange={v => setForm(p => ({ ...p, unit: v }))} options={UNITS} />
          </div>
          <div className="action-bar" style={{ marginTop: 16 }}>
            <button onClick={() => {
              if (!form.name.trim()) { notify("Name required.", "error"); return; }
              onSave({ ...form, id: form.id || uid(), unitPrice: Math.max(0, Number(form.unitPrice) || 0) });
              setForm(null);
            }} className="btn btn--primary">Save</button>
            <button onClick={() => setForm(null)} className="btn btn--ghost">Cancel</button>
          </div>
        </div>
      )}

      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search..." className="field-input" />
        {categories.length > 0 && (
          <select value={fCat} onChange={e => setFCat(e.target.value)} className="field-select" style={{ width: "auto" }}>
            <option value="">All categories</option>
            {categories.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        )}
      </div>

      {filtered.length === 0 ? (
        <div className="empty-state">
          <Icon.emptyBox />
          <h3>{catalog.length === 0 ? "Build your catalog" : "No results"}</h3>
          {catalog.length === 0 && <p>Reusable products and services you can drop into quotes.</p>}
        </div>
      ) : (
        <div className="simple-list">
          {filtered.map(p => (
            <div key={p.id} className="simple-row">
              <div style={{ minWidth: 0 }}>
                <div className="name">{p.name}{p.category && <span className="badge badge--draft" style={{ marginLeft: 8 }}>{p.category}</span>}</div>
                <div className="meta">{p.description || "—"} · {money(p.unitPrice)}/{p.unit}</div>
              </div>
              <div className="simple-row-actions">
                <button onClick={() => setForm({ ...p })} className="btn btn--ghost btn--sm">Edit</button>
                <ConfirmBtn label="Delete" confirmLabel="Confirm?" onConfirm={() => onDelete(p.id)} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// LICENSE MODAL
// ---------------------------------------------------------------------------

function LicenseKeyModal({ tierName, onClose, onActivate }) {
  const [licenseKey, setLicenseKey] = useState("");
  const [error, setError] = useState("");
  const inputRef = useRef(null);
  const closeBtnRef = useRef(null);

  useEffect(() => {
    inputRef.current?.focus();
    function onKey(e) {
      if (e.key === "Escape") onClose();
      if (e.key === "Tab") {
        const focusables = [inputRef.current, closeBtnRef.current, document.getElementById("act-btn"), document.getElementById("cancel-btn")].filter(Boolean);
        const idx = focusables.indexOf(document.activeElement);
        if (idx === -1) return;
        e.preventDefault();
        const next = e.shiftKey ? (idx - 1 + focusables.length) % focusables.length : (idx + 1) % focusables.length;
        focusables[next]?.focus();
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  function handleActivate() {
    setError("");
    const result = verifyLicenseKey(licenseKey);
    if (!result) { setError("Invalid license key. Check it and try again."); return; }
    onActivate(result, licenseKey.trim().toUpperCase());
  }

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="license-title">
      <div className="modal">
        <div className="modal-header">
          <h2 id="license-title">Activate {tierName}</h2>
          <button ref={closeBtnRef} onClick={onClose} className="btn btn--ghost btn--sm" aria-label="Close">✕</button>
        </div>
        <div className="modal-body">
          <p>After completing payment, you will receive a license key by email. Paste it below to activate your plan.</p>
          <div className="field-group" style={{ marginTop: 16 }}>
            <label className="field-label" htmlFor="lk">License Key</label>
            <input ref={inputRef} id="lk" className="field-input"
                   style={{ fontFamily: "var(--font-mono)", letterSpacing: "0.08em" }}
                   placeholder="BQ-PRO-XXXXXX-XXXXXX"
                   value={licenseKey}
                   onChange={e => setLicenseKey(e.target.value.toUpperCase())}
                   onKeyDown={e => e.key === "Enter" && handleActivate()} />
            {error && <span className="field-error" role="alert">{error}</span>}
          </div>
        </div>
        <div className="modal-footer">
          <button id="cancel-btn" onClick={onClose} className="btn btn--ghost">Cancel</button>
          <button id="act-btn" onClick={handleActivate} className="btn btn--primary">Activate Plan</button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// SETTINGS
// ---------------------------------------------------------------------------

function Settings({ biz, tier, onActivateLicense, onClearLicense, cryptoKey, onSave, notify, onLock, onPasswordChange }) {
  const [form, setForm] = useState({ ...biz });
  const [licenseModal, setLicenseModal] = useState(null);
  const [showPw, setShowPw] = useState(false);
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [newPw2, setNewPw2] = useState("");
  const [pwLoading, setPwLoading] = useState(false);

  async function handleChangePw() {
    if (newPw.length < 8) { notify("Minimum 8 characters.", "error"); return; }
    if (newPw !== newPw2) { notify("Passwords do not match.", "error"); return; }
    if (!/[A-Z]/.test(newPw) || !/[0-9]/.test(newPw)) { notify("Needs uppercase + number.", "error"); return; }
    setPwLoading(true);
    try {
      const testKey = await AUTH.login(oldPw);
      if (!testKey) { notify("Current password is wrong.", "error"); setPwLoading(false); return; }
      const newKey = await AUTH.changePassword(cryptoKey, newPw);
      onPasswordChange(newKey);
      setShowPw(false); setOldPw(""); setNewPw(""); setNewPw2("");
      notify("Password changed. All data re-encrypted.");
    } catch { notify("Failed.", "error"); }
    setPwLoading(false);
  }

  return (
    <div className="page-enter">
      <div className="page-header"><h1 className="page-title">Settings</h1></div>

      <h2 className="section-title">Your Plan</h2>
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="tier-grid">
          {Object.entries(TIERS).map(([k, t]) => (
            <button key={k} type="button" className={`tier-card ${tier === k ? "active" : ""}`}
                    onClick={() => {
                      if (k === "free") return;
                      window.open(PAYMENT_URL, "_blank");
                      setLicenseModal({ tier: k, name: t.name });
                    }}>
              <h4>{t.name}</h4>
              <div className="price">{t.price || "Free forever"}</div>
              <ul>
                <li>{t.quotesPerMonth === Infinity ? "∞" : t.quotesPerMonth} quotes/mo</li>
                <li>{t.maxClients === Infinity ? "∞" : t.maxClients} clients</li>
                <li>{t.features.print ? "✓" : "—"} Print/PDF</li>
                <li>{t.features.discount ? "✓" : "—"} Discounts</li>
                <li>{t.features.signature ? "✓" : "—"} Signatures</li>
                <li>{t.features.duplicate ? "✓" : "—"} Duplicate</li>
              </ul>
            </button>
          ))}
        </div>
        <p className="field-hint" style={{ marginTop: 14 }}>
          After payment, you will receive a license key by email. Enter it here to activate your plan.
        </p>
        <div className="action-bar" style={{ marginTop: 10 }}>
          <button className="btn btn--secondary btn--sm" onClick={() => setLicenseModal({ tier: "pro", name: "Pro" })}>Activate License</button>
          {tier !== "free" && <button className="btn btn--ghost btn--sm" onClick={onClearLicense}>Downgrade to Free</button>}
        </div>
      </div>

      <h2 className="section-title">Business Info</h2>
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="form-grid">
          <Field label="Business Name" value={form.name || ""} onChange={v => setForm(p => ({ ...p, name: v }))} placeholder="Your Business" />
          <Field label="Email" value={form.email || ""} onChange={v => setForm(p => ({ ...p, email: v }))} placeholder="info@business.co" />
          <Field label="Phone" value={form.phone || ""} onChange={v => setForm(p => ({ ...p, phone: v }))} placeholder="+27 00 000 0000" />
          <Field label="Tax / VAT" value={form.taxId || ""} onChange={v => setForm(p => ({ ...p, taxId: v }))} placeholder="VAT4830000000" />
          <Field label="Website" value={form.website || ""} onChange={v => setForm(p => ({ ...p, website: v }))} placeholder="https://yourbusiness.co" />
          <Sel label="Currency" value={form.defaultCurrency || "ZAR"} onChange={v => setForm(p => ({ ...p, defaultCurrency: v }))}
               options={CURRENCIES.map(c => ({ value: c.code, label: `${c.code} — ${c.symbol}` }))} />
          <Field label="Address" value={form.address || ""} onChange={v => setForm(p => ({ ...p, address: v }))} placeholder="123 Main Rd" span />
          <div className="field-group field-group--span">
            <label className="field-label" htmlFor="terms">Default Terms</label>
            <textarea id="terms" className="field-textarea" value={form.terms || ""}
                      onChange={e => setForm(p => ({ ...p, terms: e.target.value }))} rows={3}
                      placeholder="Payment due within 30 days..." />
          </div>
        </div>
        <button onClick={() => { onSave(form); notify("Saved."); }} className="btn btn--primary" style={{ marginTop: 14 }}>Save</button>
      </div>

      <h2 className="section-title">Authentication</h2>
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="action-bar" style={{ marginBottom: 12 }}>
          <button onClick={onLock} className="btn btn--secondary">Lock App Now</button>
          <button onClick={() => setShowPw(!showPw)} className="btn btn--ghost">{showPw ? "Cancel" : "Change Password"}</button>
        </div>
        {showPw && (
          <div className="form-grid" style={{ gridTemplateColumns: "1fr" }}>
            <Field label="Current Password" type="password" value={oldPw} onChange={setOldPw} placeholder="" />
            <Field label="New Password" type="password" value={newPw} onChange={setNewPw} placeholder="Min 8 chars, uppercase + number" />
            <Field label="Confirm New Password" type="password" value={newPw2} onChange={setNewPw2} placeholder="" />
            <button onClick={handleChangePw} disabled={pwLoading} className={`btn btn--primary ${pwLoading ? "btn--loading" : ""}`}>Change Password</button>
          </div>
        )}
      </div>

      <h2 className="section-title">Security</h2>
      <div className="card" style={{ marginBottom: 24, background: "var(--bg-warm)" }}>
        <ul style={{ listStyle: "none", display: "flex", flexDirection: "column", gap: 10, fontSize: "var(--font-size-sm)", color: "var(--text-secondary)" }}>
          <li><strong style={{ color: "var(--success)" }}>✓ PBKDF2</strong> — 600,000 iterations derive your encryption key.</li>
          <li><strong style={{ color: "var(--success)" }}>✓ AES-256-GCM</strong> — Every record encrypted with a unique IV.</li>
          <li><strong style={{ color: "var(--success)" }}>✓ Password never stored</strong> — Only a verification hash on disk.</li>
          <li><strong style={{ color: "var(--success)" }}>✓ Auto-lock</strong> — Locks after 15 minutes of inactivity.</li>
          <li><strong style={{ color: "var(--success)" }}>✓ Rate-limited login</strong> — 5 failed attempts = 30s lockout.</li>
          <li><strong style={{ color: "var(--success)" }}>✓ Zero network</strong> — No data leaves your device.</li>
        </ul>
      </div>

      <h2 className="section-title" style={{ color: "var(--danger)" }}>Danger Zone</h2>
      <div className="card" style={{ borderColor: "var(--danger)" }}>
        <p style={{ fontSize: "var(--font-size-sm)", color: "var(--text-secondary)", marginBottom: 12 }}>
          Permanently delete all data, password, and license. This cannot be undone.
        </p>
        <ConfirmBtn label="Delete All Data" confirmLabel="Confirm — delete everything?"
                    onConfirm={() => { AUTH.destroyAll(); window.location.reload(); }}
                    className="btn btn--danger" />
      </div>

      {licenseModal && (
        <LicenseKeyModal
          tierName={licenseModal.name}
          onClose={() => setLicenseModal(null)}
          onActivate={(tier, key) => {
            onActivateLicense(tier, key);
            setLicenseModal(null);
            notify(`${TIERS[tier].name} plan activated.`);
          }}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// ROOT
// ---------------------------------------------------------------------------

export default function App() {
  const [cryptoKey, setCryptoKey] = useState(null);
  const [authState, setAuthState] = useState("loading");
  const lastActivity = useRef(Date.now());

  useEffect(() => { setAuthState(AUTH.isSetUp() ? "locked" : "locked"); }, []);

  useEffect(() => {
    if (authState !== "unlocked") return;
    function resetTimer() { lastActivity.current = Date.now(); }
    function checkLock() {
      if (Date.now() - lastActivity.current > AUTH.LOCK_TIMEOUT_MS) {
        setCryptoKey(null);
        setAuthState("locked");
      }
    }
    const events = ["pointermove", "keydown", "click"];
    events.forEach(e => window.addEventListener(e, resetTimer));
    const id = setInterval(checkLock, 30_000);
    return () => { events.forEach(e => window.removeEventListener(e, resetTimer)); clearInterval(id); };
  }, [authState]);

  function handleUnlock(key) { setCryptoKey(key); setAuthState("unlocked"); lastActivity.current = Date.now(); }
  function handleLock() { setCryptoKey(null); setAuthState("locked"); }

  if (authState === "loading") return <div className="lock-screen"><span style={{ color: "var(--text-secondary)" }}>Loading…</span></div>;
  if (authState === "locked") return <LockScreen onUnlock={handleUnlock} />;

  return <AuthenticatedApp cryptoKey={cryptoKey} onLock={handleLock} onKeyChange={setCryptoKey} />;
}

function AuthenticatedApp({ cryptoKey, onLock, onKeyChange }) {
  const [quotes, setQuotes, q1] = useStore("quotes", [], cryptoKey);
  const [clients, setClients, q2] = useStore("clients", [], cryptoKey);
  const [catalog, setCatalog, q3] = useStore("catalog", [], cryptoKey);
  const [biz, setBiz, q4] = useStore("biz", { name: "", email: "", phone: "", address: "", taxId: "", website: "", defaultCurrency: "ZAR", terms: "" }, cryptoKey);
  const [tierData, setTierData, q5] = useStore("tier", { plan: "business" }, cryptoKey);
  const [licenseData, setLicenseData, q6] = useStore("license_key", { key: "DEV-BUILD" }, cryptoKey);

  const [page, setPage] = useState("dashboard");
  const [editingQuote, setEditingQuote] = useState(null);
  const [toast, setToast] = useState(null);

  const ready = q1 && q2 && q3 && q4 && q5 && q6;
  // Dev build: tier permanently locked to business — all features unlocked, no payment gates.
  const tier = "business";

  // Storage-full toast
  useEffect(() => {
    function handler() { notify("Storage full — export your data or delete old quotes.", "error"); }
    window.addEventListener("bqd:storage-full", handler);
    return () => window.removeEventListener("bqd:storage-full", handler);
  }, []);

  function notify(m, t = "success") {
    setToast({ m, t });
    setTimeout(() => setToast(null), 2800);
  }

  function go(p) { setPage(p); setEditingQuote(null); }

  async function saveQ(q) {
    const i = quotes.findIndex(x => x.id === q.id);
    await setQuotes(i >= 0 ? quotes.map(x => x.id === q.id ? q : x) : [...quotes, q]);
    notify("Saved.");
    go("quotes");
  }
  async function delQ(qid) { await setQuotes(quotes.filter(x => x.id !== qid)); notify("Deleted.", "error"); go("quotes"); }
  async function saveC(c) { const i = clients.findIndex(x => x.id === c.id); await setClients(i >= 0 ? clients.map(x => x.id === c.id ? c : x) : [...clients, c]); notify(i >= 0 ? "Updated." : "Added."); }
  async function delC(cid) { await setClients(clients.filter(x => x.id !== cid)); notify("Deleted.", "error"); }
  async function saveP(p) { const i = catalog.findIndex(x => x.id === p.id); await setCatalog(i >= 0 ? catalog.map(x => x.id === p.id ? p : x) : [...catalog, p]); notify(i >= 0 ? "Updated." : "Added."); }
  async function delP(pid) { await setCatalog(catalog.filter(x => x.id !== pid)); notify("Removed.", "error"); }

  async function activateLicense(newTier, key) {
    await setLicenseData({ key });
    await setTierData({ plan: newTier });
  }
  async function clearLicense() {
    await setLicenseData({ key: "" });
    await setTierData({ plan: "free" });
    notify("Downgraded to Free.");
  }

  function startNewQuote() {
    const mu = quotesThisMonth(quotes);
    if (TIERS[tier].quotesPerMonth !== Infinity && mu >= TIERS[tier].quotesPerMonth) {
      notify("Monthly limit reached. Upgrade for more.", "error");
      return;
    }
    setEditingQuote(newQuote(biz.defaultCurrency));
    setPage("editor");
  }

  if (!ready) return <div className="lock-screen"><span style={{ color: "var(--text-secondary)" }}>Decrypting data…</span></div>;

  return (
    <div className="app-shell">
      <Sidebar page={page} setPage={go} biz={biz} tier={tier} onLock={onLock} />
      <div style={{ display: "contents" }}>
        <MobileBar biz={biz} onSettings={() => go("settings")} onLock={onLock} />
        <main className="main-content">
          {page === "dashboard" && (
            <Dashboard quotes={quotes} currency={biz.defaultCurrency || "ZAR"} tier={tier}
                       onNew={startNewQuote} onEdit={q => { setEditingQuote({ ...q }); setPage("editor"); }} />
          )}
          {page === "quotes" && (
            <QuotesList quotes={quotes} tier={tier}
                        onNew={startNewQuote} onEdit={q => { setEditingQuote({ ...q }); setPage("editor"); }} />
          )}
          {page === "editor" && editingQuote && (
            <Editor initial={editingQuote} clients={clients} catalog={catalog} allQuotes={quotes}
                    tier={tier} biz={biz} onSave={saveQ} onDelete={delQ}
                    onBack={() => go("quotes")} notify={notify} />
          )}
          {page === "catalog" && <Catalog catalog={catalog} tier={tier} onSave={saveP} onDelete={delP} notify={notify} />}
          {page === "clients" && <Clients clients={clients} tier={tier} onSave={saveC} onDelete={delC} notify={notify} />}
          {page === "settings" && (
            <Settings biz={biz} tier={tier} cryptoKey={cryptoKey}
                      onActivateLicense={activateLicense} onClearLicense={clearLicense}
                      onSave={setBiz} notify={notify} onLock={onLock} onPasswordChange={onKeyChange} />
          )}
        </main>
        <BottomNav page={page} setPage={go} />
      </div>
      {toast && <div role="status" aria-live="polite" className={`toast toast--${toast.t}`}>{toast.m}</div>}
    </div>
  );
}
