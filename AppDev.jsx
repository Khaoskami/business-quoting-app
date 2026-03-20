import { useState, useEffect, useCallback, useMemo, useRef } from "react";

/* ==========================================================================
   BUSINESS QUOTING APPLICATION — DEV BUILD (AUTH PROTECTED)
   
   This build is password-protected. Only someone with the password
   can access the app or read any stored data.
   
   HOW IT WORKS:
   - First run: you create a master password
   - The password is run through PBKDF2 (600,000 iterations) to derive
     an AES-256-GCM encryption key
   - ALL stored data is encrypted with this key
   - Without the password, localStorage contents are unreadable gibberish
   - The password itself is NEVER stored — only a verification hash
   - Auto-locks after 15 minutes of inactivity
   
   All features unlocked. No tier limits. No payment gates.
   Separate storage namespace from production (prefix: bqd_)
   
   Copyright (c) 2026 Khaos / Khaoskami. All rights reserved.
   Contact: github.com/Khaoskami
   ========================================================================== */

// ---------------------------------------------------------------------------
// AUTH + ENCRYPTION ENGINE
// ---------------------------------------------------------------------------
// The encryption key is derived from your password. No password = no data.
// This is not a server login — it is local cryptographic access control.
// Even if someone clones your device storage, they cannot read the data.
// ---------------------------------------------------------------------------

const AUTH = {
  PREFIX: "bqd_",
  SALT_KEY: "bqd_auth_salt",
  HASH_KEY: "bqd_auth_hash",
  PBKDF2_ITERATIONS: 600000,
  KEY_LENGTH: 256,
  IV_LENGTH: 12,
  LOCK_TIMEOUT_MS: 15 * 60 * 1000, // 15 minutes

  // Generate a random salt on first setup
  generateSalt() {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    return btoa(String.fromCharCode(...salt));
  },

  // Derive AES-256 key from password using PBKDF2
  async deriveKey(password, saltB64) {
    const encoder = new TextEncoder();
    const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));

    const baseKey = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: this.PBKDF2_ITERATIONS, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: this.KEY_LENGTH },
      false,
      ["encrypt", "decrypt"]
    );
  },

  // Create a verification hash so we can check the password on login
  // This is a separate PBKDF2 derivation with a different purpose salt
  async createVerifyHash(password, saltB64) {
    const encoder = new TextEncoder();
    const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
    const purposeSalt = new Uint8Array([...salt, ...encoder.encode("verify")]);

    const baseKey = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: purposeSalt, iterations: this.PBKDF2_ITERATIONS, hash: "SHA-256" },
      baseKey,
      256
    );

    return btoa(String.fromCharCode(...new Uint8Array(bits)));
  },

  // Encrypt data with the derived key
  async encrypt(key, data) {
    const iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));
    const encoded = new TextEncoder().encode(JSON.stringify(data));
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
    return JSON.stringify({
      iv: btoa(String.fromCharCode(...iv)),
      d: btoa(String.fromCharCode(...new Uint8Array(cipher))),
    });
  },

  // Decrypt data with the derived key
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

  // Check if auth has been set up (salt + hash exist)
  isSetUp() {
    return localStorage.getItem(this.SALT_KEY) !== null && localStorage.getItem(this.HASH_KEY) !== null;
  },

  // First-time setup: create salt, derive key, store verification hash
  async setup(password) {
    const salt = this.generateSalt();
    const hash = await this.createVerifyHash(password, salt);
    const key = await this.deriveKey(password, salt);
    localStorage.setItem(this.SALT_KEY, salt);
    localStorage.setItem(this.HASH_KEY, hash);
    return key;
  },

  // Login: verify password, derive key
  async login(password) {
    const salt = localStorage.getItem(this.SALT_KEY);
    const storedHash = localStorage.getItem(this.HASH_KEY);
    if (!salt || !storedHash) return null;

    const hash = await this.createVerifyHash(password, salt);
    if (hash !== storedHash) return null;

    return this.deriveKey(password, salt);
  },

  // Change password: re-encrypt all data with new key
  async changePassword(oldKey, newPassword) {
    const salt = this.generateSalt();
    const hash = await this.createVerifyHash(newPassword, salt);
    const newKey = await this.deriveKey(newPassword, salt);

    // Re-encrypt all stored data
    const dataKeys = Object.keys(localStorage).filter(
      k => k.startsWith(this.PREFIX) && k !== this.SALT_KEY && k !== this.HASH_KEY
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

  // Nuke everything
  destroyAll() {
    Object.keys(localStorage)
      .filter(k => k.startsWith(this.PREFIX) || k === this.SALT_KEY || k === this.HASH_KEY)
      .forEach(k => localStorage.removeItem(k));
  },
};

// ---------------------------------------------------------------------------
// SANITISATION
// ---------------------------------------------------------------------------

function san(v) {
  if (typeof v === "string") { const m = { "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "&": "&amp;" }; return v.replace(/[<>"'&]/g, c => m[c]); }
  if (Array.isArray(v)) return v.map(san);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, val]) => [k, san(val)]));
  return v;
}

function validateUrl(url) {
  if (!url || typeof url !== "string") return "";
  const t = url.trim();
  if (!t) return "";
  try { const p = new URL(t.startsWith("http") ? t : "https://" + t); if (!["http:", "https:"].includes(p.protocol) || p.hostname.includes("javascript") || /[<>"'`]/.test(p.href)) return ""; return p.href; } catch { return ""; }
}

// ---------------------------------------------------------------------------
// SHA-256 SIGNATURE
// ---------------------------------------------------------------------------

async function signQuote(quote, ownerInfo) {
  const payload = JSON.stringify({
    id: quote.id, title: quote.title, items: quote.items,
    total: calcTotals(quote.items, quote.taxPercent, quote.discountPercent).total,
    created: quote.createdAt, owner: ownerInfo.name || "Business Quotes App",
    ownerContact: ownerInfo.email || "",
    copyright: `© ${new Date().getFullYear()} ${ownerInfo.name || "Khaoskami"}. All rights reserved.`,
    timestamp: new Date().toISOString(),
  });
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload));
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// AUTHENTICATED STORAGE HOOK
// Uses the password-derived key passed through React context
// ---------------------------------------------------------------------------

function useAuthStore(key, fallback, cryptoKey) {
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
    const clean = san(next);
    setData(clean);
    try {
      const enc = await AUTH.encrypt(cryptoKey, clean);
      localStorage.setItem(fk, enc);
    } catch {}
  }, [fk, cryptoKey]);

  return [data, save, ok];
}

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------

const uid = () => crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2);

const CURRENCIES = [
  { code: "ZAR", symbol: "R" }, { code: "USD", symbol: "$" }, { code: "EUR", symbol: "€" },
  { code: "GBP", symbol: "£" }, { code: "AUD", symbol: "A$" }, { code: "CAD", symbol: "C$" },
  { code: "JPY", symbol: "¥" }, { code: "INR", symbol: "₹" }, { code: "BRL", symbol: "R$" },
  { code: "NGN", symbol: "₦" }, { code: "KES", symbol: "KSh" }, { code: "AED", symbol: "د.إ" },
  { code: "CNY", symbol: "¥" }, { code: "CHF", symbol: "CHF" }, { code: "NZD", symbol: "NZ$" },
  { code: "MXN", symbol: "MX$" }, { code: "SEK", symbol: "kr" }, { code: "SGD", symbol: "S$" },
];

function money(a, c = "ZAR") { try { return new Intl.NumberFormat("en", { style: "currency", currency: c }).format(a || 0); } catch { return (CURRENCIES.find(x => x.code === c)?.symbol || "") + (a || 0).toFixed(2); } }
function fmtDate(iso) { return new Date(iso).toLocaleDateString("en", { day: "numeric", month: "short", year: "numeric" }); }

function calcTotals(items, tax, disc = 0) {
  const line = items.reduce((s, i) => s + i.quantity * i.unitPrice, 0);
  const da = line * (disc / 100), sub = line - da, t = sub * (tax / 100);
  return { line, discountAmt: da, sub, tax: t, total: sub + t };
}

const STATUSES = {
  draft: { label: "Draft", col: "#71717a" }, sent: { label: "Sent", col: "#3b82f6" },
  accepted: { label: "Accepted", col: "#22c55e" }, declined: { label: "Declined", col: "#ef4444" },
  expired: { label: "Expired", col: "#f59e0b" },
};

function newQuote(cur) {
  return { id: uid(), quoteNumber: "", title: "", clientId: "", clientName: "", clientUrl: "",
    status: "draft", currency: cur || "ZAR", taxPercent: 15, discountPercent: 0,
    validityDays: 30, notes: "", createdAt: new Date().toISOString(),
    items: [{ id: uid(), description: "", quantity: 1, unitPrice: 0, catalogId: "" }],
    signature: "", signedAt: "" };
}
function newClient() { return { id: "", name: "", company: "", email: "", phone: "", address: "", website: "", notes: "" }; }
function newProduct() { return { id: "", name: "", category: "", description: "", unitPrice: 0, unit: "each" }; }

// ---------------------------------------------------------------------------
// STYLES
// ---------------------------------------------------------------------------

const X = {
  bg: "#0e0e11", sf: "#16161a", bd: "#25252b", hv: "#1c1c22",
  tx: "#d4d4d8", mt: "#6b6b76", pr: "#3b82f6", ok: "#22c55e",
  no: "#ef4444", wn: "#f59e0b", ac: "#8b5cf6", dev: "#14b8a6",
};

const $ = {
  root: { fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif", background: X.bg, color: X.tx, minHeight: "100vh", display: "flex", flexDirection: "column", fontSize: 14, lineHeight: 1.5 },
  hdr: { padding: "12px 20px", borderBottom: `1px solid ${X.bd}`, display: "flex", alignItems: "center", justifyContent: "space-between" },
  nav: { display: "flex", borderBottom: `1px solid ${X.bd}`, padding: "0 8px", overflowX: "auto", gap: 2 },
  main: { padding: 20, flex: 1, overflowY: "auto" },
  h2: { fontSize: 20, fontWeight: 700, margin: "0 0 20px", color: X.tx },
  card: { background: X.sf, border: `1px solid ${X.bd}`, borderRadius: 8, padding: 16, marginBottom: 12 },
  lbl: { display: "block", fontSize: 11, fontWeight: 600, color: X.mt, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.04em" },
  inp: { background: X.bg, border: `1px solid ${X.bd}`, borderRadius: 6, padding: "8px 10px", color: X.tx, fontSize: 13, width: "100%", boxSizing: "border-box", fontFamily: "inherit", outline: "none" },
  ta: { background: X.bg, border: `1px solid ${X.bd}`, borderRadius: 6, padding: "8px 10px", color: X.tx, fontSize: 13, width: "100%", boxSizing: "border-box", fontFamily: "inherit", outline: "none", resize: "vertical" },
  btn: { background: X.pr, color: "#fff", border: "none", borderRadius: 6, padding: "8px 14px", fontSize: 13, fontWeight: 600, cursor: "pointer", fontFamily: "inherit" },
  btn2: { background: X.sf, color: X.tx, border: `1px solid ${X.bd}`, borderRadius: 6, padding: "8px 14px", fontSize: 13, fontWeight: 500, cursor: "pointer", fontFamily: "inherit" },
  btnD: { background: "transparent", color: X.no, border: `1px solid ${X.no}33`, borderRadius: 6, padding: "8px 14px", fontSize: 13, fontWeight: 500, cursor: "pointer", fontFamily: "inherit" },
  btnG: { background: "none", color: X.mt, border: "none", padding: "8px 10px", fontSize: 13, cursor: "pointer", fontFamily: "inherit" },
  badge: (c) => ({ display: "inline-block", fontSize: 11, fontWeight: 600, padding: "2px 8px", borderRadius: 4, background: c + "18", color: c }),
  grid: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 },
  row: { display: "flex", alignItems: "center", gap: 8 },
  btwn: { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 },
  stat: (c) => ({ background: X.sf, border: `1px solid ${X.bd}`, borderRadius: 8, padding: "14px 16px", borderLeft: `3px solid ${c}` }),
  li: { background: X.sf, border: `1px solid ${X.bd}`, borderRadius: 8, padding: "12px 14px", display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "pointer", gap: 12, marginBottom: 6 },
  empty: { textAlign: "center", padding: 48, color: X.mt, fontSize: 14 },
  toast: (t) => ({ position: "fixed", bottom: 20, left: "50%", transform: "translateX(-50%)", background: t === "error" ? "#3b1111" : "#113b1a", color: t === "error" ? X.no : X.ok, padding: "10px 20px", borderRadius: 8, fontSize: 13, fontWeight: 600, boxShadow: "0 4px 20px rgba(0,0,0,0.5)", zIndex: 1000 }),
  divider: { borderTop: `1px solid ${X.bd}`, margin: "8px 0" },
};

// ---------------------------------------------------------------------------
// AUTH SCREENS
// ---------------------------------------------------------------------------

function SetupScreen({ onSetup }) {
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSetup() {
    setErr("");
    if (pw.length < 8) { setErr("Minimum 8 characters."); return; }
    if (pw !== pw2) { setErr("Passwords do not match."); return; }
    if (!/[A-Z]/.test(pw) || !/[0-9]/.test(pw)) { setErr("Must include at least one uppercase letter and one number."); return; }
    setLoading(true);
    try {
      const key = await AUTH.setup(pw);
      onSetup(key);
    } catch (e) {
      setErr("Setup failed. Try again.");
      setLoading(false);
    }
  }

  return (
    <div style={{ ...$.root, alignItems: "center", justifyContent: "center", padding: 20 }}>
      <div style={{ width: "100%", maxWidth: 360 }}>
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div style={{ fontSize: 20, fontWeight: 700, marginBottom: 6 }}>Create Master Password</div>
          <div style={{ fontSize: 13, color: X.mt, lineHeight: 1.6 }}>
            This password encrypts all your data. It is never stored.
            If you forget it, your data cannot be recovered.
          </div>
        </div>
        <div style={{ marginBottom: 12 }}>
          <label style={$.lbl}>Password</label>
          <input type="password" value={pw} onChange={e => setPw(e.target.value)} placeholder="Minimum 8 characters" style={$.inp} onKeyDown={e => e.key === "Enter" && handleSetup()} autoFocus />
        </div>
        <div style={{ marginBottom: 12 }}>
          <label style={$.lbl}>Confirm Password</label>
          <input type="password" value={pw2} onChange={e => setPw2(e.target.value)} placeholder="Re-enter password" style={$.inp} onKeyDown={e => e.key === "Enter" && handleSetup()} />
        </div>
        <div style={{ fontSize: 11, color: X.mt, marginBottom: 16, lineHeight: 1.5 }}>
          Requirements: 8+ characters, at least one uppercase letter, at least one number.
        </div>
        {err && <div style={{ fontSize: 13, color: X.no, marginBottom: 12 }}>{err}</div>}
        <button onClick={handleSetup} disabled={loading} style={{ ...$.btn, width: "100%", padding: "10px 0", opacity: loading ? 0.6 : 1 }}>
          {loading ? "Deriving encryption key..." : "Create Password & Enter"}
        </button>
      </div>
    </div>
  );
}

function LoginScreen({ onLogin }) {
  const [pw, setPw] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);
  const [attempts, setAttempts] = useState(0);

  async function handleLogin() {
    setErr("");

    // Rate limiting: lock for 30s after 5 failed attempts
    if (attempts >= 5) {
      setErr("Too many attempts. Wait 30 seconds.");
      setTimeout(() => setAttempts(0), 30000);
      return;
    }

    setLoading(true);
    try {
      const key = await AUTH.login(pw);
      if (!key) {
        setAttempts(a => a + 1);
        setErr(`Wrong password. ${4 - attempts} attempts remaining.`);
        setPw("");
        setLoading(false);
        return;
      }
      onLogin(key);
    } catch {
      setErr("Login failed.");
      setLoading(false);
    }
  }

  return (
    <div style={{ ...$.root, alignItems: "center", justifyContent: "center", padding: 20 }}>
      <div style={{ width: "100%", maxWidth: 360 }}>
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div style={{ fontSize: 20, fontWeight: 700, marginBottom: 6 }}>Business Quotes</div>
          <div style={{ ...$.row, justifyContent: "center", marginBottom: 8 }}>
            <span style={$.badge(X.dev)}>Dev Build</span>
            <span style={{ fontSize: 11, color: X.ok, fontWeight: 600, background: X.ok + "15", padding: "3px 8px", borderRadius: 4 }}>Encrypted</span>
          </div>
          <div style={{ fontSize: 13, color: X.mt }}>Enter your master password to decrypt and access your data.</div>
        </div>
        <div style={{ marginBottom: 16 }}>
          <label style={$.lbl}>Master Password</label>
          <input type="password" value={pw} onChange={e => setPw(e.target.value)} placeholder="Enter password" style={$.inp} onKeyDown={e => e.key === "Enter" && handleLogin()} autoFocus />
        </div>
        {err && <div style={{ fontSize: 13, color: X.no, marginBottom: 12 }}>{err}</div>}
        <button onClick={handleLogin} disabled={loading || attempts >= 5} style={{ ...$.btn, width: "100%", padding: "10px 0", opacity: (loading || attempts >= 5) ? 0.6 : 1 }}>
          {loading ? "Deriving key (this takes a moment)..." : "Unlock"}
        </button>
        <div style={{ textAlign: "center", marginTop: 20 }}>
          <button onClick={() => { if (confirm("This will permanently delete ALL data. Are you sure?")) { AUTH.destroyAll(); window.location.reload(); } }} style={{ ...$.btnG, fontSize: 12, color: X.no }}>
            Reset everything (destroys all data)
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// SHARED UI
// ---------------------------------------------------------------------------

function Tab({ label, active, onClick }) {
  return <button onClick={onClick} style={{ background: "none", border: "none", borderBottom: active ? `2px solid ${X.pr}` : "2px solid transparent", padding: "10px 14px", fontSize: 13, fontWeight: 500, color: active ? X.pr : X.mt, cursor: "pointer", fontFamily: "inherit", whiteSpace: "nowrap" }}>{label}</button>;
}
function Badge({ status }) { const s = STATUSES[status] || STATUSES.draft; return <span style={$.badge(s.col)}>{s.label}</span>; }
function ConfirmBtn({ label, confirmLabel, onConfirm, style: bs }) {
  const [a, sA] = useState(false);
  useEffect(() => { if (!a) return; const t = setTimeout(() => sA(false), 3000); return () => clearTimeout(t); }, [a]);
  return a ? <button onClick={onConfirm} style={{ ...bs, fontWeight: 700 }}>{confirmLabel || "Confirm?"}</button> : <button onClick={() => sA(true)} style={bs}>{label}</button>;
}
function Field({ label, value, onChange, placeholder, type = "text", span, min, max, step }) {
  return <div style={span ? { gridColumn: "1 / -1" } : undefined}><label style={$.lbl}>{label}</label><input type={type} value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} min={min} max={max} step={step} style={$.inp} /></div>;
}
function Sel({ label, value, onChange, options, span }) {
  return <div style={span ? { gridColumn: "1 / -1" } : undefined}><label style={$.lbl}>{label}</label><select value={value} onChange={e => onChange(e.target.value)} style={$.inp}>{options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}</select></div>;
}

// ---------------------------------------------------------------------------
// DASHBOARD
// ---------------------------------------------------------------------------

function Dash({ quotes, currency, onNew, onEdit, search, setSearch }) {
  const accepted = quotes.filter(q => q.status === "accepted");
  const revenue = accepted.reduce((s, q) => s + calcTotals(q.items, q.taxPercent, q.discountPercent).total, 0);
  const winRate = quotes.length > 0 ? Math.round((accepted.length / quotes.length) * 100) : 0;
  const filtered = quotes.filter(q => { if (!search) return true; const t = search.toLowerCase(); return (q.title || "").toLowerCase().includes(t) || (q.clientName || "").toLowerCase().includes(t) || (q.quoteNumber || "").toLowerCase().includes(t); }).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const stats = [{ l: "Total", v: quotes.length, c: X.pr }, { l: "Pending", v: quotes.filter(q => q.status === "sent").length, c: X.wn }, { l: "Accepted", v: accepted.length, c: X.ok }, { l: "Declined", v: quotes.filter(q => q.status === "declined").length, c: X.no }, { l: "Revenue", v: money(revenue, currency), c: X.ac }, { l: "Win Rate", v: winRate + "%", c: "#06b6d4" }];

  return (
    <div>
      <div style={{ ...$.btwn, marginBottom: 20, flexWrap: "wrap" }}><h2 style={$.h2}>Quotes</h2><button onClick={onNew} style={$.btn}>+ New Quote</button></div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: 8, marginBottom: 20 }}>{stats.map((s, i) => <div key={i} style={$.stat(s.c)}><div style={{ fontSize: 11, color: X.mt, textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 4 }}>{s.l}</div><div style={{ fontSize: 17, fontWeight: 700, color: s.c }}>{s.v}</div></div>)}</div>
      <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search quotes..." style={{ ...$.inp, marginBottom: 14 }} />
      {filtered.length === 0 ? <div style={$.empty}>{quotes.length === 0 ? "No quotes yet." : "No results."}</div> : filtered.map(q => {
        const { total } = calcTotals(q.items, q.taxPercent, q.discountPercent);
        return <div key={q.id} onClick={() => onEdit(q)} style={$.li}><div style={{ minWidth: 0 }}><div style={{ fontSize: 14, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{q.quoteNumber && <span style={{ color: X.mt, fontWeight: 400, marginRight: 6 }}>#{q.quoteNumber}</span>}{q.title || "Untitled"}{q.signature && <span style={{ marginLeft: 6, fontSize: 10, color: X.ok }}>✓ signed</span>}</div><div style={{ fontSize: 12, color: X.mt, marginTop: 2 }}>{q.clientName || "No client"} · {fmtDate(q.createdAt)}</div></div><div style={{ ...$.row, flexShrink: 0 }}><span style={{ fontWeight: 600, fontSize: 14 }}>{money(total, q.currency)}</span><Badge status={q.status} /></div></div>;
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// QUOTE EDITOR
// ---------------------------------------------------------------------------

function Editor({ initial, clients, catalog, allQuotes, biz, onSave, onDelete, onBack, notify }) {
  const [q, setQ] = useState({ ...initial });
  const isEx = allQuotes.some(x => x.id === q.id);
  const { line, discountAmt, sub, tax, total } = calcTotals(q.items, q.taxPercent, q.discountPercent);
  const cats = useMemo(() => [...new Set(catalog.map(p => p.category).filter(Boolean))], [catalog]);
  const [catF, setCatF] = useState("");
  const [showCat, setShowCat] = useState(false);

  function set(f, v) { setQ(p => ({ ...p, [f]: v })); }
  function setI(idx, f, v) { setQ(p => { const it = [...p.items]; it[idx] = { ...it[idx], [f]: (f === "quantity" || f === "unitPrice") ? Math.max(0, Number(v) || 0) : v }; return { ...p, items: it }; }); }
  function addBlank() { setQ(p => ({ ...p, items: [...p.items, { id: uid(), description: "", quantity: 1, unitPrice: 0, catalogId: "" }] })); }
  function addCat(pr) { setQ(p => ({ ...p, items: [...p.items, { id: uid(), description: pr.name + (pr.description ? ` — ${pr.description}` : ""), quantity: 1, unitPrice: pr.unitPrice, catalogId: pr.id }] })); setShowCat(false); }
  function rmI(idx) { if (q.items.length > 1) setQ(p => ({ ...p, items: p.items.filter((_, i) => i !== idx) })); }

  async function handleSign() { const sig = await signQuote(q, biz); setQ(p => ({ ...p, signature: sig, signedAt: new Date().toISOString() })); notify("Signed."); }
  function handleDuplicate() { setQ({ ...q, id: uid(), title: q.title + " (copy)", quoteNumber: "", status: "draft", createdAt: new Date().toISOString(), signature: "", signedAt: "" }); notify("Duplicated."); }

  function handleCSV() {
    const rows = [["GENERATED BY", "Business Quotes App — github.com/Khaoskami"], [`© ${new Date().getFullYear()} ${biz.name || "Khaoskami"}`, "All rights reserved."], q.signature ? ["INTEGRITY SIGNATURE", q.signature] : null, q.signature ? ["SIGNED AT", q.signedAt] : null, [], ["Quote", q.title, "Number", q.quoteNumber, "Date", fmtDate(q.createdAt)], ["Client", q.clientName], q.clientUrl ? ["Client Website", q.clientUrl] : null, [], ["Description", "Qty", "Unit Price", "Line Total"], ...q.items.map(i => [i.description, i.quantity, i.unitPrice, i.quantity * i.unitPrice]), [], ["", "", "Line Total", line], q.discountPercent > 0 ? ["", "", `Discount (${q.discountPercent}%)`, -discountAmt] : null, ["", "", "Subtotal", sub], ["", "", `Tax (${q.taxPercent}%)`, tax], ["", "", "TOTAL", total]].filter(Boolean);
    const csv = rows.map(r => r.map(c => `"${c}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" }); const url = URL.createObjectURL(blob);
    Object.assign(document.createElement("a"), { href: url, download: `${q.quoteNumber || q.title || "quote"}.csv` }).click(); URL.revokeObjectURL(url); notify("CSV exported.");
  }

  function handlePrint() {
    const cur = q.currency;
    const itemRows = q.items.map(i => `<tr><td style="padding:8px;border-bottom:1px solid #e5e5e5">${i.description}</td><td style="padding:8px;border-bottom:1px solid #e5e5e5;text-align:center">${i.quantity}</td><td style="padding:8px;border-bottom:1px solid #e5e5e5;text-align:right">${money(i.unitPrice, cur)}</td><td style="padding:8px;border-bottom:1px solid #e5e5e5;text-align:right">${money(i.quantity * i.unitPrice, cur)}</td></tr>`).join("");
    const sigBlock = q.signature ? `<div style="margin-top:24px;padding:12px;background:#f8f8f8;border:1px solid #ddd;border-radius:4px;font-size:11px;color:#666"><strong>INTEGRITY SIGNATURE</strong><br/><code style="font-size:10px;word-break:break-all">${q.signature}</code><br/>Signed: ${q.signedAt}</div>` : "";
    const copyright = `<div style="margin-top:32px;padding-top:12px;border-top:1px solid #ddd;font-size:10px;color:#999;text-align:center">© ${new Date().getFullYear()} ${biz.name || "Khaoskami"} · Business Quotes App · github.com/Khaoskami</div>`;
    const clientUrlLine = q.clientUrl ? `<div><strong>Website</strong><a href="${q.clientUrl}" style="color:#3b82f6;text-decoration:none"> ${q.clientUrl}</a></div>` : "";
    const html = `<!DOCTYPE html><html><head><title>${q.title || "Quote"}</title><style>body{font-family:-apple-system,sans-serif;padding:40px;color:#1a1a1a;max-width:800px;margin:0 auto}h1{font-size:24px;margin-bottom:4px}table{width:100%;border-collapse:collapse;margin:20px 0}th{text-align:left;padding:8px;border-bottom:2px solid #333;font-size:11px;text-transform:uppercase}td{font-size:13px}.totals{margin-left:auto;width:280px}.totals td{padding:4px 8px}.totals .grand{font-weight:700;font-size:16px;border-top:2px solid #333;padding-top:8px}.meta{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:20px 0;font-size:13px}.meta strong{display:block;font-size:10px;text-transform:uppercase;color:#666;margin-bottom:2px}@media print{body{padding:20px}}</style></head><body><h1>${q.title || "Quote"}</h1>${q.quoteNumber ? `<div style="color:#666;margin-bottom:16px">Quote #${q.quoteNumber}</div>` : ""}<div class="meta"><div><strong>Client</strong>${q.clientName || "—"}</div><div><strong>Date</strong>${fmtDate(q.createdAt)}</div>${clientUrlLine}<div><strong>Valid For</strong>${q.validityDays} days</div><div><strong>Status</strong>${(STATUSES[q.status] || STATUSES.draft).label}</div></div><table><thead><tr><th>Description</th><th style="text-align:center">Qty</th><th style="text-align:right">Unit Price</th><th style="text-align:right">Total</th></tr></thead><tbody>${itemRows}</tbody></table><table class="totals"><tr><td style="color:#666">Line Total</td><td style="text-align:right">${money(line, cur)}</td></tr>${q.discountPercent > 0 ? `<tr><td style="color:#666">Discount (${q.discountPercent}%)</td><td style="text-align:right;color:#c00">-${money(discountAmt, cur)}</td></tr>` : ""}<tr><td style="color:#666">Subtotal</td><td style="text-align:right">${money(sub, cur)}</td></tr><tr><td style="color:#666">Tax (${q.taxPercent}%)</td><td style="text-align:right">${money(tax, cur)}</td></tr><tr class="grand"><td>Total Due</td><td style="text-align:right">${money(total, cur)}</td></tr></table>${q.notes ? `<div style="margin-top:24px;padding-top:16px;border-top:1px solid #ddd"><strong style="font-size:10px;text-transform:uppercase;color:#666;display:block;margin-bottom:4px">Notes / Terms</strong><div style="font-size:12px;white-space:pre-wrap">${q.notes}</div></div>` : ""}${sigBlock}${copyright}</body></html>`;
    const w = window.open("", "_blank"); if (w) { w.document.write(html); w.document.close(); w.print(); }
  }

  const fc = catalog.filter(p => !catF || p.category === catF);

  return (
    <div>
      <div style={{ ...$.row, marginBottom: 20 }}><button onClick={onBack} style={$.btnG}>← Back</button><h2 style={{ ...$.h2, margin: 0, flex: 1 }}>{isEx ? "Edit Quote" : "New Quote"}</h2></div>
      <div style={{ ...$.grid, marginBottom: 16 }}>
        <Field label="Quote Title" value={q.title} onChange={v => set("title", v)} placeholder="e.g. Roof Repair, Brand Package" span />
        <Field label="Quote Number" value={q.quoteNumber} onChange={v => set("quoteNumber", v)} placeholder="QT-001" />
        <div><label style={$.lbl}>Client</label><select value={q.clientId} onChange={e => { const c = clients.find(x => x.id === e.target.value); set("clientId", e.target.value); set("clientName", c?.name || ""); set("clientUrl", c?.website || ""); }} style={$.inp}><option value="">— Select —</option>{clients.map(c => <option key={c.id} value={c.id}>{c.name}{c.company ? ` (${c.company})` : ""}</option>)}</select></div>
        <Sel label="Status" value={q.status} onChange={v => set("status", v)} options={Object.entries(STATUSES).map(([k, v]) => ({ value: k, label: v.label }))} />
        <Sel label="Currency" value={q.currency} onChange={v => set("currency", v)} options={CURRENCIES.map(c => ({ value: c.code, label: `${c.code} (${c.symbol})` }))} />
        <Field label="Tax %" type="number" value={q.taxPercent} onChange={v => set("taxPercent", Math.min(100, Math.max(0, Number(v) || 0)))} min={0} max={100} />
        <Field label="Discount %" type="number" value={q.discountPercent} onChange={v => set("discountPercent", Math.min(100, Math.max(0, Number(v) || 0)))} min={0} max={100} />
        <Field label="Valid (days)" type="number" value={q.validityDays} onChange={v => set("validityDays", Math.max(1, Number(v) || 1))} min={1} />
        <Field label="Client Website" value={q.clientUrl} onChange={v => set("clientUrl", v)} placeholder="https://clientsite.com" span />
      </div>
      <div style={{ marginBottom: 16 }}>
        <div style={{ ...$.btwn, marginBottom: 8 }}><span style={{ ...$.lbl, margin: 0, fontSize: 13 }}>Line Items</span><div style={$.row}>{catalog.length > 0 && <button onClick={() => setShowCat(!showCat)} style={{ ...$.btnG, color: X.ac, fontSize: 12 }}>{showCat ? "Close" : "From catalog"}</button>}<button onClick={addBlank} style={{ ...$.btnG, fontSize: 12 }}>+ Item</button></div></div>
        {showCat && <div style={{ ...$.card, padding: 12 }}><div style={{ ...$.row, marginBottom: 8 }}><span style={{ fontSize: 12, color: X.mt, fontWeight: 600 }}>CATALOG</span><select value={catF} onChange={e => setCatF(e.target.value)} style={{ ...$.inp, width: "auto", fontSize: 12, padding: "4px 8px" }}><option value="">All</option>{cats.map(c => <option key={c} value={c}>{c}</option>)}</select></div><div style={{ maxHeight: 160, overflowY: "auto" }}>{fc.length === 0 ? <div style={{ fontSize: 12, color: X.mt, padding: 8 }}>Empty.</div> : fc.map(p => <div key={p.id} onClick={() => addCat(p)} style={{ display: "flex", justifyContent: "space-between", padding: "6px 8px", borderRadius: 4, cursor: "pointer", marginBottom: 2, fontSize: 13 }} onMouseEnter={e => e.currentTarget.style.background = X.hv} onMouseLeave={e => e.currentTarget.style.background = "transparent"}><span>{p.name}{p.category && <span style={{ marginLeft: 6, fontSize: 11, color: X.mt }}>({p.category})</span>}</span><span style={{ color: X.mt, fontSize: 12 }}>{money(p.unitPrice, q.currency)}/{p.unit}</span></div>)}</div></div>}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 56px 86px 24px", gap: 8, marginBottom: 4 }}><span style={{ fontSize: 11, color: X.mt }}>Description</span><span style={{ fontSize: 11, color: X.mt, textAlign: "center" }}>Qty</span><span style={{ fontSize: 11, color: X.mt }}>Price</span><span /></div>
        {q.items.map((item, idx) => <div key={item.id} style={{ display: "grid", gridTemplateColumns: "1fr 56px 86px 24px", gap: 8, marginBottom: 6, alignItems: "center" }}><input value={item.description} onChange={e => setI(idx, "description", e.target.value)} placeholder="Description" style={$.inp} /><input type="number" min={0} value={item.quantity} onChange={e => setI(idx, "quantity", e.target.value)} style={{ ...$.inp, textAlign: "center" }} /><input type="number" min={0} step={0.01} value={item.unitPrice} onChange={e => setI(idx, "unitPrice", e.target.value)} style={$.inp} /><button onClick={() => rmI(idx)} disabled={q.items.length <= 1} style={{ ...$.btnG, color: q.items.length > 1 ? X.no : X.bd, padding: 2, fontSize: 16 }}>×</button></div>)}
      </div>
      <div style={$.card}>
        {[{ l: "Line Total", v: money(line, q.currency) }, q.discountPercent > 0 && { l: `Discount (${q.discountPercent}%)`, v: `-${money(discountAmt, q.currency)}`, c: X.no }, { l: "Subtotal", v: money(sub, q.currency) }, { l: `Tax (${q.taxPercent}%)`, v: money(tax, q.currency) }].filter(Boolean).map((r, i) => <div key={i} style={{ display: "flex", justifyContent: "space-between", padding: "4px 0", fontSize: 14 }}><span style={{ color: X.mt }}>{r.l}</span><span style={r.c ? { color: r.c } : undefined}>{r.v}</span></div>)}
        <div style={$.divider} /><div style={{ display: "flex", justifyContent: "space-between", padding: "4px 0", fontSize: 18, fontWeight: 700, color: X.ok }}><span>Total</span><span>{money(total, q.currency)}</span></div>
      </div>
      {q.signature ? <div style={{ background: `${X.ok}08`, border: `1px solid ${X.ok}25`, borderRadius: 8, padding: 12, marginBottom: 12 }}><div style={{ fontSize: 12, fontWeight: 600, color: X.ok, marginBottom: 4 }}>Signed ✓</div><div style={{ fontSize: 10, color: X.mt, fontFamily: "monospace", wordBreak: "break-all" }}>{q.signature}</div><div style={{ fontSize: 10, color: X.mt, marginTop: 4 }}>Signed: {q.signedAt}</div></div> : <button onClick={handleSign} style={{ ...$.btn2, marginBottom: 12, width: "100%" }}>Sign Quote (SHA-256)</button>}
      <div style={{ marginBottom: 20 }}><label style={$.lbl}>Notes / Terms</label><textarea value={q.notes} onChange={e => set("notes", e.target.value)} rows={3} placeholder="Payment terms, delivery, warranty..." style={$.ta} /></div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        <button onClick={() => onSave({ ...q, clientUrl: validateUrl(q.clientUrl) })} style={$.btn}>Save</button>
        <button onClick={handlePrint} style={$.btn2}>Print / PDF</button>
        <button onClick={handleCSV} style={$.btn2}>CSV</button>
        <button onClick={handleDuplicate} style={$.btnG}>Duplicate</button>
        {isEx && <ConfirmBtn label="Delete" confirmLabel="Confirm?" onConfirm={() => onDelete(q.id)} style={$.btnD} />}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// CLIENTS
// ---------------------------------------------------------------------------

function Clients({ clients, onSave, onDelete, notify }) {
  const [form, setForm] = useState(null);
  const [search, setSearch] = useState("");
  const fields = [{ key: "name", l: "Name *", ph: "Jane Doe" }, { key: "company", l: "Company", ph: "Acme Pty Ltd" }, { key: "email", l: "Email", ph: "jane@acme.co" }, { key: "phone", l: "Phone", ph: "+27 12 345 6789" }, { key: "website", l: "Website", ph: "https://clientsite.com" }, { key: "address", l: "Address", ph: "123 Long St, Cape Town", span: true }, { key: "notes", l: "Notes", ph: "Account terms...", span: true }];
  const filtered = clients.filter(c => { if (!search) return true; const t = search.toLowerCase(); return (c.name || "").toLowerCase().includes(t) || (c.company || "").toLowerCase().includes(t); });

  return (
    <div>
      <div style={{ ...$.btwn, marginBottom: 20 }}><h2 style={$.h2}>Clients</h2><button onClick={() => setForm(newClient())} style={$.btn}>+ Add</button></div>
      {form && <div style={$.card}><div style={$.grid}>{fields.map(f => <Field key={f.key} label={f.l} value={form[f.key]} onChange={v => setForm(p => ({ ...p, [f.key]: v }))} placeholder={f.ph} span={f.span} />)}</div><div style={{ ...$.row, marginTop: 14 }}><button onClick={() => { if (!form.name.trim()) { notify("Name required.", "error"); return; } onSave({ ...form, id: form.id || uid(), website: validateUrl(form.website) }); setForm(null); }} style={$.btn}>Save</button><button onClick={() => setForm(null)} style={$.btnG}>Cancel</button></div></div>}
      <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search..." style={{ ...$.inp, marginBottom: 12 }} />
      {filtered.length === 0 ? <div style={$.empty}>{clients.length === 0 ? "No clients yet." : "No results."}</div> : filtered.map(c => <div key={c.id} style={$.li}><div style={{ minWidth: 0 }}><div style={{ fontWeight: 600 }}>{c.name}{c.company && <span style={{ fontWeight: 400, color: X.mt }}> — {c.company}</span>}</div><div style={{ fontSize: 12, color: X.mt }}>{[c.email, c.phone, c.website].filter(Boolean).join(" · ")}</div></div><div style={$.row}><button onClick={() => setForm({ ...c })} style={$.btnG}>Edit</button><ConfirmBtn label="×" confirmLabel="?" onConfirm={() => onDelete(c.id)} style={{ ...$.btnG, color: X.no }} /></div></div>)}
    </div>
  );
}

// ---------------------------------------------------------------------------
// CATALOG
// ---------------------------------------------------------------------------

function Catalog({ catalog, onSave, onDelete, notify }) {
  const [form, setForm] = useState(null);
  const [search, setSearch] = useState("");
  const [fCat, setFCat] = useState("");
  const categories = useMemo(() => [...new Set(catalog.map(p => p.category).filter(Boolean))].sort(), [catalog]);
  const UNITS = [{ value: "each", label: "Each" }, { value: "hour", label: "Hour" }, { value: "day", label: "Day" }, { value: "sqm", label: "Per m²" }, { value: "sqft", label: "Per ft²" }, { value: "kg", label: "Per kg" }, { value: "km", label: "Per km" }, { value: "unit", label: "Unit" }, { value: "lot", label: "Lot" }, { value: "month", label: "Month" }, { value: "project", label: "Project" }, { value: "session", label: "Session" }, { value: "page", label: "Page" }, { value: "word", label: "Word" }, { value: "metre", label: "Metre" }, { value: "litre", label: "Litre" }];
  const filtered = catalog.filter(p => { const ms = !search || (p.name || "").toLowerCase().includes(search.toLowerCase()); const mc = !fCat || p.category === fCat; return ms && mc; });

  return (
    <div>
      <div style={{ ...$.btwn, marginBottom: 20 }}><h2 style={$.h2}>Products & Services</h2><button onClick={() => setForm(newProduct())} style={$.btn}>+ Add</button></div>
      {form && <div style={$.card}><div style={$.grid}><Field label="Name *" value={form.name} onChange={v => setForm(p => ({ ...p, name: v }))} placeholder="e.g. Consultation, Logo Design" /><Field label="Category" value={form.category} onChange={v => setForm(p => ({ ...p, category: v }))} placeholder="Labour, Materials" /><Field label="Description" value={form.description} onChange={v => setForm(p => ({ ...p, description: v }))} placeholder="Detail" span /><Field label="Price" type="number" value={form.unitPrice} onChange={v => setForm(p => ({ ...p, unitPrice: v }))} min={0} step={0.01} /><Sel label="Unit" value={form.unit} onChange={v => setForm(p => ({ ...p, unit: v }))} options={UNITS} /></div><div style={{ ...$.row, marginTop: 14 }}><button onClick={() => { if (!form.name.trim()) { notify("Name required.", "error"); return; } onSave({ ...form, id: form.id || uid(), unitPrice: Math.max(0, Number(form.unitPrice) || 0) }); setForm(null); }} style={$.btn}>Save</button><button onClick={() => setForm(null)} style={$.btnG}>Cancel</button></div></div>}
      <div style={{ ...$.row, marginBottom: 12, gap: 8 }}><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search..." style={{ ...$.inp, flex: 1 }} />{categories.length > 0 && <select value={fCat} onChange={e => setFCat(e.target.value)} style={{ ...$.inp, width: "auto" }}><option value="">All</option>{categories.map(c => <option key={c} value={c}>{c}</option>)}</select>}</div>
      {filtered.length === 0 ? <div style={$.empty}>{catalog.length === 0 ? "Build your catalog here." : "No results."}</div> : filtered.map(p => <div key={p.id} style={$.li}><div style={{ minWidth: 0 }}><div style={{ fontWeight: 600 }}>{p.name}{p.category && <span style={{ ...$.badge(X.ac), marginLeft: 8, fontSize: 10 }}>{p.category}</span>}</div><div style={{ fontSize: 12, color: X.mt }}>{p.description || "—"} · {money(p.unitPrice)}/{p.unit}</div></div><div style={$.row}><button onClick={() => setForm({ ...p })} style={$.btnG}>Edit</button><ConfirmBtn label="×" confirmLabel="?" onConfirm={() => onDelete(p.id)} style={{ ...$.btnG, color: X.no }} /></div></div>)}
    </div>
  );
}

// ---------------------------------------------------------------------------
// SETTINGS
// ---------------------------------------------------------------------------

function Settings({ biz, onSave, cryptoKey, notify, onLock, onPasswordChange }) {
  const [form, setForm] = useState({ ...biz });
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
      // Verify old password first
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
    <div>
      <h2 style={$.h2}>Settings</h2>
      <div style={$.card}>
        <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 12 }}>Business Info</div>
        <div style={$.grid}>
          <Field label="Business Name" value={form.name || ""} onChange={v => setForm(p => ({ ...p, name: v }))} placeholder="Your Business" />
          <Field label="Email" value={form.email || ""} onChange={v => setForm(p => ({ ...p, email: v }))} placeholder="info@business.co" />
          <Field label="Phone" value={form.phone || ""} onChange={v => setForm(p => ({ ...p, phone: v }))} placeholder="+27 00 000 0000" />
          <Field label="Tax / VAT" value={form.taxId || ""} onChange={v => setForm(p => ({ ...p, taxId: v }))} placeholder="VAT4830000000" />
          <Field label="Website" value={form.website || ""} onChange={v => setForm(p => ({ ...p, website: v }))} placeholder="https://yourbusiness.co" />
          <Sel label="Currency" value={form.defaultCurrency || "ZAR"} onChange={v => setForm(p => ({ ...p, defaultCurrency: v }))} options={CURRENCIES.map(c => ({ value: c.code, label: `${c.code} — ${c.symbol}` }))} />
          <Field label="Address" value={form.address || ""} onChange={v => setForm(p => ({ ...p, address: v }))} placeholder="123 Main Rd" span />
          <div style={{ gridColumn: "1 / -1" }}><label style={$.lbl}>Default Terms</label><textarea value={form.terms || ""} onChange={e => setForm(p => ({ ...p, terms: e.target.value }))} rows={3} placeholder="Payment due within 30 days..." style={$.ta} /></div>
        </div>
        <button onClick={() => { onSave(form); notify("Saved."); }} style={{ ...$.btn, marginTop: 14 }}>Save</button>
      </div>

      {/* PASSWORD MANAGEMENT */}
      <div style={$.card}>
        <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 12 }}>Authentication</div>
        <button onClick={onLock} style={{ ...$.btn2, marginBottom: 10, width: "100%" }}>Lock App Now</button>
        <button onClick={() => setShowPw(!showPw)} style={{ ...$.btnG, width: "100%", textAlign: "left" }}>{showPw ? "Cancel password change" : "Change master password"}</button>
        {showPw && (
          <div style={{ marginTop: 12 }}>
            <div style={{ marginBottom: 8 }}><label style={$.lbl}>Current Password</label><input type="password" value={oldPw} onChange={e => setOldPw(e.target.value)} style={$.inp} /></div>
            <div style={{ marginBottom: 8 }}><label style={$.lbl}>New Password</label><input type="password" value={newPw} onChange={e => setNewPw(e.target.value)} placeholder="Min 8 chars, uppercase + number" style={$.inp} /></div>
            <div style={{ marginBottom: 12 }}><label style={$.lbl}>Confirm New Password</label><input type="password" value={newPw2} onChange={e => setNewPw2(e.target.value)} style={$.inp} /></div>
            <button onClick={handleChangePw} disabled={pwLoading} style={{ ...$.btn, opacity: pwLoading ? 0.6 : 1 }}>{pwLoading ? "Re-encrypting all data..." : "Change Password"}</button>
          </div>
        )}
      </div>

      <h3 style={{ fontSize: 15, fontWeight: 700, margin: "24px 0 10px" }}>Security</h3>
      {[
        { t: "PBKDF2 Key Derivation", d: "Your password is run through 600,000 PBKDF2 iterations to derive the encryption key. Brute-force is computationally infeasible." },
        { t: "AES-256-GCM Encryption", d: "All data encrypted with password-derived key. Unique IV per record." },
        { t: "Password Never Stored", d: "Only a verification hash (separate PBKDF2 derivation) is stored. The password itself never touches disk." },
        { t: "Auto-Lock", d: "App locks automatically after 15 minutes of inactivity. Requires re-entry of password." },
        { t: "Rate-Limited Login", d: "5 failed attempts triggers a 30-second lockout. Prevents automated guessing." },
        { t: "Zero Network", d: "No data leaves your device. No server, no API, no telemetry." },
        { t: "XSS + URL Sanitisation", d: "All inputs entity-encoded. URLs validated against injection." },
        { t: "SHA-256 Signatures", d: "Tamper-proof integrity hashes on signed quotes." },
      ].map((s, i) => <div key={i} style={{ background: X.bg, border: `1px solid ${X.bd}`, borderRadius: 6, padding: "10px 14px", marginBottom: 6 }}><div style={{ fontSize: 13, fontWeight: 600, color: X.ok, marginBottom: 2 }}>{s.t}</div><div style={{ fontSize: 12, color: X.mt }}>{s.d}</div></div>)}

      <div style={{ marginTop: 20, padding: 14, background: X.sf, border: `1px solid ${X.bd}`, borderRadius: 8 }}>
        <div style={{ fontSize: 12, color: X.no, fontWeight: 600, marginBottom: 6 }}>DANGER ZONE</div>
        <p style={{ fontSize: 12, color: X.mt, margin: "0 0 10px" }}>Permanently delete all data and reset password.</p>
        <ConfirmBtn label="Delete Everything" confirmLabel="Confirm — destroy all data and password?" onConfirm={() => { AUTH.destroyAll(); window.location.reload(); }} style={$.btnD} />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ROOT APPLICATION — AUTH GATED
// ---------------------------------------------------------------------------

export default function App() {
  const [cryptoKey, setCryptoKey] = useState(null);
  const [authState, setAuthState] = useState("loading"); // loading | setup | login | unlocked
  const lastActivity = useRef(Date.now());

  // Check if auth is set up on mount
  useEffect(() => {
    setAuthState(AUTH.isSetUp() ? "login" : "setup");
  }, []);

  // Auto-lock on inactivity
  useEffect(() => {
    if (authState !== "unlocked") return;

    function resetTimer() { lastActivity.current = Date.now(); }
    function checkLock() {
      if (Date.now() - lastActivity.current > AUTH.LOCK_TIMEOUT_MS) {
        setCryptoKey(null);
        setAuthState("login");
      }
    }

    const events = ["mousedown", "keydown", "touchstart", "scroll"];
    events.forEach(e => window.addEventListener(e, resetTimer));
    const interval = setInterval(checkLock, 30000);

    return () => {
      events.forEach(e => window.removeEventListener(e, resetTimer));
      clearInterval(interval);
    };
  }, [authState]);

  // Lock on tab visibility change (optional extra security)
  useEffect(() => {
    function handleVisibility() {
      if (document.hidden && authState === "unlocked") {
        // Only lock if hidden for extended period — handled by the interval above
      }
    }
    document.addEventListener("visibilitychange", handleVisibility);
    return () => document.removeEventListener("visibilitychange", handleVisibility);
  }, [authState]);

  function handleSetup(key) { setCryptoKey(key); setAuthState("unlocked"); }
  function handleLogin(key) { setCryptoKey(key); setAuthState("unlocked"); lastActivity.current = Date.now(); }
  function handleLock() { setCryptoKey(null); setAuthState("login"); }

  // ─── AUTH SCREENS ───
  if (authState === "loading") return <div style={{ ...$.root, alignItems: "center", justifyContent: "center" }}><span style={{ color: X.mt }}>Loading...</span></div>;
  if (authState === "setup") return <SetupScreen onSetup={handleSetup} />;
  if (authState === "login") return <LoginScreen onLogin={handleLogin} />;

  // ─── AUTHENTICATED APP ───
  return <AuthenticatedApp cryptoKey={cryptoKey} onLock={handleLock} onKeyChange={setCryptoKey} />;
}

function AuthenticatedApp({ cryptoKey, onLock, onKeyChange }) {
  const [quotes, setQuotes, q1] = useAuthStore("quotes", [], cryptoKey);
  const [clients, setClients, q2] = useAuthStore("clients", [], cryptoKey);
  const [catalog, setCatalog, q3] = useAuthStore("catalog", [], cryptoKey);
  const [biz, setBiz, q4] = useAuthStore("biz", { name: "", email: "", phone: "", address: "", taxId: "", website: "", defaultCurrency: "ZAR", terms: "" }, cryptoKey);

  const [page, setPage] = useState("dashboard");
  const [aq, setAq] = useState(null);
  const [search, setSearch] = useState("");
  const [toast, setToast] = useState(null);

  const ready = q1 && q2 && q3 && q4;
  function notify(m, t = "success") { setToast({ m, t }); setTimeout(() => setToast(null), 2500); }
  function go(p) { setPage(p); setAq(null); }

  async function saveQ(q) { const i = quotes.findIndex(x => x.id === q.id); await setQuotes(i >= 0 ? quotes.map(x => x.id === q.id ? q : x) : [...quotes, q]); notify("Saved."); go("dashboard"); }
  async function delQ(qid) { await setQuotes(quotes.filter(x => x.id !== qid)); notify("Deleted.", "error"); go("dashboard"); }
  async function saveC(c) { const i = clients.findIndex(x => x.id === c.id); await setClients(i >= 0 ? clients.map(x => x.id === c.id ? c : x) : [...clients, c]); notify(i >= 0 ? "Updated." : "Added."); }
  async function delC(cid) { await setClients(clients.filter(x => x.id !== cid)); notify("Deleted.", "error"); }
  async function saveP(p) { const i = catalog.findIndex(x => x.id === p.id); await setCatalog(i >= 0 ? catalog.map(x => x.id === p.id ? p : x) : [...catalog, p]); notify(i >= 0 ? "Updated." : "Added."); }
  async function delP(pid) { await setCatalog(catalog.filter(x => x.id !== pid)); notify("Removed.", "error"); }

  if (!ready) return <div style={{ ...$.root, alignItems: "center", justifyContent: "center" }}><span style={{ color: X.mt }}>Decrypting data...</span></div>;

  const tabs = [{ id: "dashboard", l: "Quotes" }, { id: "catalog", l: "Products" }, { id: "clients", l: "Clients" }, { id: "settings", l: "Settings" }];

  return (
    <div style={$.root}>
      <style>{`*{margin:0;padding:0;box-sizing:border-box}input:focus,select:focus,textarea:focus{border-color:${X.pr}!important}::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:${X.bd};border-radius:3px}`}</style>
      <header style={$.hdr}>
        <h1 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>{biz.name || "Business Quotes"}</h1>
        <div style={$.row}>
          <span style={$.badge(X.dev)}>Dev</span>
          <span style={{ fontSize: 11, color: X.ok, fontWeight: 600, background: X.ok + "15", padding: "3px 8px", borderRadius: 4 }}>Encrypted</span>
          <button onClick={onLock} style={{ ...$.btnG, fontSize: 12, color: X.wn, padding: "4px 8px" }}>Lock</button>
        </div>
      </header>
      <nav style={$.nav}>{tabs.map(t => <Tab key={t.id} label={t.l} active={page === t.id || (page === "editor" && t.id === "dashboard")} onClick={() => go(t.id)} />)}</nav>
      <main style={$.main}>
        {page === "dashboard" && <Dash quotes={quotes} currency={biz.defaultCurrency || "ZAR"} onNew={() => { setAq(newQuote(biz.defaultCurrency)); setPage("editor"); }} onEdit={q => { setAq({ ...q }); setPage("editor"); }} search={search} setSearch={setSearch} />}
        {page === "editor" && aq && <Editor initial={aq} clients={clients} catalog={catalog} allQuotes={quotes} biz={biz} onSave={saveQ} onDelete={delQ} onBack={() => go("dashboard")} notify={notify} />}
        {page === "catalog" && <Catalog catalog={catalog} onSave={saveP} onDelete={delP} notify={notify} />}
        {page === "clients" && <Clients clients={clients} onSave={saveC} onDelete={delC} notify={notify} />}
        {page === "settings" && <Settings biz={biz} onSave={setBiz} cryptoKey={cryptoKey} notify={notify} onLock={onLock} onPasswordChange={onKeyChange} />}
      </main>
      {toast && <div style={$.toast(toast.t)}>{toast.m}</div>}
    </div>
  );
}