import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../api';
import { authClient } from '../auth-client';
import { useToast } from '../components/Toast';
import { CURRENCIES, fmtDate } from '../lib/quote';
import { PRICING } from '../../../shared/pricing';

const TIERS = [
  { key: 'free', name: PRICING.free.name, price: `${PRICING.free.priceLabel} forever`, features: ['5 quotes/month', '3 clients', '10 catalog items', '10 client emails/month', 'PDF + online quote links'] },
  { key: 'pro', name: PRICING.pro.name, price: `${PRICING.pro.priceLabel}/mo`, features: ['300 quotes/month', '250 clients', '400 client emails/month', 'Automated reminders', 'Client portal + e-signature', '5 team members'] },
  { key: 'business', name: PRICING.business.name, price: `${PRICING.business.priceLabel}/mo`, features: ['Unlimited quotes, clients & catalog', '2,000 client emails/month', 'Custom reminder schedules', 'All Growth workflow features', 'Higher-volume client communication'] },
];

const REMINDER_OPTIONS = [
  { value: 7, label: '7 days before' },
  { value: 3, label: '3 days before' },
  { value: 0, label: 'Due today' },
  { value: -3, label: '3 days overdue' },
  { value: -7, label: '7 days overdue' },
  { value: -14, label: '14 days overdue' },
  { value: -30, label: '30 days overdue' },
];
const DEFAULT_REMINDERS = [3, 0, -3, -14];

function hasOldLocalStorage() {
  try { return Object.keys(localStorage).some(k => k.startsWith('bq_')); }
  catch { return false; }
}

export default function Settings() {
  const qc = useQueryClient();
  const { notify } = useToast();
  const { data: profile, refetch } = useQuery({ queryKey: ['profile'], queryFn: api.profile.get });
  const tier = profile?.subscription?.tier ?? 'free';

  const [form, setForm] = useState<any>(profile?.profile ?? {});
  useEffect(() => { if (profile?.profile) setForm(profile.profile); }, [profile?.profile]);

  const [pw, setPw] = useState({ current: '', next: '', confirm: '' });
  const emailStatus = profile?.email;
  const emailSettings = form?.emailSettings ?? {};
  const autoReminders = emailSettings.autoReminders ?? tier !== 'free';
  const reminderDays: number[] = Array.isArray(emailSettings.reminderDays) && emailSettings.reminderDays.length ? emailSettings.reminderDays : DEFAULT_REMINDERS;
  const [pwBusy, setPwBusy] = useState(false);

  async function handleLogoFile(file: File) {
    if (!file.type.startsWith('image/')) {
      notify('Please choose an image file.', 'error');
      return;
    }
    try {
      const dataUrl = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result as string);
        reader.onerror = () => reject(reader.error);
        reader.readAsDataURL(file);
      });
      const img = new Image();
      img.src = dataUrl;
      await img.decode();
      const scale = Math.min(1, 480 / img.width);
      const canvas = document.createElement('canvas');
      canvas.width = Math.round(img.width * scale);
      canvas.height = Math.round(img.height * scale);
      const ctx = canvas.getContext('2d');
      if (!ctx) {
        notify('Could not process image.', 'error');
        return;
      }
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      const out = canvas.toDataURL('image/png');
      if (out.length > 1_400_000) {
        notify('Logo is too large after resizing. Please use a simpler image.', 'error');
        return;
      }
      setForm({ ...form, logo: out });
    } catch {
      notify('Could not read that image.', 'error');
    }
  }

  async function changePassword() {
    if (pw.next.length < 8) {
      notify('New password must be at least 8 characters.', 'error');
      return;
    }
    if (pw.next !== pw.confirm) {
      notify('New passwords do not match.', 'error');
      return;
    }
    setPwBusy(true);
    try {
      const { error } = await authClient.changePassword({
        currentPassword: pw.current,
        newPassword: pw.next,
        revokeOtherSessions: true,
      });
      if (error) {
        notify(error.message ?? 'Could not change password.', 'error');
        return;
      }
      setPw({ current: '', next: '', confirm: '' });
      notify('Password changed.');
    } catch (e: any) {
      notify(e?.message ?? 'Could not change password.', 'error');
    } finally {
      setPwBusy(false);
    }
  }

  // Handle billing return banner
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    if (params.get('billing') === 'success') {
      notify('Payment received. Refreshing your plan…');
      setTimeout(() => refetch(), 1500);
    } else if (params.get('billing') === 'cancelled') {
      notify('Checkout cancelled.', 'warning');
    }
  }, []);

  const saveProfile = useMutation({
    mutationFn: () => api.profile.save({ ...form, emailSettings }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['profile'] }); notify('Saved.'); },
    onError: (e: any) => notify(e.message ?? 'Save failed', 'error'),
  });

  const checkout = useMutation({
    mutationFn: (t: string) => api.billing.checkout(t),
    onSuccess: ({ url }) => { if (url) window.location.href = url; },
    onError: (e: any) => notify(e.message ?? 'Checkout failed', 'error'),
  });

  const cancel = useMutation({
    mutationFn: () => api.billing.cancel(),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['profile'] }); notify('Subscription cancelled.'); },
    onError: (e: any) => notify(e.message ?? 'Could not cancel subscription', 'error'),
  });

  async function exportAccountData() {
    try {
      const { blob, disposition } = await api.profile.export();
      const match = disposition?.match(/filename=([^;]+)/i);
      const filename = match?.[1]?.replace(/^"|"$/g, '') || `business-quotes-export-${new Date().toISOString().slice(0, 10)}.json`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename; a.click();
      URL.revokeObjectURL(url);
      notify('Account export downloaded.');
    } catch (e: any) { notify(e?.message ?? 'Could not export account data.', 'error'); }
  }

  async function importFromLocalStorage() {
    const prefix = 'bq_';
    const keys = ['quotes', 'clients', 'catalog', 'biz'];
    const results: Record<string, any> = {};
    for (const key of keys) {
      try {
        const raw = localStorage.getItem(prefix + key);
        if (raw) results[key] = JSON.parse(raw);
      } catch {}
    }

    if (!results.quotes?.length && !results.clients?.length && !results.catalog?.length) {
      notify('No importable data found. Encrypted data cannot be migrated automatically.', 'error');
      return;
    }

    try {
      for (const q of results.quotes ?? [])  await api.quotes.create(q);
      for (const c of results.clients ?? []) await api.clients.create(c);
      for (const p of results.catalog ?? []) await api.catalog.create(p);
      if (results.biz) await api.profile.save(results.biz);
      notify(`Imported ${results.quotes?.length ?? 0} quotes, ${results.clients?.length ?? 0} clients, ${results.catalog?.length ?? 0} items.`);
      qc.invalidateQueries();
    } catch (e: any) {
      notify(e.message ?? 'Import failed partway. Some records may have been saved.', 'error');
      qc.invalidateQueries();
    }
  }

  return (
    <div className="page-enter">
      <div className="page-header"><h1 className="page-title">Settings</h1></div>

      <h2 className="section-title">Your Plan</h2>
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="tier-grid">
          {TIERS.map(t => (
            <div key={t.key} className={`tier-card ${tier === t.key ? 'active' : ''}`}>
              <h4>{t.name}</h4>
              <div className="price">{t.price}</div>
              <ul>{t.features.map(f => <li key={f}>✓ {f}</li>)}</ul>
              {tier === t.key
                ? <span className="field-hint" style={{ marginTop: 8 }}>Current plan</span>
                : ((tier === 'free' && t.key !== 'free') || (tier === 'pro' && t.key === 'business')) && (
                  <button className="btn btn--primary btn--sm" style={{ marginTop: 8 }}
                          onClick={() => checkout.mutate(t.key)}
                          disabled={checkout.isPending}>Get {t.name}</button>
                )}
            </div>
          ))}
        </div>
        <div className="field-hint" style={{ marginTop: 12 }}>
          {profile?.subscription?.comped ? 'Comped account.' : profile?.subscription?.billingAmountMinor && Number(profile.subscription.billingAmountMinor) !== Number((PRICING as any)[tier]?.price ?? 0) * 100
            ? `Current billing: R${(Number(profile.subscription.billingAmountMinor) / 100).toLocaleString('en-ZA', { minimumFractionDigits: 0 })}/mo (grandfathered rate)`
            : tier === 'free' ? 'No credit card required.' : `Current price: ${(PRICING as any)[tier]?.priceLabel}/month.`}
          {profile?.subscription?.currentPeriodEnd && ` · Renews ${fmtDate(profile.subscription.currentPeriodEnd)}`}
        </div>
        {tier !== 'free' && !profile?.subscription?.comped && (
          <>
            <button onClick={() => { if (confirm('Cancel your subscription? You keep your paid plan until the end of the period you have already paid for, then revert to Free.')) cancel.mutate(); }}
                    disabled={cancel.isPending}
                    className="btn btn--secondary" style={{ marginTop: 12 }}>Cancel subscription</button>
            <div className="field-hint" style={{ marginTop: 6 }}>
              Cancelling stops future billing. Your paid features stay active until the end of the current billing period.
            </div>
          </>
        )}
      </div>

      <h2 className="section-title">Business Info</h2>
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="form-grid">
          <div className="field-group"><label className="field-label">Business Name</label>
            <input className="field-input" value={form.name ?? ''} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
          <div className="field-group"><label className="field-label">Email</label>
            <input className="field-input" value={form.email ?? ''} onChange={(e) => setForm({ ...form, email: e.target.value })} /></div>
          <div className="field-group"><label className="field-label">Phone</label>
            <input className="field-input" value={form.phone ?? ''} onChange={(e) => setForm({ ...form, phone: e.target.value })} /></div>
          <div className="field-group"><label className="field-label">Tax / VAT</label>
            <input className="field-input" value={form.taxId ?? ''} onChange={(e) => setForm({ ...form, taxId: e.target.value })} /></div>
          <div className="field-group"><label className="field-label">Website</label>
            <input className="field-input" value={form.website ?? ''} onChange={(e) => setForm({ ...form, website: e.target.value })} /></div>
          <div className="field-group"><label className="field-label">Currency</label>
            <select className="field-select" value={form.defaultCurrency ?? 'ZAR'} onChange={(e) => setForm({ ...form, defaultCurrency: e.target.value })}>
              {CURRENCIES.map(c => <option key={c.code} value={c.code}>{c.code} · {c.symbol}</option>)}
            </select>
          </div>
          <div className="field-group field-group--span"><label className="field-label">Address</label>
            <input className="field-input" value={form.address ?? ''} onChange={(e) => setForm({ ...form, address: e.target.value })} /></div>
          <div className="field-group field-group--span"><label className="field-label">Default Terms</label>
            <textarea className="field-textarea" rows={3} value={form.terms ?? ''} onChange={(e) => setForm({ ...form, terms: e.target.value })} /></div>
          <div className="field-group field-group--span"><label className="field-label">Logo</label>
            {form.logo && <img src={form.logo} alt="Business logo" style={{ maxHeight: 64, marginBottom: 8, display: 'block' }} />}
            <input className="field-input" type="file" accept="image/png,image/jpeg"
                   onChange={(e) => { const f = e.target.files?.[0]; if (f) handleLogoFile(f); e.target.value = ''; }} />
            {form.logo && (
              <button type="button" className="btn btn--ghost btn--sm" style={{ marginTop: 8 }}
                      onClick={() => setForm({ ...form, logo: '' })}>Remove logo</button>
            )}
            <div className="field-hint">Shown on quote and invoice printouts. PNG or JPEG, resized to 480px wide.</div>
          </div>
        </div>
        <button onClick={() => saveProfile.mutate()} disabled={saveProfile.isPending}
                className={`btn btn--primary ${saveProfile.isPending ? 'btn--loading' : ''}`} style={{ marginTop: 14 }}>Save</button>
      </div>

      <h2 className="section-title">Email &amp; reminders</h2>
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="settings-callout">
          <div>
            <div style={{ fontWeight: 600 }}>Client communication</div>
            <div className="field-hint" style={{ marginTop: 4 }}>
              Verification and password-reset emails are system emails and do not use your client-email allowance. Quote sends, invoice sends, reminders, and direct client messages use your monthly client-email credits.
            </div>
          </div>
          <div className={`status-pill ${emailStatus?.configured ? 'status-pill--success' : 'status-pill--warning'}`}>
            {emailStatus?.configured ? 'Email delivery connected' : 'Email delivery not configured'}
          </div>
        </div>
        <div className="email-usage-card">
          <div><strong>{emailStatus?.usedThisMonth ?? 0}</strong><span>client emails used this month</span></div>
          <div><strong>{emailStatus?.monthlyClientLimit == null ? '∞' : (emailStatus?.monthlyClientLimit ?? 0)}</strong><span>included on your plan</span></div>
          <div><strong>{emailStatus?.monthlyClientLimit == null ? '∞' : Math.max(0, (emailStatus?.monthlyClientLimit ?? 0) - (emailStatus?.usedThisMonth ?? 0))}</strong><span>remaining</span></div>
        </div>
        {!emailStatus?.configured && <div className="info-banner" style={{ marginTop: 12 }}>Set RESEND_API_KEY and EMAIL_FROM in Railway, then verify your sending domain with Resend. Authentication email delivery works without adding email credentials to each customer account.</div>}

        <div className="reminder-settings" style={{ marginTop: 18 }}>
          <div className="field-group">
            <label className="field-label">Automatic invoice reminders</label>
            {tier === 'free' ? (
              <div className="locked-feature">Available on Growth. Upgrade to automate due-date and overdue reminders.</div>
            ) : (
              <label className="switch-row"><input type="checkbox" checked={Boolean(autoReminders)} onChange={(e) => setForm({ ...form, emailSettings: { ...emailSettings, autoReminders: e.target.checked } })} /><span>Automatically email clients about upcoming and overdue invoices</span></label>
            )}
          </div>

          {tier === 'business' ? (
            <div className="field-group" style={{ marginTop: 16 }}>
              <label className="field-label">Reminder schedule</label>
              <div className="reminder-options">
                {REMINDER_OPTIONS.map((option) => (
                  <label key={option.value} className="check-option"><input type="checkbox" checked={reminderDays.includes(option.value)} onChange={(e) => { const next = e.target.checked ? [...new Set([...reminderDays, option.value])] : reminderDays.filter((d) => d !== option.value); setForm({ ...form, emailSettings: { ...emailSettings, reminderDays: next } }); }} /><span>{option.label}</span></label>
                ))}
              </div>
              <div className="field-hint" style={{ marginTop: 8 }}>Business can tailor the schedule. Growth uses the included workflow: 3 days before, due today, 3 days overdue, and 14 days overdue.</div>
            </div>
          ) : tier === 'pro' ? (
            <div className="field-hint" style={{ marginTop: 14 }}>Growth includes automatic reminders on the standard 3 / 0 / -3 / -14 day schedule.</div>
          ) : null}
        </div>

        <button onClick={() => saveProfile.mutate()} disabled={saveProfile.isPending} className="btn btn--primary" style={{ marginTop: 16 }}>Save email settings</button>
      </div>

      <h2 className="section-title">Change Password</h2>
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="form-grid">
          <div className="field-group field-group--span"><label className="field-label">Current Password</label>
            <input className="field-input" type="password" autoComplete="current-password"
                   value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} /></div>
          <div className="field-group"><label className="field-label">New Password</label>
            <input className="field-input" type="password" autoComplete="new-password"
                   value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} /></div>
          <div className="field-group"><label className="field-label">Confirm New Password</label>
            <input className="field-input" type="password" autoComplete="new-password"
                   value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} /></div>
        </div>
        <div className="field-hint" style={{ marginTop: 10 }}>
          Must be at least 8 characters. Changing it signs out your other sessions.
        </div>
        <button onClick={changePassword} disabled={pwBusy}
                className={`btn btn--primary ${pwBusy ? 'btn--loading' : ''}`} style={{ marginTop: 14 }}>Update password</button>
      </div>

      <h2 className="section-title">Your Data</h2>
      <div className="card" style={{ marginBottom: 24 }}>
        <div style={{ fontWeight: 500 }}>Export account data</div>
        <div className="field-hint" style={{ marginTop: 4 }}>Download your business profile, quotes, invoices, payment records, clients, and catalog as JSON.</div>
        <button className="btn btn--secondary" style={{ marginTop: 12 }} onClick={exportAccountData}>Export JSON</button>
      </div>

      <h2 className="section-title">Support &amp; Legal</h2>
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="support-row">
          <div>
            <div style={{ fontWeight: 500 }}>Need help?</div>
            <div className="field-hint" style={{ marginTop: 2 }}>
              Billing questions, refunds, or anything not working · message us on WhatsApp.
            </div>
          </div>
          <a className="btn btn--whatsapp" href="https://wa.me/27832001798" target="_blank" rel="noopener"
             aria-label="Contact support on WhatsApp at +27 83 200 1798">
            WhatsApp support
          </a>
        </div>
        <div className="field-hint" style={{ marginTop: 14 }}>
          <a href="/terms.html" target="_blank" rel="noopener">Terms &amp; Conditions</a>
          {' · '}
          <a href="/privacy-policy.html" target="_blank" rel="noopener">Privacy Policy</a>
          {' · '}Payments processed by PayFast
        </div>
      </div>

      {hasOldLocalStorage() && (
        <>
          <h2 className="section-title">Import from old app</h2>
          <div className="card" style={{ marginBottom: 24 }}>
            <p style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)', marginBottom: 12 }}>
              We found data from a previous local-only version of the app on this device. Click to upload it to your account.
              Encrypted data cannot be migrated automatically · only plain-text records from before the auth update.
            </p>
            <button onClick={importFromLocalStorage} className="btn btn--secondary">Import</button>
          </div>
        </>
      )}
    </div>
  );
}
