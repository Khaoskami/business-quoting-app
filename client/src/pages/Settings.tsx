import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../api';
import { authClient } from '../auth-client';
import { useToast } from '../components/Toast';
import { CURRENCIES, fmtDate } from '../lib/quote';

const TIERS = [
  { key: 'free',     name: 'Free',     price: 'Free forever', features: ['5 quotes/month', '3 clients', '10 catalog items', 'CSV export'] },
  { key: 'pro',      name: 'Pro',      price: '$9.99/mo',     features: ['50 quotes/month', '999 clients', 'Print/PDF', 'Discounts', 'Signatures'] },
  { key: 'business', name: 'Business', price: '$24.99/mo',    features: ['Unlimited quotes', 'Unlimited clients', 'All Pro features'] },
];

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
      if (out.length > 180_000) {
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
    mutationFn: () => api.profile.save(form),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['profile'] }); notify('Saved.'); },
    onError: (e: any) => notify(e.message ?? 'Save failed', 'error'),
  });

  const checkout = useMutation({
    mutationFn: (t: string) => api.billing.checkout(t),
    onSuccess: ({ url }) => { if (url) window.location.href = url; },
    onError: (e: any) => notify(e.message ?? 'Checkout failed', 'error'),
  });

  const portal = useMutation({
    mutationFn: () => api.billing.portal(),
    onSuccess: ({ url }) => { if (url) window.location.href = url; },
    onError: (e: any) => notify(e.message ?? 'Could not open portal', 'error'),
  });

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
                : t.key !== 'free' && (
                  <button className="btn btn--primary btn--sm" style={{ marginTop: 8 }}
                          onClick={() => checkout.mutate(t.key)}
                          disabled={checkout.isPending}>Upgrade</button>
                )}
            </div>
          ))}
        </div>
        {profile?.subscription?.currentPeriodEnd && (
          <div className="field-hint" style={{ marginTop: 12 }}>
            Renews {fmtDate(profile.subscription.currentPeriodEnd)}
            {profile?.subscription?.comped && ' (comped)'}
          </div>
        )}
        {tier !== 'free' && !profile?.subscription?.comped && (
          <button onClick={() => portal.mutate()} disabled={portal.isPending}
                  className="btn btn--secondary" style={{ marginTop: 12 }}>Manage billing</button>
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
              {CURRENCIES.map(c => <option key={c.code} value={c.code}>{c.code} — {c.symbol}</option>)}
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

      {hasOldLocalStorage() && (
        <>
          <h2 className="section-title">Import from old app</h2>
          <div className="card" style={{ marginBottom: 24 }}>
            <p style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)', marginBottom: 12 }}>
              We found data from a previous local-only version of the app on this device. Click to upload it to your account.
              Encrypted data cannot be migrated automatically — only plain-text records from before the auth update.
            </p>
            <button onClick={importFromLocalStorage} className="btn btn--secondary">Import</button>
          </div>
        </>
      )}
    </div>
  );
}
