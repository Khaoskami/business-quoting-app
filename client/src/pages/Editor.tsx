import { useState, useEffect, useMemo } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../api';
import { Icon } from '../components/Icons';
import { useToast } from '../components/Toast';
import {
  STATUSES, CURRENCIES, calcTotals, money, newQuote, uid,
  validateUrl, signQuote, buildPrintHtml, buildCsv,
} from '../lib/quote';

export default function Editor() {
  const { id } = useParams();
  const nav = useNavigate();
  const qc  = useQueryClient();
  const { notify } = useToast();
  const isNew = !id;

  const { data: quotes = [] } = useQuery({ queryKey: ['quotes'], queryFn: api.quotes.list });
  const { data: clients = [] } = useQuery({ queryKey: ['clients'], queryFn: api.clients.list });
  const { data: catalog = [] } = useQuery({ queryKey: ['catalog'], queryFn: api.catalog.list });
  const { data: profile }      = useQuery({ queryKey: ['profile'], queryFn: api.profile.get });
  const biz   = profile?.profile ?? {};
  const tier  = profile?.subscription?.tier ?? 'free';
  const tf    = profile?.subscription?.limits?.features ?? { discount: false, print: false, csv: true, signature: false, clientUrl: false, duplicate: false };

  const existing = !isNew ? quotes.find((q: any) => q.id === id) : null;
  const [q, setQ] = useState<any>(() => isNew ? newQuote(biz.defaultCurrency) : { ...existing });
  const [showCat, setShowCat] = useState(false);

  // Once existing loads, populate state
  useEffect(() => {
    if (!isNew && existing && !q.title && !q.id) setQ({ ...existing });
    if (!isNew && existing && q.id !== existing.id) setQ({ ...existing });
  }, [existing, isNew]);

  const { line, discountAmt, sub, tax, total } = calcTotals(q.items ?? [], q.taxPercent ?? 0, q.discountPercent ?? 0);

  const save = useMutation({
    mutationFn: (data: any) => isNew ? api.quotes.create(data) : api.quotes.update(id!, data),
    onSuccess: (saved) => {
      qc.invalidateQueries({ queryKey: ['quotes'] });
      notify('Saved.');
      if (isNew && saved?.id) nav(`/quotes/${saved.id}/edit`, { replace: true });
    },
    onError: (e: any) => notify(e.message ?? 'Save failed', 'error'),
  });

  const del = useMutation({
    mutationFn: () => api.quotes.delete(id!),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['quotes'] }); notify('Deleted.', 'error'); nav('/quotes'); },
  });

  function set(f: string, v: any) { setQ((p: any) => ({ ...p, [f]: v })); }
  function setI(idx: number, f: string, v: any) {
    setQ((p: any) => {
      const it = [...p.items];
      const value = (f === 'quantity' || f === 'unitPrice') ? Math.max(0, Number(v) || 0) : v;
      it[idx] = { ...it[idx], [f]: value };
      return { ...p, items: it };
    });
  }
  function addBlank() { setQ((p: any) => ({ ...p, items: [...p.items, { id: uid(), description: '', quantity: 1, unitPrice: 0, catalogId: '' }] })); }
  function addCat(pr: any) {
    setQ((p: any) => ({ ...p, items: [...p.items, { id: uid(), description: pr.name + (pr.description ? ` — ${pr.description}` : ''), quantity: 1, unitPrice: pr.unitPrice, catalogId: pr.id }] }));
    setShowCat(false);
  }
  function rmI(idx: number) { if (q.items.length > 1) setQ((p: any) => ({ ...p, items: p.items.filter((_: any, i: number) => i !== idx) })); }

  function handlePrint() {
    const html = buildPrintHtml(q, biz);
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const w = window.open(url, '_blank');
    if (w) w.addEventListener('load', () => URL.revokeObjectURL(url), { once: true });
  }
  function handleCSV() {
    const blob = new Blob([buildCsv(q, biz)], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: `${q.quoteNumber || q.title || 'quote'}.csv` });
    a.click(); URL.revokeObjectURL(url); notify('CSV exported.');
  }

  const cats = useMemo(() => [...new Set(catalog.map((p: any) => p.category).filter(Boolean))], [catalog]);
  const [catF, setCatF] = useState('');
  const fc = catalog.filter((p: any) => !catF || p.category === catF);

  if (!isNew && !existing) {
    return <div className="page-enter"><p>Loading quote…</p></div>;
  }

  return (
    <div className="page-enter">
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <Link to="/quotes" className="btn btn--ghost btn--sm" aria-label="Back"><Icon.back /></Link>
          <h1 className="page-title">{isNew ? 'New Quote' : 'Edit Quote'}</h1>
        </div>
      </div>

      <div className="editor-shell">
        <div className="editor-main">
          <div className="card">
            <div className="form-grid">
              <div className="field-group field-group--span">
                <label className="field-label" htmlFor="title">Quote Title</label>
                <input id="title" className="field-input" value={q.title} onChange={(e) => set('title', e.target.value)} placeholder="e.g. Roof Repair" />
              </div>
              <div className="field-group">
                <label className="field-label" htmlFor="qnum">Quote Number</label>
                <input id="qnum" className="field-input" value={q.quoteNumber || (isNew ? 'Assigned on save' : '—')} readOnly disabled />
              </div>
              <div className="field-group">
                <label className="field-label" htmlFor="client">Client</label>
                <select id="client" className="field-select" value={q.clientId}
                        onChange={(e) => {
                          const c = clients.find((x: any) => x.id === e.target.value);
                          set('clientId', e.target.value);
                          set('clientName', c?.name ?? '');
                          set('clientUrl', c?.website ?? '');
                        }}>
                  <option value="">— Select —</option>
                  {clients.map((c: any) => <option key={c.id} value={c.id}>{c.name}{c.company ? ` (${c.company})` : ''}</option>)}
                </select>
              </div>
              <div className="field-group">
                <label className="field-label" htmlFor="status">Status</label>
                <select id="status" className="field-select" value={q.status} onChange={(e) => set('status', e.target.value)}>
                  {Object.entries(STATUSES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                </select>
              </div>
              <div className="field-group">
                <label className="field-label" htmlFor="currency">Currency</label>
                <select id="currency" className="field-select" value={q.currency} onChange={(e) => set('currency', e.target.value)}>
                  {CURRENCIES.map(c => <option key={c.code} value={c.code}>{c.code} ({c.symbol})</option>)}
                </select>
              </div>
              <div className="field-group">
                <label className="field-label" htmlFor="tax">Tax %</label>
                <input id="tax" type="number" min={0} max={100} className="field-input"
                       value={q.taxPercent} onChange={(e) => set('taxPercent', Math.min(100, Math.max(0, Number(e.target.value) || 0)))} />
              </div>
              {tf.discount ? (
                <div className="field-group">
                  <label className="field-label" htmlFor="disc">Discount %</label>
                  <input id="disc" type="number" min={0} max={100} className="field-input"
                         value={q.discountPercent} onChange={(e) => set('discountPercent', Math.min(100, Math.max(0, Number(e.target.value) || 0)))} />
                </div>
              ) : (
                <div className="field-group"><label className="field-label">Discount %</label><div className="field-hint" style={{ padding: '10px 0' }}>Pro feature</div></div>
              )}
              <div className="field-group">
                <label className="field-label" htmlFor="valid">Valid (days)</label>
                <input id="valid" type="number" min={1} className="field-input"
                       value={q.validityDays} onChange={(e) => set('validityDays', Math.max(1, Number(e.target.value) || 1))} />
              </div>
              {tf.clientUrl ? (
                <div className="field-group field-group--span">
                  <label className="field-label" htmlFor="clientUrl">Client Website</label>
                  <input id="clientUrl" className="field-input" value={q.clientUrl} onChange={(e) => set('clientUrl', e.target.value)} placeholder="https://clientsite.com" />
                </div>
              ) : (
                <div className="field-group field-group--span"><label className="field-label">Client Website</label><div className="field-hint" style={{ padding: '10px 0' }}>Pro feature</div></div>
              )}
            </div>
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span className="field-label">Line Items</span>
              <div style={{ display: 'flex', gap: 6 }}>
                {catalog.length > 0 && <button onClick={() => setShowCat(!showCat)} className="btn btn--ghost btn--sm">{showCat ? 'Close' : 'From catalog'}</button>}
                <button onClick={addBlank} className="btn btn--secondary btn--sm"><Icon.plus /> Item</button>
              </div>
            </div>

            {showCat && (
              <div className="card" style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                  <span className="field-label">Catalog</span>
                  <select value={catF} onChange={(e) => setCatF(e.target.value)} className="field-select" style={{ width: 'auto', minHeight: 30, padding: '4px 8px', fontSize: 12 }}>
                    <option value="">All</option>
                    {cats.map((c: any) => <option key={c} value={c}>{c}</option>)}
                  </select>
                </div>
                {fc.length === 0
                  ? <div className="field-hint">Empty.</div>
                  : fc.map((p: any) => (
                    <div key={p.id} onClick={() => addCat(p)} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 8px', borderRadius: 4, cursor: 'pointer', fontSize: 13 }}>
                      <span>{p.name}{p.category ? ` (${p.category})` : ''}</span>
                      <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{money(p.unitPrice, q.currency)}/{p.unit}</span>
                    </div>
                  ))}
              </div>
            )}

            <div className="line-items">
              <div className="line-items-header">
                <span>Description</span><span style={{ textAlign: 'center' }}>Qty</span><span>Unit Price</span><span style={{ textAlign: 'right' }}>Total</span><span />
              </div>
              {q.items.map((item: any, idx: number) => (
                <div key={item.id} className="line-items-row">
                  <input className="li-input" value={item.description} onChange={(e) => setI(idx, 'description', e.target.value)} placeholder="Description" aria-label="Description" />
                  <input className="li-input li-input--num" type="number" min={0} value={item.quantity} onChange={(e) => setI(idx, 'quantity', e.target.value)} aria-label="Quantity" />
                  <input className="li-input li-input--num" type="number" min={0} step={0.01} value={item.unitPrice} onChange={(e) => setI(idx, 'unitPrice', e.target.value)} aria-label="Unit price" />
                  <div className="li-total">{money(item.quantity * item.unitPrice, q.currency)}</div>
                  <button className="li-remove" onClick={() => rmI(idx)} disabled={q.items.length <= 1} aria-label="Remove item">×</button>
                </div>
              ))}
            </div>
          </div>

          <div className="field-group">
            <label className="field-label" htmlFor="notes">Notes / Terms</label>
            <textarea id="notes" className="field-textarea" rows={4} value={q.notes}
                      onChange={(e) => set('notes', e.target.value)} placeholder="Payment terms, delivery, warranty..." />
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
              <div style={{ background: 'var(--success-bg)', border: '1px solid var(--success)', borderRadius: 'var(--radius)', padding: 10 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--success)' }}>Signed ✓</div>
                <div style={{ fontSize: 10, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', marginTop: 4 }}>{q.signature.slice(0, 32)}…</div>
              </div>
            ) : tf.signature ? (
              <button className="btn btn--secondary btn--full"
                      onClick={async () => {
                        const sig = await signQuote(q, biz);
                        setQ((p: any) => ({ ...p, signature: sig, signedAt: new Date().toISOString() }));
                        notify('Signed.');
                      }}>Sign Quote (SHA-256)</button>
            ) : null}

            <button onClick={() => save.mutate({ ...q, clientUrl: validateUrl(q.clientUrl) })}
                    disabled={save.isPending}
                    className={`btn btn--primary btn--full ${save.isPending ? 'btn--loading' : ''}`}>Save</button>

            <div className="action-bar">
              {tf.print
                ? <button onClick={handlePrint} className="btn btn--secondary">Print / PDF</button>
                : <button disabled className="btn btn--secondary">Print (Pro)</button>}
              <button onClick={handleCSV} className="btn btn--secondary">CSV</button>
              {tf.duplicate && !isNew && (
                <button onClick={() => save.mutate({ ...q, quoteNumber: '', status: 'draft', signature: '', signedAt: '', title: (q.title ?? '') + ' (copy)' })} className="btn btn--ghost">Duplicate</button>
              )}
            </div>
            {!isNew && (
              <button onClick={() => { if (confirm('Delete this quote?')) del.mutate(); }} className="btn btn--danger btn--full">Delete Quote</button>
            )}
          </div>
        </aside>
      </div>
    </div>
  );
}
