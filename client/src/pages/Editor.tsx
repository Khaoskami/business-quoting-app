import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api';
import { Icon } from '../components/Icons';
import { useToast } from '../components/Toast';
import { CURRENCIES, STATUSES, calcTotals, money, newQuote, uid, validateUrl, buildCsv, buildPrintHtml } from '../lib/quote';

export default function Editor() {
  const { id } = useParams();
  const nav = useNavigate();
  const qc = useQueryClient();
  const { notify } = useToast();
  const isNew = !id;
  const { data: quotes = [], isLoading } = useQuery({ queryKey: ['quotes'], queryFn: api.quotes.list });
  const { data: clients = [] } = useQuery({ queryKey: ['clients'], queryFn: api.clients.list });
  const { data: catalog = [] } = useQuery({ queryKey: ['catalog'], queryFn: api.catalog.list });
  const { data: profile } = useQuery({ queryKey: ['profile'], queryFn: api.profile.get });
  const biz = profile?.profile ?? {};
  const tf = profile?.subscription?.limits?.features ?? {};
  const existing = !isNew ? quotes.find((x: any) => x.id === id) : undefined;
  const [q, setQ] = useState<any>(() => isNew ? newQuote(biz.defaultCurrency) : existing);
  const [catOpen, setCatOpen] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [sendResult, setSendResult] = useState('');
  const [historyOpen, setHistoryOpen] = useState(false);
  const { data: history = [] } = useQuery({ queryKey: ['quote-events', q?.id], queryFn: () => api.quotes.events(q.id), enabled: Boolean(q?.id) });
  const [catFilter, setCatFilter] = useState('');

  useEffect(() => { if (!isNew && existing) setQ(existing); }, [id, isNew, existing]);
  useEffect(() => { if (isNew && biz.defaultCurrency && !q?.id) setQ((p: any) => ({ ...p, currency: biz.defaultCurrency })); }, [biz.defaultCurrency]);

  const totals = useMemo(() => calcTotals(q?.items ?? [], q?.taxPercent ?? 0, q?.discountPercent ?? 0, q?.currency ?? 'ZAR'), [q]);
  const deleted = Boolean(q?.deletedAt);
  const locked = q?.status === 'accepted' || deleted;

  const save = useMutation({
    mutationFn: () => isNew ? api.quotes.create(q) : api.quotes.update(id!, q),
    onSuccess: (saved) => { setQ(saved); qc.invalidateQueries({ queryKey: ['quotes'] }); notify('Saved.'); if (isNew && saved?.id) nav(`/quotes/${saved.id}/edit`, { replace: true }); },
    onError: (e: any) => notify(e.message ?? 'Save failed', 'error'),
  });
  const send = useMutation({
    mutationFn: () => api.quotes.send(q.id),
    onSuccess: (res) => { setSendResult(res.url); qc.invalidateQueries({ queryKey: ['quotes'] }); notify('Quote link created and email queued.'); },
    onError: (e: any) => notify(e.message ?? 'Send failed', 'error'),
  });
  const accept = useMutation({
    mutationFn: () => api.quotes.accept(q.id),
    onSuccess: (res) => { setConfirmOpen(false); qc.invalidateQueries({ queryKey: ['quotes'] }); qc.invalidateQueries({ queryKey: ['invoices'] }); notify(res.invoice ? `Invoice ${res.invoice.invoiceNumber} issued.` : 'Quote accepted.'); },
    onError: (e: any) => notify(e.message ?? 'Accept failed', 'error'),
  });
  const duplicate = useMutation({
    mutationFn: () => api.quotes.duplicate(q.id),
    onSuccess: (copy) => { notify('Quote duplicated.'); nav(`/quotes/${copy.id}/edit`); },
    onError: (e: any) => notify(e.message ?? 'Could not duplicate quote.', 'error'),
  });

  const restore = useMutation({ mutationFn: () => api.quotes.restore(q.id), onSuccess: () => { qc.invalidateQueries({ queryKey: ['quotes'] }); notify('Quote restored.'); }, onError: (e: any) => notify(e.message ?? 'Restore failed', 'error') });

  const del = useMutation({
    mutationFn: () => api.quotes.delete(q.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['quotes'] }); notify('Deleted.'); nav('/quotes'); },
    onError: (e: any) => notify(e.message ?? 'Delete failed', 'error'),
  });

  function setField(field: string, value: any) { if (!locked) setQ((p: any) => ({ ...p, [field]: value })); }
  function setItem(index: number, field: string, value: any) { if (locked) return; setQ((p: any) => { const items = [...p.items]; items[index] = { ...items[index], [field]: field === 'quantity' || field === 'unitPrice' ? Math.max(0, Number(value) || 0) : value }; return { ...p, items }; }); }
  function addItem(item?: any) { if (locked) return; setQ((p: any) => ({ ...p, items: [...p.items, item ?? { id: uid(), description: '', quantity: 1, unitPrice: 0, catalogId: '' }] })); }
  function removeItem(index: number) { if (!locked && q.items.length > 1) setQ((p: any) => ({ ...p, items: p.items.filter((_: any, i: number) => i !== index) })); }
  function applyClient(client: any) { if (locked) return; setQ((p: any) => ({ ...p, clientId: client.id, clientName: client.company ? `${client.name} (${client.company})` : client.name, clientEmail: client.email || '', clientUrl: client.website || '' })); }
  function print() { const url = URL.createObjectURL(new Blob([buildPrintHtml(q, biz)], { type: 'text/html' })); const w = window.open(url, '_blank', 'noopener,noreferrer'); if (w) setTimeout(() => URL.revokeObjectURL(url), 60_000); }
  function csv() { const url = URL.createObjectURL(new Blob([buildCsv(q, biz)], { type: 'text/csv;charset=utf-8' })); const a = document.createElement('a'); a.href = url; a.download = `${q.quoteNumber || 'quote'}.csv`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1_000); }
  async function copyLink() { if (!sendResult) return; await navigator.clipboard.writeText(sendResult); notify('Link copied.'); }

  const categories = [...new Set(catalog.map((x: any) => x.category).filter(Boolean))];
  const filteredCatalog = catalog.filter((x: any) => !catFilter || x.category === catFilter);

  if (!isNew && isLoading) return <div className="page-loading">Loading quote...</div>;
  if (!isNew && !existing) return <div className="empty-state"><Icon.emptyDoc /><h3>Quote not found</h3><Link className="btn btn--primary" to="/quotes">Back to quotes</Link></div>;

  return <div className="page-enter">
    <div className="page-header">
      <div><div className="field-hint"><Link to="/quotes">Quotes</Link> / {isNew ? 'New quote' : q.quoteNumber}</div><h1 className="page-title">{isNew ? 'New quote' : q.title || q.quoteNumber}</h1></div>
      <div className="action-bar">
        {!isNew && <button className="btn btn--ghost" onClick={() => setHistoryOpen(true)}>History</button>}
        {deleted && !isNew && <button className="btn btn--secondary" onClick={() => restore.mutate()} disabled={restore.isPending}>{restore.isPending ? 'Restoring...' : 'Restore quote'}</button>}
        {!isNew && !deleted && !locked && tf.duplicate && <button className="btn btn--ghost" onClick={() => duplicate.mutate()} disabled={duplicate.isPending}>Duplicate</button>}
        {!isNew && !deleted && !locked && <button className="btn btn--ghost" onClick={() => setQ(existing)}>Reset</button>}
        <button className="btn btn--primary" onClick={() => save.mutate()} disabled={locked || save.isPending}>{save.isPending ? 'Saving...' : 'Save quote'}</button>
      </div>
    </div>

    <div className="editor-shell">
      <main className="editor-main">
        {deleted && <div className="upgrade-banner"><div><div className="upgrade-banner-title">Deleted quote is archived</div><div className="upgrade-banner-sub">This quote is hidden from the active list. Its history and any linked invoice remain preserved.</div></div><button className="btn btn--secondary btn--sm" onClick={() => restore.mutate()} disabled={restore.isPending}>Restore</button></div>}
        {!deleted && locked && <div className="upgrade-banner"><div><div className="upgrade-banner-title">Accepted quote is locked</div><div className="upgrade-banner-sub">The invoice uses a frozen snapshot. Create changes as a new quote.</div></div><Link className="btn btn--secondary btn--sm" to="/quotes/new">New quote</Link></div>}
        <section className="card">
          <div className="section-row"><h2 className="section-title">Quote details</h2>{q.status && <span className={`badge ${(STATUSES as any)[q.status]?.cls}`}>{(STATUSES as any)[q.status]?.label}</span>}</div>
          <div className="form-grid">
            <div className="field-group field-group--span"><label className="field-label">Title</label><input className="field-input" value={q.title || ''} disabled={locked} onChange={e => setField('title', e.target.value)} placeholder="Website redesign" /></div>
            <div className="field-group"><label className="field-label">Client</label><select className="field-select" value={q.clientId || ''} disabled={locked} onChange={e => { const c = clients.find((x: any) => x.id === e.target.value); if (c) applyClient(c); else setField('clientId', ''); }}><option value="">Choose client</option>{clients.map((c: any) => <option key={c.id} value={c.id}>{c.name}{c.company ? ` · ${c.company}` : ''}</option>)}</select></div>
            <div className="field-group"><label className="field-label">Currency</label><select className="field-select" value={q.currency || 'ZAR'} disabled={locked} onChange={e => setField('currency', e.target.value)}>{CURRENCIES.map(c => <option key={c.code} value={c.code}>{c.code} {c.symbol}</option>)}</select></div>
            <div className="field-group"><label className="field-label">Valid for</label><input className="field-input" type="number" min="1" max="365" value={q.validityDays ?? 30} disabled={locked} onChange={e => setField('validityDays', Number(e.target.value))} /></div>
            <div className="field-group"><label className="field-label">Payment terms</label><select className="field-select" value={q.paymentTermsDays ?? 30} disabled={locked} onChange={e => setField('paymentTermsDays', Number(e.target.value))}><option value="0">Due on receipt</option><option value="7">7 days</option><option value="14">14 days</option><option value="30">30 days</option><option value="60">60 days</option><option value="90">90 days</option></select></div>
            {q.clientEmail && <div className="field-group"><label className="field-label">Client email</label><input className="field-input" value={q.clientEmail} disabled /></div>}
            <div className="field-group field-group--span"><label className="field-label">Notes / terms</label><textarea className="field-textarea" rows={5} value={q.notes || ''} disabled={locked} onChange={e => setField('notes', e.target.value)} placeholder={biz.terms || 'Scope, exclusions, payment conditions, delivery details...'}/></div>
          </div>
        </section>

        <section className="card">
          <div className="section-row"><h2 className="section-title">Line items</h2><div className="action-bar"><button className="btn btn--secondary btn--sm" onClick={() => addItem()} disabled={locked}>Add line</button><button className="btn btn--ghost btn--sm" onClick={() => setCatOpen(!catOpen)} disabled={locked}>From catalog</button></div></div>
          {catOpen && <div className="catalog-picker"><div className="form-grid"><div className="field-group"><label className="field-label">Category</label><select className="field-select" value={catFilter} onChange={e => setCatFilter(e.target.value)}><option value="">All</option>{categories.map((x: any) => <option key={x} value={x}>{x}</option>)}</select></div></div><div className="simple-list">{filteredCatalog.map((item: any) => <button key={item.id} type="button" className="simple-row catalog-choice" onClick={() => { addItem({ id: uid(), description: item.name + (item.description ? `: ${item.description}` : ''), quantity: 1, unitPrice: item.unitPrice, catalogId: item.id }); setCatOpen(false); }}><span><strong>{item.name}</strong><span className="field-hint"> {item.unitPrice}/{item.unit}</span></span><span>{money(item.unitPrice, q.currency)}</span></button>)}</div></div>}
          <div className="line-items">
            <div className="line-items-header"><span>Description</span><span>Qty</span><span>Unit price</span><span>Total</span><span /></div>
            {(q.items ?? []).map((item: any, i: number) => <div className="line-items-row" key={item.id || i}><input className="li-input" value={item.description || ''} disabled={locked} onChange={e => setItem(i, 'description', e.target.value)} placeholder="Service or product"/><input className="li-input li-input--num" type="number" min="0" step="0.01" value={item.quantity} disabled={locked} onChange={e => setItem(i, 'quantity', e.target.value)}/><input className="li-input li-input--num" type="number" min="0" step="0.01" value={item.unitPrice} disabled={locked} onChange={e => setItem(i, 'unitPrice', e.target.value)}/><span className="li-total">{money((Number(item.quantity) || 0) * (Number(item.unitPrice) || 0), q.currency)}</span><button className="li-remove" onClick={() => removeItem(i)} disabled={locked || q.items.length <= 1} aria-label="Remove line">×</button></div>)}
          </div>
        </section>

        <section className="card">
          <h2 className="section-title">Tax and discount</h2>
          <div className="form-grid">
            <div className="field-group"><label className="field-label">Tax %</label><input className="field-input" type="number" min="0" max="100" step="0.01" value={q.taxPercent ?? 0} disabled={locked} onChange={e => setField('taxPercent', Number(e.target.value))} /></div>
            <div className="field-group"><label className="field-label">Discount %</label><input className="field-input" type="number" min="0" max="100" step="0.01" value={q.discountPercent ?? 0} disabled={locked || !tf.discount} onChange={e => setField('discountPercent', Number(e.target.value))} />{!tf.discount && <span className="field-hint">Available on a paid plan.</span>}</div>
          </div>
        </section>

        <div className="action-bar">
          {!isNew && !deleted && <button className="btn btn--danger" onClick={() => { if (confirm('Delete this quote? It will be archived, not erased. The audit history and any linked invoice will remain.')) del.mutate(); }} disabled={del.isPending}>Delete</button>}
          {!isNew && !deleted && !locked && <button className="btn btn--secondary" onClick={() => setConfirmOpen(true)}>Accept &amp; invoice</button>}
          {!isNew && !deleted && !locked && tf.clientUrl && <button className="btn btn--secondary" onClick={() => send.mutate()} disabled={send.isPending || !q.clientEmail}>{send.isPending ? 'Creating link...' : 'Send to client'}</button>}
          {!deleted && sendResult && <button className="btn btn--ghost" onClick={copyLink}>Copy client link</button>}
          {!deleted && tf.print && <button className="btn btn--ghost" onClick={print}>Print / PDF</button>}
          {!deleted && tf.csv && <button className="btn btn--ghost" onClick={csv}>CSV</button>}
        </div>
        {sendResult && <div className="field-hint">Client link: <a href={sendResult} target="_blank" rel="noopener noreferrer">{sendResult}</a></div>}
      </main>

      <aside className="totals-card"><div className="field-hint">{q.quoteNumber || 'New quote'}</div><div className="totals-row"><span>Line total</span><span className="totals-value">{money(totals.line, q.currency)}</span></div><div className="totals-row"><span>Discount</span><span className="totals-value">{money(totals.discountAmt, q.currency)}</span></div><div className="totals-row"><span>Subtotal</span><span className="totals-value">{money(totals.sub, q.currency)}</span></div><div className="totals-row"><span>Tax</span><span className="totals-value">{money(totals.tax, q.currency)}</span></div><div className="totals-row grand"><span>Total</span><span className="totals-value">{money(totals.total, q.currency)}</span></div>{q.clientEmail ? <div className="field-hint">Ready to send to {q.clientEmail}</div> : <div className="field-hint">Add a client with an email address to enable client delivery.</div>}</aside>
    </div>

    {historyOpen && <div className="modal-overlay"><div className="modal" role="dialog" aria-modal="true"><div className="modal-header"><h2>Quote history</h2><button className="btn btn--ghost btn--sm" onClick={() => setHistoryOpen(false)}>Close</button></div><div className="modal-body"><div className="simple-list">{history.map((event: any) => <div key={event.id} className="simple-row"><span><strong>{String(event.eventType).replaceAll('_',' ')}</strong><span className="field-hint"> {new Date(event.createdAt).toLocaleString()}</span></span><span className="field-hint">{event.metadata ? JSON.stringify(event.metadata) : ''}</span></div>)}</div></div></div></div>}
    {confirmOpen && <div className="modal-overlay" role="presentation"><div className="modal" role="dialog" aria-modal="true"><div className="modal-header"><h2>Accept quote and issue invoice?</h2><button className="btn btn--ghost btn--sm" onClick={() => setConfirmOpen(false)}>Close</button></div><div className="modal-body"><p>This freezes the accepted pricing and creates invoice <strong>{q.quoteNumber ? `INV-${q.quoteNumber.replace(/^QT-/, '')}` : 'numbered invoice'}</strong>. The client can no longer change the quote.</p></div><div className="modal-footer"><button className="btn btn--ghost" onClick={() => setConfirmOpen(false)}>Cancel</button><button className="btn btn--primary" onClick={() => accept.mutate()} disabled={accept.isPending}>{accept.isPending ? 'Issuing...' : 'Accept and invoice'}</button></div></div></div>}
  </div>;
}
