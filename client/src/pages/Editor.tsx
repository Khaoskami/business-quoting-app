import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api';
import { Icon } from '../components/Icons';
import { useToast } from '../components/Toast';
import { CURRENCIES, STATUSES, calcTotals, money, newClient, newQuote, uid, validateUrl, buildCsv } from '../lib/quote';
import { quoteAttention, toneClass } from '../lib/workflow';

const LOCAL_DRAFT_KEY = 'bq_quote_draft_v2';

function loadLocalDraft() {
  try {
    const raw = localStorage.getItem(LOCAL_DRAFT_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export default function Editor() {
  const { id } = useParams();
  const [searchParams] = useSearchParams();
  const nav = useNavigate();
  const qc = useQueryClient();
  const { notify } = useToast();
  const isNew = !id;
  const selectedClientId = searchParams.get('client') || '';

  const { data: existing, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['quote', id],
    queryFn: () => api.quotes.get(id!),
    enabled: !isNew,
    retry: 2,
  });
  const { data: clients = [] } = useQuery({ queryKey: ['clients'], queryFn: api.clients.list });
  const { data: catalog = [] } = useQuery({ queryKey: ['catalog'], queryFn: api.catalog.list });
  const { data: invoices = [] } = useQuery({ queryKey: ['invoices'], queryFn: () => api.invoices.list() });
  const { data: profile } = useQuery({ queryKey: ['profile'], queryFn: api.profile.get });
  const biz = profile?.profile ?? {};
  const tf = profile?.subscription?.limits?.features ?? {};
  const [q, setQ] = useState<any>(() => isNew ? (loadLocalDraft() || newQuote('ZAR')) : undefined);
  const [catOpen, setCatOpen] = useState(false);
  const [catSearch, setCatSearch] = useState('');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [approvalConfirmed, setApprovalConfirmed] = useState(false);
  const [sendResult, setSendResult] = useState('');
  const [historyOpen, setHistoryOpen] = useState(false);
  const [quickClientOpen, setQuickClientOpen] = useState(false);
  const [quickClient, setQuickClient] = useState(newClient());
  const [localDraftSaved, setLocalDraftSaved] = useState(() => isNew && Boolean(loadLocalDraft()));
  const { data: history = [] } = useQuery({ queryKey: ['quote-events', q?.id], queryFn: () => api.quotes.events(q.id), enabled: Boolean(q?.id) });

  useEffect(() => {
    if (!isNew && existing) setQ(existing);
  }, [isNew, existing]);

  useEffect(() => {
    if (isNew && biz.defaultCurrency && !q?.id && !localDraftSaved) {
      setQ((current: any) => ({ ...current, currency: biz.defaultCurrency }));
    }
  }, [biz.defaultCurrency, isNew, localDraftSaved, q?.id]);

  useEffect(() => {
    if (!isNew || q?.id) return;
    const timer = window.setTimeout(() => {
      try {
        localStorage.setItem(LOCAL_DRAFT_KEY, JSON.stringify(q));
        setLocalDraftSaved(true);
      } catch {
        // Local backup is best-effort only.
      }
    }, 450);
    return () => window.clearTimeout(timer);
  }, [q, isNew]);

  const totals = useMemo(() => calcTotals(q?.items ?? [], q?.taxPercent ?? 0, q?.discountPercent ?? 0, q?.currency ?? 'ZAR'), [q]);
  const deleted = Boolean(q?.deletedAt);
  const accepted = q?.status === 'accepted';
  const locked = accepted || deleted;
  const hasLineItem = (q?.items ?? []).some((item: any) => String(item.description || '').trim() && Number(item.quantity) > 0 && Number(item.unitPrice) >= 0);
  const canSend = Boolean(q?.clientEmail && hasLineItem && !locked && tf.clientUrl);
  const linkedInvoice = invoices.find((inv: any) => inv.quoteId === q?.id);
  const attention = quoteAttention(q || {});

  const save = useMutation({
    mutationFn: async (mode: 'save' | 'send') => {
      const saved = isNew ? await api.quotes.create(q) : await api.quotes.update(id!, q);
      if (mode === 'send') {
        const sent = await api.quotes.send(saved.id);
        return { saved, sent };
      }
      return { saved };
    },
    onSuccess: ({ saved, sent }) => {
      setQ(saved);
      qc.invalidateQueries({ queryKey: ['quotes'] });
      if (sent) {
        setSendResult(sent.url);
        navigator.clipboard?.writeText(sent.url).catch(() => {});
        notify('Quote sent. Client link copied.');
      } else {
        notify('Quote saved.');
      }
      try { localStorage.removeItem(LOCAL_DRAFT_KEY); } catch {}
      setLocalDraftSaved(false);
      if (isNew && saved?.id) nav(`/quotes/${saved.id}/edit`, { replace: true });
    },
    onError: (e: any) => notify(e.message ?? 'Could not save quote.', 'error'),
  });

  const accept = useMutation({
    mutationFn: () => api.quotes.accept(q.id),
    onSuccess: (res) => {
      setConfirmOpen(false);
      setApprovalConfirmed(false);
      setQ((current: any) => ({ ...current, ...res }));
      qc.invalidateQueries({ queryKey: ['quotes'] });
      qc.invalidateQueries({ queryKey: ['invoices'] });
      notify(res.invoice ? `Invoice ${res.invoice.invoiceNumber} issued.` : 'Client approval recorded.');
    },
    onError: (e: any) => notify(e.message ?? 'Could not issue invoice.', 'error'),
  });

  const duplicate = useMutation({
    mutationFn: () => api.quotes.duplicate(q.id),
    onSuccess: (copy) => { notify('Revision created.'); nav(`/quotes/${copy.id}/edit`); },
    onError: (e: any) => notify(e.message ?? 'Could not create revision.', 'error'),
  });

  const restore = useMutation({
    mutationFn: () => api.quotes.restore(q.id),
    onSuccess: (res) => { setQ((current: any) => ({ ...current, ...res, deletedAt: null })); qc.invalidateQueries({ queryKey: ['quotes'] }); notify('Quote restored.'); },
    onError: (e: any) => notify(e.message ?? 'Restore failed.', 'error'),
  });

  const del = useMutation({
    mutationFn: () => api.quotes.delete(q.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['quotes'] }); notify('Quote archived.'); nav('/quotes'); },
    onError: (e: any) => notify(e.message ?? 'Archive failed.', 'error'),
  });

  const createQuickClient = useMutation({
    mutationFn: () => api.clients.create({ ...quickClient, website: validateUrl(quickClient.website) }),
    onSuccess: (client) => {
      qc.invalidateQueries({ queryKey: ['clients'] });
      setQ((current: any) => ({ ...current, clientId: client.id, clientName: client.company ? `${client.name} (${client.company})` : client.name, clientEmail: client.email || '', clientUrl: client.website || '' }));
      setQuickClientOpen(false);
      setQuickClient(newClient());
      notify('Client added to quote.');
    },
    onError: (e: any) => notify(e.message ?? 'Could not add client.', 'error'),
  });

  function setField(field: string, value: any) {
    if (!locked) setQ((current: any) => ({ ...current, [field]: value }));
  }

  function setItem(index: number, field: string, value: any) {
    if (locked) return;
    setQ((current: any) => {
      const items = [...(current.items || [])];
      items[index] = { ...items[index], [field]: field === 'quantity' || field === 'unitPrice' ? Math.max(0, Number(value) || 0) : value };
      return { ...current, items };
    });
  }

  function addItem(item?: any, focus = false) {
    if (locked) return;
    const next = item ?? { id: uid(), description: '', quantity: 1, unitPrice: 0, catalogId: '' };
    setQ((current: any) => ({ ...current, items: [...(current.items || []), next] }));
    if (focus) window.setTimeout(() => document.querySelector<HTMLInputElement>(`[data-line-id="${next.id}"]`)?.focus(), 0);
  }

  function removeItem(index: number) {
    if (!locked && q.items.length > 1) setQ((current: any) => ({ ...current, items: current.items.filter((_: any, i: number) => i !== index) }));
  }

  function applyClient(client: any) {
    if (locked) return;
    setQ((current: any) => ({ ...current, clientId: client.id, clientName: client.company ? `${client.name} (${client.company})` : client.name, clientEmail: client.email || '', clientUrl: client.website || '' }));
  }

  async function downloadPdf() {
    try {
      if (!q.id) return notify('Save the quote before creating a PDF.', 'error');
      const result = await api.quotes.pdf(q.id);
      const url = URL.createObjectURL(result.blob);
      const a = document.createElement('a'); a.href = url; a.download = result.filename; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    } catch (e: any) { notify(e.message ?? 'Could not generate PDF.', 'error'); }
  }

  function csv() {
    const url = URL.createObjectURL(new Blob([buildCsv(q, biz)], { type: 'text/csv;charset=utf-8' }));
    const a = document.createElement('a'); a.href = url; a.download = `${q.quoteNumber || 'quote'}.csv`; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1_000);
  }

  const categories = [...new Set(catalog.map((x: any) => x.category).filter(Boolean))];
  const filteredCatalog = catalog.filter((x: any) => {
    const categoryMatch = true;
    const text = `${x.name || ''} ${x.description || ''}`.toLowerCase();
    return categoryMatch && (!catSearch || text.includes(catSearch.toLowerCase()));
  });

  useEffect(() => {
    if (!isNew || !selectedClientId || !clients.length || q?.clientId) return;
    const client = clients.find((item: any) => item.id === selectedClientId);
    if (client) applyClient(client);
  }, [clients, isNew, selectedClientId, q?.clientId]);

  if (!isNew && isLoading) return <div className="page-loading local-loading"><div className="loading-card"><span className="loading-spinner" aria-hidden="true" /><strong>Loading quote</strong><span>Opening your saved quote and preparing the editor.</span></div></div>;
  if (!isNew && isError) return <div className="empty-state card error-state"><Icon.emptyDoc /><h3>Quote could not be loaded</h3><p>{(error as any)?.message || 'Something went wrong while loading this quote.'}</p><div className="action-bar"><button className="btn btn--primary" onClick={() => refetch()}>Try again</button><Link className="btn btn--secondary" to="/quotes">Back to quotes</Link></div></div>;
  if (!isNew && !existing) return <div className="empty-state card"><Icon.emptyDoc /><h3>Quote not found</h3><p>The quote may have been deleted or you may no longer have access to it.</p><Link className="btn btn--primary" to="/quotes">Back to quotes</Link></div>;
  // The query result arrives before the state-setting effect. Keep rendering gated here
  // so q can never be dereferenced during that one render between data arrival and effect.
  if (!isNew && !q) return <div className="page-loading">Preparing quote editor...</div>;

  return (
    <div className="page-enter">
      <div className="page-header editor-header">
        <div>
          <div className="eyebrow"><Link to="/quotes">Quotes</Link> <span>·</span> {isNew ? 'New quote' : q.quoteNumber}</div>
          <h1 className="page-title">{isNew ? 'Build a quote' : q.title || q.quoteNumber}</h1>
          <p className="page-subtitle">{isNew ? 'A clean quote now. A faster path to payment later.' : attention.detail}</p>
        </div>
        <div className="action-bar">
          {!isNew && <button className="btn btn--ghost" onClick={() => setHistoryOpen(true)}>History</button>}
          {!isNew && deleted && <button className="btn btn--secondary" onClick={() => restore.mutate()} disabled={restore.isPending}>Restore</button>}
          {!isNew && !deleted && q.status === 'declined' && <button className="btn btn--secondary" onClick={() => duplicate.mutate()} disabled={duplicate.isPending}>Create revision</button>}
          {!isNew && !deleted && !accepted && <button className="btn btn--primary" onClick={() => save.mutate('save')} disabled={save.isPending}>{save.isPending ? 'Saving...' : 'Save changes'}</button>}
        </div>
      </div>

      {localDraftSaved && isNew && <div className="info-banner"><strong>Local draft restored.</strong> Your unfinished quote was kept on this device so you do not have to start again.</div>}
      {deleted && <div className="info-banner"><strong>Archived quote.</strong> It is preserved with its history and linked invoice. Restore it to work with it again.</div>}
      {accepted && <div className="success-banner"><div><strong>Approved and invoiced.</strong><span>{linkedInvoice ? `${linkedInvoice.invoiceNumber} is now tracking payment.` : 'The invoice was created from the approved pricing snapshot.'}</span></div><Link className="btn btn--secondary btn--sm" to="/invoices">Open invoices</Link></div>}
      {!accepted && !deleted && q.status === 'declined' && <div className="warning-banner"><div><strong>Client declined this version.</strong><span>Create a revision instead of editing the history of the declined offer.</span></div><button className="btn btn--secondary btn--sm" onClick={() => duplicate.mutate()} disabled={duplicate.isPending}>Create revision</button></div>}

      <div className="editor-shell editor-shell--solution">
        <main className="editor-main">
          <section className="card editor-section">
            <div className="section-heading-row">
              <div><div className="eyebrow">Step 1</div><h2 className="section-title">Who is this for?</h2></div>
              {q.clientEmail ? <span className="ready-pill">Client ready</span> : <span className="needs-pill">Needs client</span>}
            </div>
            <div className="form-grid">
              <div className="field-group field-group--span">
                <label className="field-label">Client</label>
                <div className="inline-field-action"><select className="field-select" value={q.clientId || ''} disabled={locked} onChange={(e) => { const client = clients.find((item: any) => item.id === e.target.value); if (client) applyClient(client); else setField('clientId', ''); }}><option value="">Choose a client</option>{clients.map((client: any) => <option key={client.id} value={client.id}>{client.name}{client.company ? ` · ${client.company}` : ''}</option>)}</select><button className="btn btn--secondary btn--sm" disabled={locked} onClick={() => setQuickClientOpen(true)}>New client</button></div>
                {q.clientEmail ? <span className="field-hint">{q.clientEmail}</span> : <span className="field-hint">Pick an existing client or add one without leaving this quote.</span>}
              </div>
              <div className="field-group field-group--span"><label className="field-label">Quote title</label><input className="field-input" value={q.title || ''} disabled={locked} onChange={(e) => setField('title', e.target.value)} placeholder="Website redesign, kitchen renovation, monthly support..." /></div>
            </div>
          </section>

          <section className="card editor-section">
            <div className="section-heading-row">
              <div><div className="eyebrow">Step 2</div><h2 className="section-title">What are you charging for?</h2></div>
              <button className="btn btn--secondary btn--sm" onClick={() => addItem(undefined, true)} disabled={locked}><Icon.plus /> Add line</button>
            </div>
            <div className="line-items line-items--solution">
              <div className="line-items-header"><span>Description</span><span>Qty</span><span>Unit price</span><span>Total</span><span /></div>
              {(q.items ?? []).map((item: any, i: number) => <div className="line-items-row" key={item.id || i}>
                <input data-line-id={item.id} className="li-input" value={item.description || ''} disabled={locked} onChange={(e) => setItem(i, 'description', e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addItem(undefined, true); } }} placeholder="Service or product" />
                <input className="li-input li-input--num" type="number" min="0" step={q.currency === 'JPY' ? '1' : '0.01'} value={item.quantity} disabled={locked} onChange={(e) => setItem(i, 'quantity', e.target.value)} />
                <input className="li-input li-input--num" type="number" min="0" step={q.currency === 'JPY' ? '1' : '0.01'} value={item.unitPrice} disabled={locked} onChange={(e) => setItem(i, 'unitPrice', e.target.value)} />
                <span className="li-total">{money((Number(item.quantity) || 0) * (Number(item.unitPrice) || 0), q.currency)}</span>
                <button className="li-remove" onClick={() => removeItem(i)} disabled={locked || q.items.length <= 1} aria-label="Remove line">×</button>
              </div>)}
            </div>
            <div className="catalog-inline">
              <button className="btn btn--ghost btn--sm" onClick={() => setCatOpen((open) => !open)} disabled={locked}>Add from catalog</button>
              <span className="field-hint">Press Enter in a description to add another line.</span>
            </div>
            {catOpen && <div className="catalog-picker catalog-picker--solution"><div className="catalog-picker-head"><input className="field-input" autoFocus placeholder="Search services or products" value={catSearch} onChange={(e) => setCatSearch(e.target.value)} /><button className="btn btn--ghost btn--sm" onClick={() => setCatOpen(false)}>Close</button></div><div className="catalog-picker-list">{filteredCatalog.length === 0 ? <div className="field-hint">No matching catalog items.</div> : filteredCatalog.map((item: any) => <button key={item.id} type="button" className="catalog-choice" onClick={() => { addItem({ id: uid(), description: item.name + (item.description ? `: ${item.description}` : ''), quantity: 1, unitPrice: item.unitPrice, catalogId: item.id }); setCatOpen(false); }}><span><strong>{item.name}</strong><small>{item.category || 'Catalog item'} · {item.unit}</small></span><span>{money(item.unitPrice, q.currency)}</span></button>)}</div></div>}
          </section>

          <section className="card editor-section">
            <div className="section-heading-row"><div><div className="eyebrow">Step 3</div><h2 className="section-title">Make the offer clear</h2></div></div>
            <details className="advanced-details" open={!q.notes}>
              <summary><span>Pricing, dates, tax & terms</span><span className="field-hint">Only change what you need</span></summary>
              <div className="form-grid" style={{ marginTop: 16 }}>
                <div className="field-group"><label className="field-label">Currency</label><select className="field-select" value={q.currency || 'ZAR'} disabled={locked} onChange={(e) => setField('currency', e.target.value)}>{CURRENCIES.map((currency) => <option key={currency.code} value={currency.code}>{currency.code} · {currency.symbol}</option>)}</select></div>
                <div className="field-group"><label className="field-label">Quote valid for</label><select className="field-select" value={q.validityDays ?? 30} disabled={locked} onChange={(e) => setField('validityDays', Number(e.target.value))}><option value="7">7 days</option><option value="14">14 days</option><option value="30">30 days</option><option value="60">60 days</option><option value="90">90 days</option></select></div>
                <div className="field-group"><label className="field-label">Invoice payment terms</label><select className="field-select" value={q.paymentTermsDays ?? 30} disabled={locked} onChange={(e) => setField('paymentTermsDays', Number(e.target.value))}><option value="0">Due on receipt</option><option value="7">7 days</option><option value="14">14 days</option><option value="30">30 days</option><option value="60">60 days</option><option value="90">90 days</option></select></div>
                <div className="field-group"><label className="field-label">Tax %</label><input className="field-input" type="number" min="0" max="100" step="0.01" value={q.taxPercent ?? 0} disabled={locked} onChange={(e) => setField('taxPercent', Number(e.target.value))} /><span className="field-hint">Set this deliberately; do not guess from currency.</span></div>
                <div className="field-group"><label className="field-label">Discount %</label><input className="field-input" type="number" min="0" max="100" step="0.01" value={q.discountPercent ?? 0} disabled={locked || !tf.discount} onChange={(e) => setField('discountPercent', Number(e.target.value))} />{!tf.discount && <span className="field-hint">Discounts are available on a paid plan.</span>}</div>
                <div className="field-group field-group--span"><label className="field-label">Notes / terms</label><textarea className="field-textarea" rows={5} value={q.notes || ''} disabled={locked} onChange={(e) => setField('notes', e.target.value)} placeholder={biz.terms || 'Scope, exclusions, delivery notes, payment conditions...'}/></div>
              </div>
            </details>
          </section>

          <section className="editor-actions">
            {!isNew && !deleted && <button className="btn btn--danger" onClick={() => { if (confirm('Archive this quote? Its history and any linked invoice will remain preserved.')) del.mutate(); }} disabled={del.isPending}>Archive quote</button>}
            {q.id && !deleted && tf.print && <button className="btn btn--ghost" onClick={downloadPdf}>PDF</button>}
            {tf.csv && <button className="btn btn--ghost" onClick={csv}>CSV</button>}
            {q.status === 'sent' && q.clientEmail && tf.clientUrl && <button className="btn btn--secondary" onClick={() => save.mutate('send')} disabled={save.isPending}>Send again</button>}
            {!isNew && !deleted && !accepted && q.status !== 'declined' && <button className="btn btn--secondary" onClick={() => { setApprovalConfirmed(false); setConfirmOpen(true); }}>Record client approval</button>}
          </section>
          {sendResult && <div className="share-banner"><span>Client link ready</span><a href={sendResult} target="_blank" rel="noopener noreferrer">Open client view</a><button className="btn btn--ghost btn--sm" onClick={() => navigator.clipboard?.writeText(sendResult)}>Copy link</button></div>}
        </main>

        <aside className="totals-card totals-card--solution">
          <div className="totals-sticky-top"><div><div className="eyebrow">Quote summary</div><div className="totals-number">{q.quoteNumber || 'Draft'}</div></div><span className={toneClass(attention.tone)}>{attention.label}</span></div>
          <div className="total-hero"><span>Total</span><strong>{money(totals.total, q.currency)}</strong></div>
          <div className="totals-breakdown"><div className="totals-row"><span>Subtotal</span><span>{money(totals.sub, q.currency)}</span></div><div className="totals-row"><span>Tax</span><span>{money(totals.tax, q.currency)}</span></div>{q.discountPercent > 0 && <div className="totals-row discount"><span>Discount</span><span>−{money(totals.discountAmt, q.currency)}</span></div>}</div>
          <div className="checklist">
            <div className="check-item"><span className={q.clientId ? 'check-dot done' : 'check-dot'}>{q.clientId ? '✓' : ''}</span><span><strong>Client selected</strong><small>{q.clientName || 'Choose who receives this quote'}</small></span></div>
            <div className="check-item"><span className={q.clientEmail ? 'check-dot done' : 'check-dot'}>{q.clientEmail ? '✓' : ''}</span><span><strong>Delivery email</strong><small>{q.clientEmail || 'Add a client with an email'}</small></span></div>
            <div className="check-item"><span className={hasLineItem ? 'check-dot done' : 'check-dot'}>{hasLineItem ? '✓' : ''}</span><span><strong>Priced line items</strong><small>{hasLineItem ? `${q.items.length} line item${q.items.length === 1 ? '' : 's'}` : 'Add at least one priced item'}</small></span></div>
          </div>
          <div className="sticky-actions">
            {!locked && <button className="btn btn--primary btn--lg btn--full" onClick={() => save.mutate('send')} disabled={save.isPending || !canSend}>{save.isPending ? 'Sending...' : q.id ? 'Save & send quote' : 'Save & send'}</button>}
            {!locked && <button className="btn btn--secondary btn--full" onClick={() => save.mutate('save')} disabled={save.isPending}>{save.isPending ? 'Saving...' : 'Save draft'}</button>}
            {!tf.clientUrl && <span className="field-hint">Client sharing is available on a paid plan.</span>}
            {!q.clientEmail && <span className="field-hint">Once an email is set, one click sends the quote and copies its client link.</span>}
          </div>
          {accepted && linkedInvoice && <Link className="invoice-link-card" to="/invoices"><span>Invoice issued</span><strong>{linkedInvoice.invoiceNumber}</strong><small>Track payment in Invoices →</small></Link>}
        </aside>
      </div>

      {quickClientOpen && <div className="modal-overlay"><div className="modal" role="dialog" aria-modal="true"><div className="modal-header"><div><div className="eyebrow">Keep your place</div><h2>Add client</h2></div><button className="btn btn--ghost btn--sm" onClick={() => setQuickClientOpen(false)}>Close</button></div><div className="modal-body"><div className="form-grid"><div className="field-group"><label className="field-label">Name *</label><input autoFocus className="field-input" value={quickClient.name} onChange={(e) => setQuickClient({ ...quickClient, name: e.target.value })} /></div><div className="field-group"><label className="field-label">Company</label><input className="field-input" value={quickClient.company} onChange={(e) => setQuickClient({ ...quickClient, company: e.target.value })} /></div><div className="field-group field-group--span"><label className="field-label">Email</label><input className="field-input" type="email" value={quickClient.email} onChange={(e) => setQuickClient({ ...quickClient, email: e.target.value })} placeholder="client@example.com" /></div><div className="field-group"><label className="field-label">Phone</label><input className="field-input" value={quickClient.phone} onChange={(e) => setQuickClient({ ...quickClient, phone: e.target.value })} /></div></div></div><div className="modal-footer"><button className="btn btn--ghost" onClick={() => setQuickClientOpen(false)}>Cancel</button><button className="btn btn--primary" disabled={createQuickClient.isPending || !quickClient.name.trim()} onClick={() => createQuickClient.mutate()}>{createQuickClient.isPending ? 'Adding...' : 'Add client & use it'}</button></div></div></div>}

      {confirmOpen && <div className="modal-overlay"><div className="modal" role="dialog" aria-modal="true"><div className="modal-header"><div><div className="eyebrow">Approval check</div><h2>Record client approval?</h2></div><button className="btn btn--ghost btn--sm" onClick={() => setConfirmOpen(false)}>Close</button></div><div className="modal-body"><p>Only issue the invoice after the client has actually approved this version.</p><label className="confirm-check"><input type="checkbox" checked={approvalConfirmed} onChange={(e) => setApprovalConfirmed(e.target.checked)} /><span>I confirm the client approved this quote and I am authorised to issue the invoice.</span></label></div><div className="modal-footer"><button className="btn btn--ghost" onClick={() => setConfirmOpen(false)}>Cancel</button><button className="btn btn--primary" disabled={!approvalConfirmed || accept.isPending} onClick={() => accept.mutate()}>{accept.isPending ? 'Issuing...' : 'Issue invoice'}</button></div></div></div>}

      {historyOpen && <div className="modal-overlay"><div className="modal modal--wide" role="dialog" aria-modal="true"><div className="modal-header"><div><div className="eyebrow">Audit trail</div><h2>{q.quoteNumber || 'Quote'} history</h2></div><button className="btn btn--ghost btn--sm" onClick={() => setHistoryOpen(false)}>Close</button></div><div className="modal-body"><div className="timeline">{history.map((event: any) => <div key={event.id} className="timeline-row"><div className="timeline-dot" /><div><strong>{String(event.eventType).replaceAll('_', ' ')}</strong><div className="field-hint">{new Date(event.createdAt).toLocaleString()}</div>{event.metadata && <div className="timeline-meta">{JSON.stringify(event.metadata)}</div>}</div></div>)}</div></div></div></div>}
    </div>
  );
}
