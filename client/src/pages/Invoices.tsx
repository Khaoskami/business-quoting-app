import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api';
import { Icon } from '../components/Icons';
import { useToast } from '../components/Toast';
import { calcTotals, money, fmtDate } from '../lib/quote';
import { invoiceAttention, toneClass } from '../lib/workflow';

const FILTERS = [
  { key: 'all', label: 'All' },
  { key: 'open', label: 'Open' },
  { key: 'overdue', label: 'Overdue' },
  { key: 'soon', label: 'Due soon' },
  { key: 'paid', label: 'Paid' },
];

function totalOf(inv: any) {
  if (Number.isFinite(inv.amountMinor)) return Number(inv.amountMinor) / (inv.currency === 'JPY' ? 1 : 100);
  return calcTotals(inv.items || [], inv.taxPercent || 0, inv.discountPercent || 0, inv.currency).total;
}

function matchesFilter(inv: any, filter: string) {
  const state = invoiceAttention(inv);
  if (filter === 'all') return true;
  if (filter === 'open') return inv.status !== 'paid' && inv.status !== 'void';
  if (filter === 'overdue') return state.label === 'Overdue';
  if (filter === 'soon') return state.label === 'Due soon';
  if (filter === 'paid') return inv.status === 'paid';
  return true;
}

export default function Invoices() {
  const qc = useQueryClient();
  const { notify } = useToast();
  const [showDeleted, setShowDeleted] = useState(false);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [paymentFor, setPaymentFor] = useState<any>(null);
  const [historyFor, setHistoryFor] = useState<any>(null);
  const [shareUrl, setShareUrl] = useState('');
  const [amount, setAmount] = useState('');
  const [method, setMethod] = useState('bank_transfer');
  const [note, setNote] = useState('');

  const { data: active = [], isLoading } = useQuery({ queryKey: ['invoices'], queryFn: () => api.invoices.list() });
  const { data: archived = [] } = useQuery({ queryKey: ['invoices', 'archived'], queryFn: () => api.invoices.list(true), enabled: showDeleted });
  const { data: history = [] } = useQuery({ queryKey: ['invoice-events', historyFor?.id], queryFn: () => api.invoices.events(historyFor.id), enabled: Boolean(historyFor) });
  const { data: profile } = useQuery({ queryKey: ['profile'], queryFn: api.profile.get });
  const biz = profile?.profile ?? {};
  const canRemind = Boolean(profile?.subscription?.limits?.features?.manualReminders);

  const refresh = () => qc.invalidateQueries({ queryKey: ['invoices'] });
  const send = useMutation({
    mutationFn: (id: string) => api.invoices.send(id),
    onSuccess: (r) => { refresh(); setShareUrl(r.url); navigator.clipboard?.writeText(r.url).catch(() => {}); notify('Invoice sent. Client link copied.'); },
    onError: (e: any) => notify(e.message ?? 'Could not send invoice.', 'error'),
  });
  const remind = useMutation({
    mutationFn: (id: string) => api.invoices.remind(id),
    onSuccess: () => { refresh(); notify('Payment reminder queued.'); },
    onError: (e: any) => notify(e.message ?? 'Could not send reminder.', 'error'),
  });
  const share = useMutation({
    mutationFn: (id: string) => api.invoices.share(id),
    onSuccess: (r) => { setShareUrl(r.url); navigator.clipboard?.writeText(r.url).catch(() => {}); notify('Invoice link copied.'); },
    onError: (e: any) => notify(e.message ?? 'Could not create link.', 'error'),
  });
  const payment = useMutation({
    mutationFn: (input: any) => api.invoices.recordPayment(input.id, { amount: Number(input.amount), method: input.method, note: input.note }),
    onSuccess: (result) => { setPaymentFor(null); refresh(); notify(`Payment recorded. ${result.balance ? `Balance: ${result.balance}` : 'Invoice is paid.'}`); },
    onError: (e: any) => notify(e.message ?? 'Payment failed.', 'error'),
  });

  const rows = showDeleted ? archived : active;
  const filtered = useMemo(() => rows.filter((inv: any) => {
    if (!showDeleted && !matchesFilter(inv, filter)) return false;
    if (!search.trim()) return true;
    const text = search.toLowerCase();
    return [inv.invoiceNumber, inv.title, inv.clientName, inv.clientEmail].some((v) => String(v || '').toLowerCase().includes(text));
  }).sort((a: any, b: any) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime()), [rows, filter, search, showDeleted]);

  const open = active.filter((inv: any) => inv.status !== 'paid' && inv.status !== 'void');
  const overdue = active.filter((inv: any) => invoiceAttention(inv).label === 'Overdue');
  const dueSoon = active.filter((inv: any) => invoiceAttention(inv).label === 'Due soon');
  const currencies = [...new Set(open.map((inv: any) => String(inv.currency || 'ZAR')))] as string[];
  const outstanding = currencies.map((currency) => money(open.filter((i: any) => String(i.currency || 'ZAR') === currency).reduce((sum: number, i: any) => sum + Number(i.balance || 0), 0), currency)).join(' · ') || money(0, String(biz.defaultCurrency || 'ZAR'));

  async function downloadPdf(inv: any) {
    try {
      const result = await api.invoices.pdf(inv.id);
      const url = URL.createObjectURL(result.blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = result.filename;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    } catch (e: any) {
      notify(e.message ?? 'Could not generate PDF.', 'error');
    }
  }

  async function archive(inv: any) {
    if (!confirm(`Archive ${inv.invoiceNumber}? Payment history stays preserved.`)) return;
    try { await api.invoices.delete(inv.id); refresh(); notify('Invoice archived.'); }
    catch (e: any) { notify(e.message ?? 'Could not archive invoice.', 'error'); }
  }

  async function restore(inv: any) {
    try { await api.invoices.restore(inv.id); refresh(); notify('Invoice restored.'); }
    catch (e: any) { notify(e.message ?? 'Could not restore invoice.', 'error'); }
  }

  async function voidInvoice(inv: any) {
    if (!confirm(`Void ${inv.invoiceNumber}? This stops new payments.`)) return;
    try { await api.invoices.setStatus(inv.id, 'void'); refresh(); notify('Invoice voided.'); }
    catch (e: any) { notify(e.message ?? 'Could not void invoice.', 'error'); }
  }

  return (
    <div className="page-enter">
      <div className="page-header">
        <div>
          <div className="eyebrow">Accounts receivable</div>
          <h1 className="page-title">Invoices</h1>
          <p className="page-subtitle">Know what is owed, what is late, and what to do next.</p>
        </div>
        <button className="btn btn--ghost" onClick={() => setShowDeleted((v) => !v)}>{showDeleted ? 'Hide archived' : 'Show archived'}</button>
      </div>

      <div className="summary-strip">
        <button className="summary-chip" onClick={() => setFilter('open')}><span>{outstanding}</span> outstanding</button>
        <button className="summary-chip summary-chip--danger" onClick={() => setFilter('overdue')}><span>{overdue.length}</span> overdue</button>
        <button className="summary-chip summary-chip--warning" onClick={() => setFilter('soon')}><span>{dueSoon.length}</span> due soon</button>
      </div>

      {!showDeleted && <div className="filter-row">
        <div className="segmented-control" role="tablist" aria-label="Invoice filters">
          {FILTERS.map((item) => <button key={item.key} className={filter === item.key ? 'active' : ''} onClick={() => setFilter(item.key)}>{item.label}</button>)}
        </div>
        <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search by invoice, client, or title" className="field-input search-field" />
      </div>}

      {shareUrl && <div className="share-banner"><span>Client link ready</span><a href={shareUrl} target="_blank" rel="noopener noreferrer">Open client view</a><button className="btn btn--ghost btn--sm" onClick={() => navigator.clipboard?.writeText(shareUrl)}>Copy link</button></div>}
      {showDeleted && <div className="info-banner">Archived invoices stay preserved with payment history and audit events.</div>}

      {isLoading ? <div className="page-loading local-loading">Loading invoices...</div> : filtered.length === 0 ? (
        <div className="empty-state card">
          <Icon.emptyDoc />
          <h3>{showDeleted ? 'No archived invoices' : search ? 'No matching invoices' : 'No invoices yet'}</h3>
          <p>When a client accepts a quote, its pricing snapshot becomes an invoice automatically.</p>
          {!showDeleted && <Link to="/quotes" className="btn btn--secondary">View quotes</Link>}
        </div>
      ) : (
        <div className="document-list">
          {filtered.map((inv: any) => {
            const state = invoiceAttention(inv);
            const total = totalOf(inv);
            const balance = Number(inv.balance || 0);
            return (
              <div key={inv.id} className="document-card document-card--invoice">
                <div className="document-main">
                  <div className="document-number">{inv.invoiceNumber}</div>
                  <div className="document-title">{inv.title || 'Invoice'} · {inv.clientName || 'No client'}</div>
                  <div className="document-meta">Issued {fmtDate(inv.createdAt)} · Due {fmtDate(inv.dueAt)} {inv.sourceQuoteNumber ? `· From ${inv.sourceQuoteNumber}` : ''}</div>
                </div>
                <div className="document-total"><strong>{money(balance, inv.currency)}</strong><span>of {money(total, inv.currency)} remaining</span></div>
                <div className="document-status"><span className={toneClass(state.tone)}>{state.label}</span><small>{state.detail}</small></div>
                <div className="document-actions">
                  {!showDeleted && !inv.deletedAt && inv.clientEmail && <button className="btn btn--secondary btn--sm" onClick={() => send.mutate(inv.id)} disabled={send.isPending}>{send.isPending ? 'Sending...' : 'Send'}</button>}
                  {!showDeleted && !inv.deletedAt && inv.status !== 'paid' && inv.status !== 'void' && inv.clientEmail && canRemind && <button className="btn btn--ghost btn--sm" onClick={() => remind.mutate(inv.id)} disabled={remind.isPending}>{remind.isPending ? 'Sending...' : 'Remind'}</button>}
                  {!showDeleted && !inv.deletedAt && inv.status !== 'paid' && inv.status !== 'void' && <button className="btn btn--secondary btn--sm" onClick={() => { setPaymentFor(inv); setAmount(String(balance)); setMethod('bank_transfer'); setNote(''); }}>Record payment</button>}
                  {!showDeleted && !inv.deletedAt && <button className="btn btn--ghost btn--sm" onClick={() => share.mutate(inv.id)} disabled={share.isPending}>Copy link</button>}
                  <button className="btn btn--ghost btn--sm" onClick={() => downloadPdf(inv)}>PDF</button>
                  <button className="btn btn--ghost btn--sm" onClick={() => setHistoryFor(inv)}>History</button>
                  {!showDeleted && !inv.deletedAt && inv.status !== 'void' && <button className="btn btn--ghost btn--sm" onClick={() => voidInvoice(inv)}>Void</button>}
                  {!showDeleted && !inv.deletedAt && <button className="btn btn--danger btn--sm" onClick={() => archive(inv)}>Archive</button>}
                  {showDeleted && <button className="btn btn--secondary btn--sm" onClick={() => restore(inv)}>Restore</button>}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {paymentFor && <div className="modal-overlay"><div className="modal" role="dialog" aria-modal="true"><div className="modal-header"><div><div className="eyebrow">Receive money</div><h2>Record payment</h2></div><button className="btn btn--ghost btn--sm" onClick={() => setPaymentFor(null)}>Close</button></div><div className="modal-body"><div className="payment-summary"><span>Balance remaining</span><strong>{money(paymentFor.balance || 0, paymentFor.currency)}</strong></div><div className="field-group"><label className="field-label">Amount</label><input autoFocus className="field-input" type="number" min="0.01" step={paymentFor.currency === 'JPY' ? '1' : '0.01'} value={amount} onChange={(e) => setAmount(e.target.value)} /></div><div className="quick-amounts"><button className="btn btn--ghost btn--sm" onClick={() => setAmount(String(paymentFor.balance || 0))}>Full balance</button>{Number(paymentFor.balance || 0) > 0 && <button className="btn btn--ghost btn--sm" onClick={() => setAmount(String((Number(paymentFor.balance || 0) / 2).toFixed(paymentFor.currency === 'JPY' ? 0 : 2)))}>Half</button>}</div><div className="field-group"><label className="field-label">Method</label><select className="field-select" value={method} onChange={(e) => setMethod(e.target.value)}><option value="bank_transfer">Bank transfer</option><option value="eft">EFT</option><option value="card">Card</option><option value="cash">Cash</option><option value="other">Other</option></select></div><div className="field-group"><label className="field-label">Reference / note</label><input className="field-input" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Bank reference, receipt number, etc." /></div></div><div className="modal-footer"><button className="btn btn--ghost" onClick={() => setPaymentFor(null)}>Cancel</button><button className="btn btn--primary" disabled={payment.isPending || Number(amount) <= 0} onClick={() => payment.mutate({ id: paymentFor.id, amount, method, note })}>{payment.isPending ? 'Saving...' : 'Save payment'}</button></div></div></div>}

      {historyFor && <div className="modal-overlay"><div className="modal" role="dialog" aria-modal="true"><div className="modal-header"><div><div className="eyebrow">Audit trail</div><h2>{historyFor.invoiceNumber} history</h2></div><button className="btn btn--ghost btn--sm" onClick={() => setHistoryFor(null)}>Close</button></div><div className="modal-body"><div className="timeline">{history.map((event: any) => <div key={event.id} className="timeline-row"><div className="timeline-dot" /><div><strong>{String(event.eventType).replaceAll('_', ' ')}</strong><div className="field-hint">{new Date(event.createdAt).toLocaleString()}</div>{event.metadata && <div className="timeline-meta">{JSON.stringify(event.metadata)}</div>}</div></div>)}</div></div></div></div>}
    </div>
  );
}
