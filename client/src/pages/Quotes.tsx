import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api';
import { Icon } from '../components/Icons';
import { useToast } from '../components/Toast';
import { money, fmtDate } from '../lib/quote';
import { quoteAttention, toneClass } from '../lib/workflow';

const FILTERS = [
  { key: 'all', label: 'All' },
  { key: 'draft', label: 'Drafts' },
  { key: 'awaiting', label: 'Awaiting reply' },
  { key: 'followup', label: 'Follow up' },
  { key: 'won', label: 'Accepted' },
  { key: 'declined', label: 'Needs revision' },
];

function matchesFilter(q: any, filter: string) {
  const state = quoteAttention(q);
  if (filter === 'all') return true;
  if (filter === 'draft') return q.status === 'draft';
  if (filter === 'awaiting') return q.status === 'sent' && state.label !== 'Follow up' && state.label !== 'Expired';
  if (filter === 'followup') return ['Follow up', 'Act soon', 'Expired'].includes(state.label);
  if (filter === 'won') return q.status === 'accepted';
  if (filter === 'declined') return q.status === 'declined';
  return true;
}

export default function Quotes() {
  const qc = useQueryClient();
  const { notify } = useToast();
  const [showDeleted, setShowDeleted] = useState(false);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('all');
  const { data: active = [], isLoading, isError, error, refetch } = useQuery({ queryKey: ['quotes'], queryFn: api.quotes.list, retry: 2 });
  const { data: archived = [] } = useQuery({ queryKey: ['quotes', 'archived'], queryFn: () => api.quotes.list(true), enabled: showDeleted });
  const send = useMutation({
    mutationFn: (id: string) => api.quotes.send(id),
    onSuccess: (r) => { qc.invalidateQueries({ queryKey: ['quotes'] }); navigator.clipboard?.writeText(r.url).catch(() => {}); notify('Quote sent. Client link copied.'); },
    onError: (e: any) => notify(e.message ?? 'Could not send quote.', 'error'),
  });
  const remind = useMutation({
    mutationFn: (id: string) => api.quotes.remind(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['quotes'] }); notify('Follow-up sent.'); },
    onError: (e: any) => notify(e.message ?? 'Could not send follow-up.', 'error'),
  });
  const duplicate = useMutation({
    mutationFn: (id: string) => api.quotes.duplicate(id),
    onSuccess: (copy) => { notify('Quote duplicated.'); window.location.href = `/quotes/${copy.id}/edit`; },
    onError: (e: any) => notify(e.message ?? 'Could not duplicate quote.', 'error'),
  });

  const rows = showDeleted ? archived : active;
  const filtered = useMemo(() => rows.filter((q: any) => {
    if (!showDeleted && !matchesFilter(q, filter)) return false;
    if (!search.trim()) return true;
    const text = search.toLowerCase();
    return [q.quoteNumber, q.title, q.clientName, q.clientEmail].some((value) => String(value || '').toLowerCase().includes(text));
  }).sort((a: any, b: any) => new Date(b.updatedAt || b.createdAt || 0).getTime() - new Date(a.updatedAt || a.createdAt || 0).getTime()), [rows, filter, search, showDeleted]);

  const awaiting = active.filter((q: any) => q.status === 'sent' && quoteAttention(q).label === 'Awaiting reply').length;
  const followup = active.filter((q: any) => ['Follow up', 'Act soon', 'Expired'].includes(quoteAttention(q).label)).length;
  const won = active.filter((q: any) => q.status === 'accepted').length;

  return (
    <div className="page-enter">
      <div className="page-header">
        <div>
          <div className="eyebrow">Sales pipeline</div>
          <h1 className="page-title">Quotes</h1>
          <p className="page-subtitle">One place for drafts, approvals, revisions, and follow-ups.</p>
        </div>
        <div className="action-bar"><button className="btn btn--ghost" onClick={() => setShowDeleted((v) => !v)}>{showDeleted ? 'Hide archived' : 'Show archived'}</button><Link to="/quotes/new" className="btn btn--primary"><Icon.plus /> New quote</Link></div>
      </div>

      <div className="summary-strip">
        <button className="summary-chip" onClick={() => setFilter('awaiting')}><span>{awaiting}</span> awaiting reply</button>
        <button className="summary-chip summary-chip--warning" onClick={() => setFilter('followup')}><span>{followup}</span> need follow-up</button>
        <button className="summary-chip summary-chip--success" onClick={() => setFilter('won')}><span>{won}</span> accepted</button>
      </div>

      {!showDeleted && <div className="filter-row">
        <div className="segmented-control" role="tablist" aria-label="Quote filters">
          {FILTERS.map((item) => <button key={item.key} className={filter === item.key ? 'active' : ''} onClick={() => setFilter(item.key)}>{item.label}</button>)}
        </div>
        <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search by quote, client, or title" className="field-input search-field" />
      </div>}

      {showDeleted && <div className="info-banner">Archived quotes stay in your account history. Restore one to send or edit it again.</div>}

      {isLoading ? <div className="page-loading local-loading"><div className="loading-card"><span className="loading-spinner" aria-hidden="true" /><strong>Loading your quotes</strong><span>Fetching your saved quotes and pipeline status.</span></div></div> : isError ? (
        <div className="empty-state card error-state">
          <Icon.emptyDoc />
          <h3>Quotes could not be loaded</h3>
          <p>{(error as any)?.message || 'Something went wrong while loading your quotes.'}</p>
          <button className="btn btn--primary" onClick={() => refetch()}>Try again</button>
        </div>
      ) : filtered.length === 0 ? (
        <div className="empty-state card">
          <Icon.emptyDoc />
          <h3>{showDeleted ? 'No archived quotes' : search ? 'No matching quotes' : 'No quotes yet'}</h3>
          <p>{showDeleted ? 'Archived documents will appear here.' : 'Start with a client and a few line items. The app handles the rest.'}</p>
          {!showDeleted && <Link to="/quotes/new" className="btn btn--primary"><Icon.plus /> Create your first quote</Link>}
        </div>
      ) : (
        <div className="document-list">
          {filtered.map((q: any) => {
            const state = quoteAttention(q);
            const total = Number.isFinite(q.totalMinor) ? Number(q.totalMinor) / (q.currency === 'JPY' ? 1 : 100) : 0;
            return (
              <div key={q.id} className="document-card">
                <Link to={`/quotes/${q.id}/edit`} className="document-main">
                  <div className="document-number">{q.quoteNumber || 'Draft quote'}</div>
                  <div className="document-title">{q.title || 'Untitled quote'}</div>
                  <div className="document-meta">{q.clientName || 'No client'} {q.sentAt ? `· Sent ${fmtDate(q.sentAt)}` : `· Updated ${fmtDate(q.updatedAt)}`}</div>
                </Link>
                <div className="document-total"><strong>{money(total, q.currency)}</strong><span>{q.validUntil ? `Valid to ${fmtDate(q.validUntil)}` : 'No expiry set'}</span></div>
                <div className="document-status"><span className={toneClass(state.tone)}>{state.label}</span><small>{state.detail}</small></div>
                <div className="document-actions">
                  {!showDeleted && q.status === 'sent' && !q.deletedAt && <button className="btn btn--secondary btn--sm" onClick={() => remind.mutate(q.id)} disabled={remind.isPending || !q.clientEmail}>{remind.isPending ? 'Sending...' : 'Follow up'}</button>}
                  {!showDeleted && q.status === 'draft' && !q.deletedAt && <button className="btn btn--secondary btn--sm" onClick={() => send.mutate(q.id)} disabled={send.isPending || !q.clientEmail}>{send.isPending ? 'Sending...' : 'Send'}</button>}
                  {!showDeleted && !q.deletedAt && q.status !== 'accepted' && <button className="btn btn--ghost btn--sm" onClick={() => duplicate.mutate(q.id)} disabled={duplicate.isPending}>Duplicate</button>}
                  {q.status === 'accepted' && <span className="field-hint">Invoice issued automatically</span>}
                  <Link to={`/quotes/${q.id}/edit`} className="btn btn--ghost btn--sm">Open</Link>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
