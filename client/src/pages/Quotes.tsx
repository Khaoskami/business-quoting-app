import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api';
import { Icon } from '../components/Icons';
import { STATUSES, calcTotals, money, fmtDate } from '../lib/quote';

export default function Quotes() {
  const { data: quotes = [] } = useQuery({ queryKey: ['quotes'], queryFn: api.quotes.list });
  const [search, setSearch] = useState('');

  const filtered = quotes
    .filter((q: any) => {
      if (!search) return true;
      const t = search.toLowerCase();
      return (q.title || '').toLowerCase().includes(t) ||
             (q.clientName || '').toLowerCase().includes(t) ||
             (q.quoteNumber || '').toLowerCase().includes(t);
    })
    .sort((a: any, b: any) => new Date(b.updatedAt ?? 0).valueOf() - new Date(a.updatedAt ?? 0).valueOf());

  return (
    <div className="page-enter">
      <div className="page-header">
        <h1 className="page-title">Quotes</h1>
        <Link to="/quotes/new" className="btn btn--primary"><Icon.plus /> New Quote</Link>
      </div>
      <input value={search} onChange={(e) => setSearch(e.target.value)}
             placeholder="Search quotes..." className="field-input" style={{ marginBottom: 16 }} />
      {filtered.length === 0 ? (
        <div className="empty-state">
          <Icon.emptyDoc />
          <h3>{quotes.length === 0 ? 'No quotes yet' : 'No results'}</h3>
          {quotes.length === 0 && <Link to="/quotes/new" className="btn btn--primary"><Icon.plus /> New Quote</Link>}
        </div>
      ) : (
        <div className="list">
          <div className="list-header">
            <span>Quote #</span><span>Title</span><span>Client</span><span>Date</span><span>Value</span><span>Status</span>
          </div>
          {filtered.map((q: any) => {
            const { total } = calcTotals(q.items ?? [], q.taxPercent ?? 0, q.discountPercent ?? 0);
            const s = (STATUSES as any)[q.status] ?? STATUSES.draft;
            return (
              <Link key={q.id} to={`/quotes/${q.id}/edit`} className="list-row" style={{ color: 'inherit', textDecoration: 'none' }}>
                <span className="num">{q.quoteNumber || '—'}</span>
                <span className="title">{q.title || 'Untitled'}</span>
                <span className="client">{q.clientName || '—'}</span>
                <span className="date">{fmtDate(q.updatedAt)}</span>
                <span className="value">{money(total, q.currency)}</span>
                <span className="status-cell"><span className={`badge ${s.cls}`}>{s.label}</span></span>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
