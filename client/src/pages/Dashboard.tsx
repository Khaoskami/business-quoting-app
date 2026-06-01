import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '../api';
import { Icon } from '../components/Icons';
import { STATUSES, calcTotals, money, fmtDate } from '../lib/quote';

export default function Dashboard() {
  const { data: quotes = [] } = useQuery({ queryKey: ['quotes'],  queryFn: api.quotes.list });
  const { data: profile }     = useQuery({ queryKey: ['profile'], queryFn: api.profile.get });
  const currency = profile?.profile?.defaultCurrency ?? 'ZAR';

  const accepted = quotes.filter((q: any) => q.status === 'accepted');
  const pending  = quotes.filter((q: any) => q.status === 'sent').length;
  const revenue  = accepted.reduce((s: number, q: any) => s + calcTotals(q.items ?? [], q.taxPercent ?? 0, q.discountPercent ?? 0).total, 0);
  const recent   = [...quotes].sort((a: any, b: any) => new Date(b.updatedAt ?? 0).valueOf() - new Date(a.updatedAt ?? 0).valueOf()).slice(0, 10);

  const stats = [
    { label: 'Total Quotes', value: quotes.length,    cls: '' },
    { label: 'Pending',      value: pending,          cls: 'stat-card--warning' },
    { label: 'Accepted',     value: accepted.length,  cls: 'stat-card--success' },
    { label: 'Total Value',  value: money(revenue, currency), cls: 'stat-card--accent' },
  ];

  return (
    <div className="page-enter">
      <div className="page-header">
        <h1 className="page-title">Dashboard</h1>
        <Link to="/quotes/new" className="btn btn--primary"><Icon.plus /> New Quote</Link>
      </div>

      <div className="stat-grid">
        {stats.map((s) => (
          <div key={s.label} className={`stat-card ${s.cls}`}>
            <div className="stat-label">{s.label}</div>
            <div className="stat-value">{s.value}</div>
          </div>
        ))}
      </div>

      <section>
        <h2 className="section-title">Recent Quotes</h2>
        {quotes.length === 0 ? (
          <div className="empty-state">
            <Icon.emptyDoc />
            <h3>No quotes yet</h3>
            <p>Create your first quote to get started.</p>
            <Link to="/quotes/new" className="btn btn--primary"><Icon.plus /> New Quote</Link>
          </div>
        ) : (
          <div className="list">
            <div className="list-header">
              <span>Quote #</span><span>Title</span><span>Client</span><span>Date</span><span>Value</span><span>Status</span>
            </div>
            {recent.map((q: any) => {
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
      </section>
    </div>
  );
}
