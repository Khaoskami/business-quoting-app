import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api';
import { Icon } from '../components/Icons';
import { money, fmtDate } from '../lib/quote';
import { invoiceAttention, quoteAttention, toneClass } from '../lib/workflow';

function groupedMoney(rows: any[], getAmount: (row: any) => number, fallback = 'ZAR') {
  const grouped = new Map<string, number>();
  rows.forEach((row) => {
    const currency = row.currency || fallback;
    grouped.set(currency, (grouped.get(currency) || 0) + getAmount(row));
  });
  const parts = [...grouped.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([currency, amount]) => money(amount, currency));
  return parts.length ? parts.join(' · ') : money(0, fallback);
}

export default function Dashboard() {
  const { data: quotes = [] } = useQuery({ queryKey: ['quotes'], queryFn: api.quotes.list });
  const { data: invoices = [] } = useQuery({ queryKey: ['invoices'], queryFn: () => api.invoices.list() });
  const { data: clients = [] } = useQuery({ queryKey: ['clients'], queryFn: api.clients.list });

  const activeQuotes = quotes.filter((q: any) => !q.deletedAt);
  const activeInvoices = invoices.filter((inv: any) => !inv.deletedAt);
  const quoteFollowUps = activeQuotes.filter((q: any) => quoteAttention(q).label === 'Follow up');
  const expiringQuotes = activeQuotes.filter((q: any) => ['Act soon', 'Expired'].includes(quoteAttention(q).label));
  const overdueInvoices = activeInvoices.filter((inv: any) => invoiceAttention(inv).label === 'Overdue');
  const dueSoonInvoices = activeInvoices.filter((inv: any) => invoiceAttention(inv).label === 'Due soon');
  const openInvoices = activeInvoices.filter((inv: any) => inv.status !== 'paid' && inv.status !== 'void');
  const outstanding = groupedMoney(openInvoices, (inv) => Number(inv.balance || 0));
  const accepted = activeQuotes.filter((q: any) => q.status === 'accepted').length;
  const awaiting = activeQuotes.filter((q: any) => q.status === 'sent').length;

  const attention = [
    ...overdueInvoices.slice(0, 4).map((inv: any) => ({ type: 'invoice', item: inv, attention: invoiceAttention(inv) })),
    ...quoteFollowUps.slice(0, 4).map((q: any) => ({ type: 'quote', item: q, attention: quoteAttention(q) })),
    ...expiringQuotes.filter((q: any) => quoteAttention(q).label === 'Act soon').slice(0, 2).map((q: any) => ({ type: 'quote', item: q, attention: quoteAttention(q) })),
    ...dueSoonInvoices.slice(0, 2).map((inv: any) => ({ type: 'invoice', item: inv, attention: invoiceAttention(inv) })),
  ].slice(0, 7);

  const recent = [
    ...activeQuotes.map((q: any) => ({ kind: 'quote', id: q.id, date: q.updatedAt, number: q.quoteNumber, title: q.title || 'Untitled quote', client: q.clientName || 'No client', status: quoteAttention(q) })),
    ...activeInvoices.map((inv: any) => ({ kind: 'invoice', id: inv.id, date: inv.updatedAt || inv.createdAt, number: inv.invoiceNumber, title: inv.title || 'Invoice', client: inv.clientName || 'No client', status: invoiceAttention(inv) })),
  ].sort((a, b) => new Date(b.date || 0).getTime() - new Date(a.date || 0).getTime()).slice(0, 8);

  return (
    <div className="page-enter">
      <div className="page-header dashboard-header">
        <div>
          <div className="eyebrow">Your work queue</div>
          <h1 className="page-title">Today</h1>
          <p className="page-subtitle">Create the quote, get the approval, send the invoice, collect the money.</p>
        </div>
        <div className="action-bar">
          <Link to="/quotes/new" className="btn btn--primary"><Icon.plus /> New quote</Link>
          <Link to="/clients" className="btn btn--secondary">Add client</Link>
        </div>
      </div>

      <div className="metric-grid">
        <div className="metric-card">
          <span className="metric-label">Outstanding</span>
          <strong className="metric-value">{outstanding}</strong>
          <span className="metric-note">Across {openInvoices.length} open invoice{openInvoices.length === 1 ? '' : 's'}</span>
        </div>
        <div className="metric-card metric-card--danger">
          <span className="metric-label">Overdue</span>
          <strong className="metric-value">{overdueInvoices.length}</strong>
          <span className="metric-note">Invoice{overdueInvoices.length === 1 ? '' : 's'} need attention</span>
        </div>
        <div className="metric-card metric-card--warning">
          <span className="metric-label">Awaiting reply</span>
          <strong className="metric-value">{awaiting}</strong>
          <span className="metric-note">Quote{awaiting === 1 ? '' : 's'} with clients</span>
        </div>
        <div className="metric-card metric-card--success">
          <span className="metric-label">Won</span>
          <strong className="metric-value">{accepted}</strong>
          <span className="metric-note">Accepted quote{accepted === 1 ? '' : 's'}</span>
        </div>
      </div>

      <div className="dashboard-grid">
        <section className="card workflow-card">
          <div className="section-heading-row">
            <div>
              <div className="eyebrow">Next actions</div>
              <h2 className="section-title">Needs attention</h2>
            </div>
            <span className="count-pill">{attention.length}</span>
          </div>
          {attention.length === 0 ? (
            <div className="success-empty">
              <div className="success-empty-icon">✓</div>
              <div>
                <h3>Nothing urgent</h3>
                <p>Your quotes and invoices are in good shape right now.</p>
              </div>
            </div>
          ) : (
            <div className="attention-list">
              {attention.map(({ type, item, attention: state }: any) => {
                const to = type === 'quote' ? `/quotes/${item.id}/edit` : '/invoices';
                const label = type === 'quote' ? item.quoteNumber || 'Quote' : item.invoiceNumber || 'Invoice';
                return (
                  <Link key={`${type}-${item.id}`} to={to} className="attention-row">
                    <span className={toneClass(state.tone)}>{state.label}</span>
                    <span className="attention-main">
                      <span className="attention-title">{label} · {item.clientName || 'No client'}</span>
                      <span className="attention-detail">{state.detail}</span>
                    </span>
                    <span className="attention-arrow">›</span>
                  </Link>
                );
              })}
            </div>
          )}
        </section>

        <section className="card quick-start-card">
          <div className="eyebrow">Keep it moving</div>
          <h2 className="section-title">Quote to cash</h2>
          <div className="flow-steps">
            <Link to="/quotes/new" className="flow-step"><span>1</span><div><strong>Build a quote</strong><small>Start from a client or catalog item</small></div></Link>
            <div className="flow-connector" />
            <Link to="/quotes" className="flow-step"><span>2</span><div><strong>Get approval</strong><small>Share one clean client link</small></div></Link>
            <div className="flow-connector" />
            <Link to="/invoices" className="flow-step"><span>3</span><div><strong>Collect payment</strong><small>Track balance and follow up</small></div></Link>
          </div>
          <div className="quick-start-meta">{clients.length} client{clients.length === 1 ? '' : 's'} · {activeQuotes.length} active quote{activeQuotes.length === 1 ? '' : 's'} · {activeInvoices.length} invoice{activeInvoices.length === 1 ? '' : 's'}</div>
        </section>
      </div>

      <section className="card recent-card">
        <div className="section-heading-row">
          <div>
            <div className="eyebrow">Activity</div>
            <h2 className="section-title">Recent documents</h2>
          </div>
          <div className="action-bar">
            <Link to="/quotes" className="btn btn--ghost btn--sm">All quotes</Link>
            <Link to="/invoices" className="btn btn--ghost btn--sm">All invoices</Link>
          </div>
        </div>
        {recent.length === 0 ? (
          <div className="empty-inline"><Icon.emptyDoc /><div><h3>Nothing here yet</h3><p>Create your first quote and the workflow starts here.</p></div><Link to="/quotes/new" className="btn btn--primary">New quote</Link></div>
        ) : (
          <div className="recent-list">
            {recent.map((item) => (
              <Link key={`${item.kind}-${item.id}`} to={item.kind === 'quote' ? `/quotes/${item.id}/edit` : '/invoices'} className="recent-row">
                <div className="recent-icon">{item.kind === 'quote' ? 'Q' : 'I'}</div>
                <div className="recent-main"><span className="recent-number">{item.number}</span><span className="recent-title">{item.title}</span><span className="recent-client">{item.client}</span></div>
                <span className={toneClass(item.status.tone)}>{item.status.label}</span>
                <span className="recent-date">{fmtDate(item.date)}</span>
              </Link>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
