import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../api';
import { Icon } from '../components/Icons';
import { useToast } from '../components/Toast';
import { calcTotals, money, fmtDate, buildPrintHtml } from '../lib/quote';

// Invoice status → reuse existing badge palette (green / amber / grey).
const INV_BADGE: Record<string, { label: string; cls: string }> = {
  paid:   { label: 'Paid',   cls: 'badge--accepted' },
  unpaid: { label: 'Unpaid', cls: 'badge--sent' },
  void:   { label: 'Void',   cls: 'badge--expired' },
};

export default function Invoices() {
  const qc = useQueryClient();
  const { notify } = useToast();
  const { data: invoices = [] } = useQuery({ queryKey: ['invoices'], queryFn: api.invoices.list });
  const { data: profile }       = useQuery({ queryKey: ['profile'], queryFn: api.profile.get });
  const biz = profile?.profile ?? {};

  const setStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: 'unpaid' | 'paid' | 'void' }) =>
      api.invoices.setStatus(id, status),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['invoices'] }); notify('Invoice updated.'); },
    onError: (e: any) => notify(e.message ?? 'Update failed', 'error'),
  });

  function handlePrint(inv: any) {
    // The snapshot is quote-shaped; override the heading so it reads as an invoice.
    const html = buildPrintHtml(
      { ...inv, title: `Invoice ${inv.invoiceNumber}${inv.title ? ` — ${inv.title}` : ''}`, quoteNumber: inv.invoiceNumber },
      biz,
    );
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const w = window.open(url, '_blank');
    if (w) w.addEventListener('load', () => URL.revokeObjectURL(url), { once: true });
  }

  return (
    <div className="page-enter">
      <div className="page-header">
        <h1 className="page-title">Invoices</h1>
      </div>

      {invoices.length === 0 ? (
        <div className="empty-state">
          <Icon.emptyDoc />
          <h3>No invoices yet</h3>
          <p className="field-hint">Invoices are issued when you confirm a client has accepted a quote.</p>
        </div>
      ) : (
        <div className="list">
          <div className="list-header">
            <span>Invoice #</span><span>Client</span><span>Date</span><span>Value</span><span>Status</span><span>Actions</span>
          </div>
          {invoices.map((inv: any) => {
            const { total } = calcTotals(inv.items ?? [], inv.taxPercent ?? 0, inv.discountPercent ?? 0);
            const b = INV_BADGE[inv.status] ?? INV_BADGE.unpaid;
            return (
              <div key={inv.id} className="list-row">
                <span className="num">{inv.invoiceNumber || '—'}</span>
                <span className="client">{inv.clientName || '—'}</span>
                <span className="date">{fmtDate(inv.createdAt)}</span>
                <span className="value">{money(total, inv.currency)}</span>
                <span className="status-cell"><span className={`badge ${b.cls}`}>{b.label}</span></span>
                <span className="invoice-actions" style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                  <button className="btn btn--ghost btn--sm" onClick={() => handlePrint(inv)}>Print</button>
                  {inv.status !== 'paid' && inv.status !== 'void' && (
                    <button className="btn btn--secondary btn--sm" disabled={setStatus.isPending}
                            onClick={() => setStatus.mutate({ id: inv.id, status: 'paid' })}>Mark paid</button>
                  )}
                  {inv.status !== 'void' && (
                    <button className="btn btn--ghost btn--sm" disabled={setStatus.isPending}
                            onClick={() => { if (confirm('Void this invoice?')) setStatus.mutate({ id: inv.id, status: 'void' }); }}>Void</button>
                  )}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
