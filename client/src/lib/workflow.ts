export type Attention = {
  label: string;
  tone: 'neutral' | 'warning' | 'danger' | 'success';
  detail: string;
};

export function daysFromNow(value?: string | Date | null): number | null {
  if (!value) return null;
  const target = new Date(value).getTime();
  if (!Number.isFinite(target)) return null;
  const start = new Date();
  start.setHours(0, 0, 0, 0);
  const targetDay = new Date(target);
  targetDay.setHours(0, 0, 0, 0);
  return Math.round((targetDay.getTime() - start.getTime()) / 86_400_000);
}

export function relativeDay(value?: string | Date | null, future = 'Due') {
  const days = daysFromNow(value);
  if (days === null) return 'Not set';
  if (days === 0) return `${future} today`;
  if (days === 1) return `${future} tomorrow`;
  if (days === -1) return '1 day overdue';
  if (days < -1) return `${Math.abs(days)} days overdue`;
  return `${future} in ${days} days`;
}

export function quoteAttention(q: any): Attention {
  if (q.deletedAt) return { label: 'Archived', tone: 'neutral', detail: 'Archived' };
  if (q.status === 'accepted') return { label: 'Won', tone: 'success', detail: 'Accepted and invoiced' };
  if (q.status === 'declined') return { label: 'Needs revision', tone: 'danger', detail: 'Client declined this version' };
  if (q.status === 'expired') return { label: 'Expired', tone: 'neutral', detail: `Expired ${q.validUntil ? '' : 'quote'}`.trim() };
  if (q.status === 'sent') {
    const days = daysFromNow(q.validUntil);
    if (days !== null && days < 0) return { label: 'Expired', tone: 'danger', detail: 'Validity date passed' };
    if (days !== null && days <= 3) return { label: 'Act soon', tone: 'warning', detail: days === 0 ? 'Expires today' : `Expires in ${days} day${days === 1 ? '' : 's'}` };
    const sentAt = q.sentAt ? new Date(q.sentAt).getTime() : 0;
    const age = sentAt ? Math.floor((Date.now() - sentAt) / 86_400_000) : 0;
    if (age >= 3) return { label: 'Follow up', tone: 'warning', detail: `Awaiting reply for ${age} days` };
    return { label: 'Awaiting reply', tone: 'neutral', detail: 'Client has not responded yet' };
  }
  if (!q.clientId) return { label: 'Missing client', tone: 'warning', detail: 'Choose a client before sending' };
  if (!q.clientEmail) return { label: 'Missing email', tone: 'warning', detail: 'Add an email to send online' };
  const hasItems = Array.isArray(q.items) && q.items.some((item: any) => String(item.description || '').trim() && Number(item.quantity) > 0);
  if (!hasItems) return { label: 'Add line items', tone: 'warning', detail: 'Add at least one priced item' };
  return { label: 'Draft', tone: 'neutral', detail: 'Ready to finish' };
}

export function invoiceAttention(inv: any): Attention {
  if (inv.deletedAt) return { label: 'Archived', tone: 'neutral', detail: 'Archived' };
  if (inv.status === 'paid') return { label: 'Paid', tone: 'success', detail: 'Balance cleared' };
  if (inv.status === 'void') return { label: 'Void', tone: 'danger', detail: 'No payment can be recorded' };
  if (inv.status === 'overdue') {
    const days = daysFromNow(inv.dueAt);
    return { label: 'Overdue', tone: 'danger', detail: `${Math.abs(days ?? 0)} day${Math.abs(days ?? 0) === 1 ? '' : 's'} overdue` };
  }
  const days = daysFromNow(inv.dueAt);
  if (days !== null && days <= 3) return { label: 'Due soon', tone: 'warning', detail: days === 0 ? 'Due today' : `Due in ${days} day${days === 1 ? '' : 's'}` };
  if (inv.status === 'partially_paid') return { label: 'Part paid', tone: 'warning', detail: 'Balance remains' };
  return { label: 'Open', tone: 'neutral', detail: 'Awaiting payment' };
}

export function toneClass(tone: Attention['tone']) {
  return `attention attention--${tone}`;
}

export function quoteHasWork(q: any) {
  const attention = quoteAttention(q);
  return ['warning', 'danger'].includes(attention.tone);
}
