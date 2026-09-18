const base = '/api';


async function requestBlob(path: string, publicRequest = false): Promise<{ blob: Blob; filename: string }> {
  const res = await fetch(base + path, { credentials: publicRequest ? 'omit' : 'include', headers: { Accept: 'application/pdf' } });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }));
    throw new Error(err.error ?? 'Request failed');
  }
  const disposition = res.headers.get('content-disposition') || '';
  const match = disposition.match(/filename="([^"]+)"/i);
  return { blob: await res.blob(), filename: match?.[1] || 'document.pdf' };
}

async function request<T>(path: string, init?: RequestInit, publicRequest = false): Promise<T> {
  const res = await fetch(base + path, {
    credentials: publicRequest ? 'omit' : 'include',
    headers: { Accept: 'application/json', ...(init?.body ? { 'Content-Type': 'application/json' } : {}), ...(init?.headers ?? {}) },
    ...init,
  });
  if (res.status === 401 && !publicRequest) {
    if (!location.pathname.startsWith('/login') && !location.pathname.startsWith('/register')) window.location.href = '/login';
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }));
    throw new Error(err.error ?? 'Request failed');
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  profile: { get: () => request<{ profile: any; subscription: any }>('/profile'), save: (data: any) => request<{ ok: true }>('/profile', { method: 'PUT', body: JSON.stringify(data) }), export: () => fetch('/api/profile/export', { credentials: 'include' }).then(async r => { if (!r.ok) throw new Error('Could not export account data'); return { blob: await r.blob(), disposition: r.headers.get('content-disposition') }; }) },
  quotes: {
    list: (includeDeleted = false) => request<any[]>(`/quotes${includeDeleted ? '?includeDeleted=1' : ''}`),
    create: (data: any, idempotencyKey = crypto.randomUUID()) => request<any>('/quotes', { method: 'POST', headers: { 'Idempotency-Key': idempotencyKey }, body: JSON.stringify(data) }),
    update: (id: string, data: any) => request<any>(`/quotes/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    delete: (id: string) => request<{ ok: true; softDeleted: true }>(`/quotes/${id}`, { method: 'DELETE' }),
    restore: (id: string) => request<{ ok: true }>(`/quotes/${id}/restore`, { method: 'POST' }),
    events: (id: string) => request<any[]>(`/quotes/${id}/events`),
    duplicate: (id: string, idempotencyKey = crypto.randomUUID()) => request<any>(`/quotes/${id}/duplicate`, { method: 'POST', headers: { 'Idempotency-Key': idempotencyKey }, body: '{}' }),
    accept: (id: string) => request<any>(`/quotes/${id}/accept`, { method: 'POST', body: JSON.stringify({ confirmedByClient: true }) }),
    send: (id: string) => request<{ ok: true; url: string; queued: boolean }>(`/quotes/${id}/send`, { method: 'POST' }),
    pdf: (id: string) => requestBlob(`/quotes/${id}/pdf`),
  },
  invoices: {
    list: (includeDeleted = false) => request<any[]>(`/invoices${includeDeleted ? '?includeDeleted=1' : ''}`),
    delete: (id: string) => request<{ ok: true; softDeleted: true }>(`/invoices/${id}`, { method: 'DELETE' }),
    restore: (id: string) => request<{ ok: true }>(`/invoices/${id}/restore`, { method: 'POST' }),
    events: (id: string) => request<any[]>(`/invoices/${id}/events`),
    setStatus: (id: string, status: 'void' | 'unpaid') => request<{ ok: true }>(`/invoices/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status }) }),
    share: (id: string) => request<{ ok: true; url: string }>(`/invoices/${id}/share`, { method: 'POST' }),
    recordPayment: (id: string, data: any, idempotencyKey = crypto.randomUUID()) => request<any>(`/invoices/${id}/payments`, { method: 'POST', headers: { 'Idempotency-Key': idempotencyKey }, body: JSON.stringify(data) }),
    pdf: (id: string) => requestBlob(`/invoices/${id}/pdf`),
  },
  clients: {
    list: () => request<any[]>('/clients'), create: (data: any) => request<any>('/clients', { method: 'POST', body: JSON.stringify(data) }), update: (id: string, data: any) => request<any>(`/clients/${id}`, { method: 'PUT', body: JSON.stringify(data) }), delete: (id: string) => request<{ ok: true }>(`/clients/${id}`, { method: 'DELETE' }),
  },
  catalog: {
    list: () => request<any[]>('/catalog'), create: (data: any) => request<any>('/catalog', { method: 'POST', body: JSON.stringify(data) }), update: (id: string, data: any) => request<any>(`/catalog/${id}`, { method: 'PUT', body: JSON.stringify(data) }), delete: (id: string) => request<{ ok: true }>(`/catalog/${id}`, { method: 'DELETE' }),
  },
  billing: { checkout: (tier: string) => request<{ url: string }>('/billing/checkout', { method: 'POST', body: JSON.stringify({ tier }) }), cancel: () => request<{ ok: true }>('/billing/cancel', { method: 'POST' }) },
  admin: {
    users: () => request<any[]>('/admin/users'), stats: () => request<any>('/admin/stats'),
    comp: (id: string, tier: string, note?: string) => request<{ ok: true }>(`/admin/users/${id}/comp`, { method: 'POST', body: JSON.stringify({ tier, note }) }),
    revoke: (id: string) => request<{ ok: true }>(`/admin/users/${id}/revoke`, { method: 'POST' }),
    toggleAdmin: (id: string, isAdmin: boolean) => request<{ ok: true }>(`/admin/users/${id}/admin`, { method: 'POST', body: JSON.stringify({ isAdmin }) }),
  },
  public: {
    quote: (token: string) => request<any>(`/public/quotes/${encodeURIComponent(token)}`, undefined, true),
    respondQuote: (token: string, data: any) => request<any>(`/public/quotes/${encodeURIComponent(token)}/respond`, { method: 'POST', body: JSON.stringify(data) }, true),
    invoice: (token: string) => request<any>(`/public/invoices/${encodeURIComponent(token)}`, undefined, true),
    quotePdf: (token: string) => requestBlob(`/public/quotes/${encodeURIComponent(token)}/pdf`, true),
    invoicePdf: (token: string) => requestBlob(`/public/invoices/${encodeURIComponent(token)}/pdf`, true),
  },
};
