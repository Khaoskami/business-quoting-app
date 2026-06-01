const base = '/api';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(base + path, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    ...init,
  });
  if (res.status === 401) {
    if (!location.pathname.startsWith('/login') && !location.pathname.startsWith('/register')) {
      window.location.href = '/login';
    }
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }));
    throw new Error(err.error ?? 'Request failed');
  }
  return res.json() as Promise<T>;
}

export const api = {
  profile: {
    get:  () => request<{ profile: any; subscription: any }>('/profile'),
    save: (data: any) => request<{ ok: true }>('/profile', { method: 'PUT', body: JSON.stringify(data) }),
  },
  quotes: {
    list:   () => request<any[]>('/quotes'),
    create: (data: any) => request<any>('/quotes', { method: 'POST', body: JSON.stringify(data) }),
    update: (id: string, data: any) => request<any>(`/quotes/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    delete: (id: string) => request<{ ok: true }>(`/quotes/${id}`, { method: 'DELETE' }),
  },
  clients: {
    list:   () => request<any[]>('/clients'),
    create: (data: any) => request<any>('/clients', { method: 'POST', body: JSON.stringify(data) }),
    update: (id: string, data: any) => request<any>(`/clients/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    delete: (id: string) => request<{ ok: true }>(`/clients/${id}`, { method: 'DELETE' }),
  },
  catalog: {
    list:   () => request<any[]>('/catalog'),
    create: (data: any) => request<any>('/catalog', { method: 'POST', body: JSON.stringify(data) }),
    update: (id: string, data: any) => request<any>(`/catalog/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    delete: (id: string) => request<{ ok: true }>(`/catalog/${id}`, { method: 'DELETE' }),
  },
  billing: {
    checkout: (tier: string) => request<{ url: string }>('/billing/checkout', { method: 'POST', body: JSON.stringify({ tier }) }),
    portal:   () => request<{ url: string }>('/billing/portal', { method: 'POST' }),
  },
  admin: {
    users:  () => request<any[]>('/admin/users'),
    stats:  () => request<any>('/admin/stats'),
    comp:   (id: string, tier: string, note?: string) =>
      request<{ ok: true }>(`/admin/users/${id}/comp`, { method: 'POST', body: JSON.stringify({ tier, note }) }),
    revoke: (id: string) => request<{ ok: true }>(`/admin/users/${id}/revoke`, { method: 'POST' }),
    toggleAdmin: (id: string, isAdmin: boolean) =>
      request<{ ok: true }>(`/admin/users/${id}/admin`, { method: 'POST', body: JSON.stringify({ isAdmin }) }),
  },
};
