import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../api';
import { Icon } from '../components/Icons';
import { useToast } from '../components/Toast';
import { newProduct, UNITS, money } from '../lib/quote';

export default function Catalog() {
  const qc = useQueryClient();
  const { notify } = useToast();
  const { data: items = [] } = useQuery({ queryKey: ['catalog'], queryFn: api.catalog.list });
  const { data: profile }    = useQuery({ queryKey: ['profile'], queryFn: api.profile.get });
  const max = profile?.subscription?.limits?.maxCatalog;

  const [form, setForm] = useState<any>(null);
  const [search, setSearch] = useState('');
  const [fCat, setFCat] = useState('');

  const save = useMutation({
    mutationFn: (data: any) => data.id ? api.catalog.update(data.id, data) : api.catalog.create(data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['catalog'] }); setForm(null); notify('Saved.'); },
    onError: (e: any) => notify(e.message ?? 'Save failed', 'error'),
  });
  const del = useMutation({
    mutationFn: (id: string) => api.catalog.delete(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['catalog'] }); notify('Deleted.', 'error'); },
  });

  const categories = useMemo(() => [...new Set(items.map((p: any) => p.category).filter(Boolean))].sort(), [items]);
  const filtered = items.filter((p: any) => {
    const ms = !search || (p.name || '').toLowerCase().includes(search.toLowerCase());
    const mc = !fCat || p.category === fCat;
    return ms && mc;
  });

  return (
    <div className="page-enter">
      <div className="page-header">
        <h1 className="page-title">Catalog</h1>
        <button onClick={() => setForm(newProduct())} className="btn btn--primary"><Icon.plus /> Add Item</button>
      </div>

      {max != null && (
        <div className="field-hint" style={{ marginBottom: 12 }}>{items.length} of {max} catalog items used</div>
      )}

      {form && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="form-grid">
            <div className="field-group"><label className="field-label">Name *</label>
              <input className="field-input" value={form.name ?? ''} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Consultation" /></div>
            <div className="field-group"><label className="field-label">Category</label>
              <input className="field-input" value={form.category ?? ''} onChange={(e) => setForm({ ...form, category: e.target.value })} placeholder="Labour" /></div>
            <div className="field-group field-group--span"><label className="field-label">Description</label>
              <input className="field-input" value={form.description ?? ''} onChange={(e) => setForm({ ...form, description: e.target.value })} /></div>
            <div className="field-group"><label className="field-label">Price</label>
              <input className="field-input" type="number" min={0} step={0.01} value={form.unitPrice ?? 0} onChange={(e) => setForm({ ...form, unitPrice: Number(e.target.value) })} /></div>
            <div className="field-group"><label className="field-label">Unit</label>
              <select className="field-select" value={form.unit ?? 'each'} onChange={(e) => setForm({ ...form, unit: e.target.value })}>
                {UNITS.map(u => <option key={u.value} value={u.value}>{u.label}</option>)}
              </select>
            </div>
          </div>
          <div className="action-bar" style={{ marginTop: 16 }}>
            <button onClick={() => {
              if (!form.name?.trim()) { notify('Name required.', 'error'); return; }
              save.mutate({ ...form, unitPrice: Math.max(0, Number(form.unitPrice) || 0) });
            }} className={`btn btn--primary ${save.isPending ? 'btn--loading' : ''}`} disabled={save.isPending}>Save</button>
            <button onClick={() => setForm(null)} className="btn btn--ghost">Cancel</button>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search..." className="field-input" />
        {categories.length > 0 && (
          <select value={fCat} onChange={(e) => setFCat(e.target.value)} className="field-select" style={{ width: 'auto' }}>
            <option value="">All categories</option>
            {categories.map((c: any) => <option key={c} value={c}>{c}</option>)}
          </select>
        )}
      </div>

      {filtered.length === 0 ? (
        <div className="empty-state">
          <Icon.emptyBox />
          <h3>{items.length === 0 ? 'Build your catalog' : 'No results'}</h3>
          {items.length === 0 && <p>Reusable products and services you can drop into quotes.</p>}
        </div>
      ) : (
        <div className="simple-list">
          {filtered.map((p: any) => (
            <div key={p.id} className="simple-row">
              <div style={{ minWidth: 0 }}>
                <div className="name">{p.name}{p.category && <span className="badge badge--draft" style={{ marginLeft: 8 }}>{p.category}</span>}</div>
                <div className="meta">{p.description || ''} · {money(p.unitPrice)}/{p.unit}</div>
              </div>
              <div className="simple-row-actions">
                <button onClick={() => setForm({ ...p })} className="btn btn--ghost btn--sm">Edit</button>
                <button onClick={() => { if (confirm('Delete item?')) del.mutate(p.id); }} className="btn btn--danger btn--sm">Delete</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
