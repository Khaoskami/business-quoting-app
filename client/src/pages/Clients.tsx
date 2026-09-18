import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../api';
import { Icon } from '../components/Icons';
import { useToast } from '../components/Toast';
import { newClient, validateUrl } from '../lib/quote';

const FIELDS = [
  { key: 'name', label: 'Name *', ph: 'Jane Doe' },
  { key: 'company', label: 'Company', ph: 'Acme Pty Ltd' },
  { key: 'email', label: 'Email', ph: 'jane@acme.co' },
  { key: 'phone', label: 'Phone', ph: '+27 12 345 6789' },
  { key: 'website', label: 'Website', ph: 'https://clientsite.com' },
  { key: 'address', label: 'Address', ph: '123 Long St', span: true },
  { key: 'notes', label: 'Notes', ph: 'Account terms...', span: true },
];

export default function Clients() {
  const qc = useQueryClient();
  const { notify } = useToast();
  const { data: clients = [] } = useQuery({ queryKey: ['clients'], queryFn: api.clients.list });
  const { data: profile }      = useQuery({ queryKey: ['profile'], queryFn: api.profile.get });
  const tf = profile?.subscription?.limits?.features ?? {};
  const max = profile?.subscription?.limits?.maxClients;

  const [form, setForm] = useState<any>(null);
  const [search, setSearch] = useState('');

  const save = useMutation({
    mutationFn: (data: any) => data.id ? api.clients.update(data.id, data) : api.clients.create(data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['clients'] }); setForm(null); notify('Saved.'); },
    onError: (e: any) => notify(e.message ?? 'Save failed', 'error'),
  });
  const del = useMutation({
    mutationFn: (id: string) => api.clients.delete(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['clients'] }); notify('Deleted.', 'error'); },
  });

  const filtered = clients.filter((c: any) => !search || (c.name || '').toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="page-enter">
      <div className="page-header">
        <h1 className="page-title">Clients</h1>
        <button onClick={() => setForm(newClient())} className="btn btn--primary"><Icon.plus /> Add Client</button>
      </div>

      {typeof max === 'number' && max !== Infinity && (
        <div className="field-hint" style={{ marginBottom: 12 }}>{clients.length} of {max} clients used</div>
      )}

      {form && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="form-grid">
            {FIELDS.map(f => {
              if (f.key === 'website' && !tf.clientUrl) {
                return <div key={f.key} className="field-group"><label className="field-label">Website</label><div className="field-hint" style={{ padding: '10px 0' }}>Pro feature</div></div>;
              }
              return (
                <div key={f.key} className={`field-group ${f.span ? 'field-group--span' : ''}`}>
                  <label className="field-label">{f.label}</label>
                  <input className="field-input" value={form[f.key] ?? ''}
                         onChange={(e) => setForm({ ...form, [f.key]: e.target.value })}
                         placeholder={f.ph} />
                </div>
              );
            })}
          </div>
          <div className="action-bar" style={{ marginTop: 16 }}>
            <button onClick={() => {
              if (!form.name?.trim()) { notify('Name required.', 'error'); return; }
              save.mutate({ ...form, website: validateUrl(form.website) });
            }} className={`btn btn--primary ${save.isPending ? 'btn--loading' : ''}`} disabled={save.isPending}>Save</button>
            <button onClick={() => setForm(null)} className="btn btn--ghost">Cancel</button>
          </div>
        </div>
      )}

      <input value={search} onChange={(e) => setSearch(e.target.value)}
             placeholder="Search clients..." className="field-input" style={{ marginBottom: 12 }} />

      {filtered.length === 0 ? (
        <div className="empty-state">
          <Icon.emptyUsers />
          <h3>{clients.length === 0 ? 'No clients yet' : 'No results'}</h3>
          {clients.length === 0 && <p>Add your first client to link them to quotes.</p>}
        </div>
      ) : (
        <div className="simple-list">
          {filtered.map((c: any) => (
            <div key={c.id} className="simple-row">
              <div style={{ minWidth: 0 }}>
                <div className="name">{c.name}{c.company && <span style={{ fontWeight: 400, color: 'var(--text-secondary)' }}> · {c.company}</span>}</div>
                <div className="meta">{[c.email, c.phone, c.website].filter(Boolean).join(' · ') || ''}</div>
              </div>
              <div className="simple-row-actions">
                <button onClick={() => setForm({ ...c })} className="btn btn--ghost btn--sm">Edit</button>
                <button onClick={() => { if (confirm('Delete client?')) del.mutate(c.id); }} className="btn btn--danger btn--sm">Delete</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
