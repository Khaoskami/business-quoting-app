import { useState } from 'react';
import { Link } from 'react-router-dom';
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
  const [emailFor, setEmailFor] = useState<any>(null);
  const [emailSubject, setEmailSubject] = useState('');
  const [emailMessage, setEmailMessage] = useState('');
  const [search, setSearch] = useState('');

  const save = useMutation({
    mutationFn: (data: any) => data.id ? api.clients.update(data.id, data) : api.clients.create(data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['clients'] }); setForm(null); notify('Saved.'); },
    onError: (e: any) => notify(e.message ?? 'Save failed', 'error'),
  });
  const sendEmail = useMutation({
    mutationFn: () => api.clients.email(emailFor.id, { subject: emailSubject, message: emailMessage }),
    onSuccess: (result) => { qc.invalidateQueries({ queryKey: ['profile'] }); setEmailFor(null); setEmailSubject(''); setEmailMessage(''); notify(result.remainingEmailCredits == null ? 'Email queued.' : `Email queued. ${result.remainingEmailCredits} client email credits remain.`); },
    onError: (e: any) => notify(e.message ?? 'Could not send email.', 'error'),
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

      {max != null && (
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
                <Link to={`/quotes/new?client=${encodeURIComponent(c.id)}`} className="btn btn--primary btn--sm">New quote</Link>
                {tf.directEmail && c.email && <button onClick={() => { setEmailFor(c); setEmailSubject(`Hello ${c.name || c.company || ''}`.trim()); setEmailMessage(''); }} className="btn btn--secondary btn--sm">Email</button>}
                <button onClick={() => setForm({ ...c })} className="btn btn--ghost btn--sm">Edit</button>
                <button onClick={() => { if (confirm('Delete client?')) del.mutate(c.id); }} className="btn btn--danger btn--sm">Delete</button>
              </div>
            </div>
          ))}
        </div>
      )}

      {emailFor && <div className="modal-overlay" onMouseDown={(e) => { if (e.target === e.currentTarget && !sendEmail.isPending) setEmailFor(null); }}>
        <div className="modal modal--wide" role="dialog" aria-modal="true" aria-labelledby="client-email-title">
          <div className="modal-header"><div><div className="eyebrow">Client email</div><h2 id="client-email-title">Email {emailFor.name || emailFor.company}</h2><div className="field-hint">{emailFor.email}</div></div><button className="btn btn--ghost btn--sm" onClick={() => setEmailFor(null)} disabled={sendEmail.isPending}>Close</button></div>
          <div className="modal-body">
            <div className="field-group"><label className="field-label" htmlFor="client-email-subject">Subject</label><input id="client-email-subject" autoFocus className="field-input" maxLength={200} value={emailSubject} onChange={(e) => setEmailSubject(e.target.value)} /></div>
            <div className="field-group" style={{ marginTop: 14 }}><label className="field-label" htmlFor="client-email-message">Message</label><textarea id="client-email-message" className="field-textarea" rows={10} maxLength={10000} value={emailMessage} onChange={(e) => setEmailMessage(e.target.value)} placeholder="Write your message to the client..." /></div>
            <div className="field-hint" style={{ marginTop: 6 }}>{emailMessage.length}/10,000 characters · Replies go to your business email.</div>
          </div>
          <div className="modal-footer"><button className="btn btn--ghost" onClick={() => setEmailFor(null)} disabled={sendEmail.isPending}>Cancel</button><button className="btn btn--primary" disabled={sendEmail.isPending || !emailSubject.trim() || !emailMessage.trim()} onClick={() => sendEmail.mutate()}>{sendEmail.isPending ? 'Sending...' : 'Send email'}</button></div>
        </div>
      </div>}
    </div>
  );
}