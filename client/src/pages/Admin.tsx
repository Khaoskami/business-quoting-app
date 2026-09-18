import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../api';
import { useToast } from '../components/Toast';
import { fmtDate } from '../lib/quote';

export default function Admin() {
  const qc = useQueryClient();
  const { notify } = useToast();
  const { data: users = [] } = useQuery({ queryKey: ['admin-users'], queryFn: api.admin.users });
  const { data: stats }      = useQuery({ queryKey: ['admin-stats'], queryFn: api.admin.stats });

  const comp = useMutation({
    mutationFn: ({ id, tier, note }: { id: string; tier: string; note?: string }) => api.admin.comp(id, tier, note),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['admin-users'] }); qc.invalidateQueries({ queryKey: ['admin-stats'] }); notify('Comp granted.'); },
    onError: (e: any) => notify(e.message ?? 'Failed', 'error'),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.admin.revoke(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['admin-users'] }); qc.invalidateQueries({ queryKey: ['admin-stats'] }); notify('Revoked.'); },
  });
  const toggleAdmin = useMutation({
    mutationFn: ({ id, isAdmin }: { id: string; isAdmin: boolean }) => api.admin.toggleAdmin(id, isAdmin),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['admin-users'] }); notify('Updated.'); },
  });

  const statCards = [
    { label: 'Total Users',     value: stats?.totalUsers ?? 'Not set',    cls: '' },
    { label: 'Pro Users',       value: stats?.proUsers ?? 'Not set',      cls: 'stat-card--success' },
    { label: 'Business Users',  value: stats?.businessUsers ?? 'Not set', cls: 'stat-card--accent' },
    { label: 'Comped',          value: stats?.compedUsers ?? 'Not set',   cls: 'stat-card--warning' },
  ];

  return (
    <div className="page-enter">
      <div className="page-header"><h1 className="page-title">Admin</h1></div>

      <div className="stat-grid">
        {statCards.map(s => (
          <div key={s.label} className={`stat-card ${s.cls}`}>
            <div className="stat-label">{s.label}</div>
            <div className="stat-value">{s.value}</div>
          </div>
        ))}
      </div>

      <h2 className="section-title">Users</h2>
      <div style={{ overflowX: 'auto' }}>
        <table className="admin-table">
          <thead>
            <tr>
              <th>Name</th><th>Email</th><th>Joined</th><th>Tier</th><th>Status</th><th>Comped</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u: any) => {
              const tierCls = u.tier === 'pro' ? 'tier-badge--pro' : u.tier === 'business' ? 'tier-badge--business' : '';
              return (
                <tr key={u.id}>
                  <td>{u.name}{u.isAdmin && <span className="badge badge--accepted" style={{ marginLeft: 6 }}>Admin</span>}</td>
                  <td>{u.email}</td>
                  <td>{fmtDate(u.createdAt)}</td>
                  <td><span className={`tier-badge ${tierCls}`}>{u.tier ?? 'free'}</span></td>
                  <td>{u.status ?? 'Not set'}</td>
                  <td>{u.comped ? (u.compedNote || 'yes') : 'Not set'}</td>
                  <td>
                    <div className="admin-actions">
                      <button className="btn btn--ghost btn--sm" onClick={() => comp.mutate({ id: u.id, tier: 'pro' })}>Grant Pro</button>
                      <button className="btn btn--ghost btn--sm" onClick={() => comp.mutate({ id: u.id, tier: 'business' })}>Grant Business</button>
                      <button className="btn btn--ghost btn--sm" onClick={() => revoke.mutate(u.id)}>Revoke</button>
                      <button className="btn btn--ghost btn--sm" onClick={() => toggleAdmin.mutate({ id: u.id, isAdmin: !u.isAdmin })}>
                        {u.isAdmin ? 'Remove Admin' : 'Make Admin'}
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
