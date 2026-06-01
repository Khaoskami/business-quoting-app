import { NavLink, useNavigate } from 'react-router-dom';
import { Icon } from './Icons';
import { useAuth } from '../auth-context';

const NAV = [
  { to: '/',         label: 'Dashboard', icon: Icon.dashboard, end: true },
  { to: '/quotes',   label: 'Quotes',    icon: Icon.quotes },
  { to: '/clients',  label: 'Clients',   icon: Icon.clients },
  { to: '/catalog',  label: 'Catalog',   icon: Icon.catalog },
];

export function Sidebar({ biz, tier }: { biz: any; tier: string }) {
  const { user, signOut } = useAuth();
  const nav = useNavigate();
  const tierCls = tier === 'pro' ? 'tier-badge--pro' : tier === 'business' ? 'tier-badge--business' : '';

  async function handleSignOut() {
    await signOut();
    nav('/login', { replace: true });
  }

  return (
    <aside className="sidebar" aria-label="Primary navigation">
      <div className="sidebar-brand">
        <div className="brand-mark" aria-hidden>BQ</div>
        <div style={{ minWidth: 0 }}>
          <div className="brand-name">{biz.name || 'Business Quotes'}</div>
          <div className="brand-sub">{user?.email}</div>
        </div>
      </div>
      <nav className="sidebar-nav">
        {NAV.map((n) => {
          const I = n.icon;
          return (
            <NavLink key={n.to} to={n.to} end={n.end}
                     className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
              <I /><span>{n.label}</span>
            </NavLink>
          );
        })}
      </nav>
      <div className="sidebar-footer">
        <span className={`tier-badge ${tierCls}`} style={{ margin: '4px 4px 8px', alignSelf: 'flex-start' }}>
          {tier.charAt(0).toUpperCase() + tier.slice(1)}
        </span>
        <NavLink to="/settings" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <Icon.settings /><span>Settings</span>
        </NavLink>
        {user?.isAdmin && (
          <NavLink to="/admin" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <Icon.admin /><span>Admin</span>
          </NavLink>
        )}
        <button className="nav-item nav-item--danger" onClick={handleSignOut} aria-label="Sign out">
          <Icon.logout /><span>Sign out</span>
        </button>
      </div>
    </aside>
  );
}
