import { NavLink } from 'react-router-dom';
import { Icon } from './Icons';

const NAV = [
  { to: '/',        label: 'Dashboard', icon: Icon.dashboard, end: true },
  { to: '/quotes',  label: 'Quotes',    icon: Icon.quotes },
  { to: '/invoices', label: 'Invoices', icon: Icon.invoice },
  { to: '/clients', label: 'Clients',   icon: Icon.clients },
  { to: '/catalog', label: 'Catalog',   icon: Icon.catalog },
];

export function BottomNav() {
  return (
    <nav className="bottom-nav" aria-label="Primary navigation">
      <div className="bottom-nav-inner">
        {NAV.map((n) => {
          const I = n.icon;
          return (
            <NavLink key={n.to} to={n.to} end={n.end}
                     className={({ isActive }) => `bottom-nav-item ${isActive ? 'active' : ''}`}>
              <I /><span>{n.label}</span>
            </NavLink>
          );
        })}
      </div>
    </nav>
  );
}
