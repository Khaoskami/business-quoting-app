import { useNavigate } from 'react-router-dom';
import { Icon } from './Icons';
import { useAuth } from '../auth-context';

export function MobileBar({ biz }: { biz: any }) {
  const nav = useNavigate();
  const { signOut } = useAuth();
  return (
    <header className="mobile-bar">
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <div className="brand-mark" aria-hidden>BQ</div>
        <span className="brand-name">{biz.name || 'Business Quotes'}</span>
      </div>
      <div style={{ display: 'flex', gap: 6 }}>
        <button aria-label="Settings" className="btn btn--ghost btn--sm" style={{ padding: 8 }} onClick={() => nav('/settings')}>
          <Icon.settings />
        </button>
        <button aria-label="Sign out" className="btn btn--ghost btn--sm" style={{ padding: 8 }} onClick={async () => { await signOut(); nav('/login'); }}>
          <Icon.logout />
        </button>
      </div>
    </header>
  );
}
