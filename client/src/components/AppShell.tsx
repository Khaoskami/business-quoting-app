import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { BottomNav } from './BottomNav';
import { MobileBar } from './MobileBar';
import { ToastProvider } from './Toast';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api';

export function AppShell() {
  const { data: profile } = useQuery({ queryKey: ['profile'], queryFn: api.profile.get });
  const biz = profile?.profile ?? {};
  const tier = profile?.subscription?.tier ?? 'free';

  return (
    <ToastProvider>
      <div className="app-shell">
        <Sidebar biz={biz} tier={tier} />
        <div style={{ display: 'contents' }}>
          <MobileBar biz={biz} />
          <main className="main-content">
            <Outlet />
          </main>
          <BottomNav />
        </div>
      </div>
    </ToastProvider>
  );
}
