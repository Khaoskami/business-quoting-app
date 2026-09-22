import { Component, type ErrorInfo, type ReactNode } from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { useAuth } from './auth-context';
import { AppShell } from './components/AppShell';
import Login from './pages/Login';
import Register from './pages/Register';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import VerifyEmail from './pages/VerifyEmail';
import Dashboard from './pages/Dashboard';
import Quotes from './pages/Quotes';
import Invoices from './pages/Invoices';
import Editor from './pages/Editor';
import Clients from './pages/Clients';
import Catalog from './pages/Catalog';
import Settings from './pages/Settings';
import Admin from './pages/Admin';
import Landing from './pages/Landing';
import PublicQuote from './pages/PublicQuote';
import PublicInvoice from './pages/PublicInvoice';


class AppErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean; message: string }> {
  state = { hasError: false, message: '' };
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, message: error?.message || 'The page could not be loaded.' };
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[app-render-error]', error, info);
  }
  render() {
    if (!this.state.hasError) return this.props.children;
    return (
      <div className="app-error-screen" role="alert">
        <div className="app-error-card">
          <div className="eyebrow">Business Quotes</div>
          <h1>We couldn't load this page</h1>
          <p>{this.state.message}</p>
          <div className="app-error-actions">
            <button className="btn btn--primary" onClick={() => window.location.reload()}>Reload page</button>
            <button className="btn btn--secondary" onClick={() => { this.setState({ hasError: false, message: '' }); window.history.replaceState({}, '', '/'); window.location.href = '/'; }}>Go to dashboard</button>
          </div>
        </div>
      </div>
    );
  }
}

function RouteAnnouncer() {
  const location = useLocation();
  return <span className="sr-only" aria-live="polite" key={location.pathname}>{location.pathname}</span>;
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="page-loading">Loading...</div>;
  return user ? <>{children}</> : <Navigate to="/login" replace />;
}

function Home() {
  const { user, loading } = useAuth();
  if (loading) return <div className="page-loading">Loading...</div>;
  return user ? <Dashboard /> : <Landing />;
}

function RequireAdmin({ children }: { children: React.ReactNode }) {
  const { user } = useAuth();
  return user?.isAdmin ? <>{children}</> : <Navigate to="/" replace />;
}

export default function App() {
  return (
    <AppErrorBoundary>
      <RouteAnnouncer />
      <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route path="/verify-email" element={<VerifyEmail />} />
      <Route path="/public/quote/:token" element={<PublicQuote />} />
      <Route path="/public/invoice/:token" element={<PublicInvoice />} />
      <Route index element={<Home />} />
      <Route element={<RequireAuth><AppShell /></RequireAuth>}>
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="quotes" element={<Quotes />} />
        <Route path="invoices" element={<Invoices />} />
        <Route path="quotes/new" element={<Editor />} />
        <Route path="quotes/:id/edit" element={<Editor />} />
        <Route path="clients" element={<Clients />} />
        <Route path="catalog" element={<Catalog />} />
        <Route path="settings" element={<Settings />} />
        <Route path="admin" element={<RequireAdmin><Admin /></RequireAdmin>} />
      </Route>
      </Routes>
    </AppErrorBoundary>
  );
}
