import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './auth-context';
import { AppShell } from './components/AppShell';
import Login from './pages/Login';
import Register from './pages/Register';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import Dashboard from './pages/Dashboard';
import Quotes from './pages/Quotes';
import Invoices from './pages/Invoices';
import Editor from './pages/Editor';
import Clients from './pages/Clients';
import Catalog from './pages/Catalog';
import Settings from './pages/Settings';
import Admin from './pages/Admin';
import PublicQuote from './pages/PublicQuote';
import PublicInvoice from './pages/PublicInvoice';

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="page-loading">Loading...</div>;
  return user ? <>{children}</> : <Navigate to="/login" replace />;
}

function RequireAdmin({ children }: { children: React.ReactNode }) {
  const { user } = useAuth();
  return user?.isAdmin ? <>{children}</> : <Navigate to="/" replace />;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route path="/public/quote/:token" element={<PublicQuote />} />
      <Route path="/public/invoice/:token" element={<PublicInvoice />} />
      <Route element={<RequireAuth><AppShell /></RequireAuth>}>
        <Route index element={<Dashboard />} />
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
  );
}
