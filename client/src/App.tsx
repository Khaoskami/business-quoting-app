import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './auth-context';
import { AppShell } from './components/AppShell';
import Login    from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Quotes    from './pages/Quotes';
import Editor    from './pages/Editor';
import Clients   from './pages/Clients';
import Catalog   from './pages/Catalog';
import Settings  from './pages/Settings';
import Admin     from './pages/Admin';

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="page-loading">Loading…</div>;
  if (!user)   return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function RequireAdmin({ children }: { children: React.ReactNode }) {
  const { user } = useAuth();
  if (!user?.isAdmin) return <Navigate to="/" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login"    element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route element={<RequireAuth><AppShell /></RequireAuth>}>
        <Route index element={<Dashboard />} />
        <Route path="quotes"          element={<Quotes />} />
        <Route path="quotes/new"      element={<Editor />} />
        <Route path="quotes/:id/edit" element={<Editor />} />
        <Route path="clients"         element={<Clients />} />
        <Route path="catalog"         element={<Catalog />} />
        <Route path="settings"        element={<Settings />} />
        <Route path="admin" element={<RequireAdmin><Admin /></RequireAdmin>} />
      </Route>
    </Routes>
  );
}
