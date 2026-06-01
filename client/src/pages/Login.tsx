import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../auth-context';

export default function Login() {
  const { signIn } = useAuth();
  const nav = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(''); setLoading(true);
    try {
      await signIn(email, password);
      nav('/', { replace: true });
    } catch (e: any) {
      setErr(e.message ?? 'Sign-in failed');
      setLoading(false);
    }
  }

  return (
    <div className="lock-screen">
      <form className="lock-card" onSubmit={submit}>
        <div className="lock-logo">BQ</div>
        <h1 className="lock-title">Sign in</h1>
        <p className="lock-subtitle">Welcome back to Business Quotes.</p>

        <div className="field-group" style={{ marginBottom: 12 }}>
          <label className="field-label" htmlFor="email">Email</label>
          <input id="email" type="email" autoComplete="email" className="field-input" required
                 value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />
        </div>
        <div className="field-group" style={{ marginBottom: 12 }}>
          <label className="field-label" htmlFor="password">Password</label>
          <input id="password" type="password" autoComplete="current-password" className="field-input" required
                 value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>

        {err && <div role="alert" className="field-error" style={{ marginBottom: 12 }}>{err}</div>}

        <button type="submit" disabled={loading} className={`btn btn--primary btn--full btn--lg ${loading ? 'btn--loading' : ''}`}>
          Sign in
        </button>

        <div className="lock-footer">
          New here? <Link to="/register">Create an account</Link>
        </div>
      </form>
    </div>
  );
}
