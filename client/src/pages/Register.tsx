import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../auth-context';

export default function Register() {
  const { signUp } = useAuth();
  const nav = useNavigate();
  const [name, setName]         = useState('');
  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm]   = useState('');
  const [err, setErr]           = useState('');
  const [loading, setLoading]   = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr('');
    if (password.length < 8) { setErr('Password must be at least 8 characters.'); return; }
    if (password !== confirm) { setErr('Passwords do not match.'); return; }
    setLoading(true);
    try {
      await signUp(name, email, password);
      nav('/', { replace: true });
    } catch (e: any) {
      setErr(e.message ?? 'Sign-up failed');
      setLoading(false);
    }
  }

  return (
    <div className="lock-screen">
      <form className="lock-card" onSubmit={submit}>
        <div className="lock-logo">BQ</div>
        <h1 className="lock-title">Create account</h1>
        <p className="lock-subtitle">Start with the free plan. Upgrade any time.</p>

        <div className="field-group" style={{ marginBottom: 12 }}>
          <label className="field-label" htmlFor="name">Name</label>
          <input id="name" autoComplete="name" required className="field-input"
                 value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        </div>
        <div className="field-group" style={{ marginBottom: 12 }}>
          <label className="field-label" htmlFor="email">Email</label>
          <input id="email" type="email" autoComplete="email" required className="field-input"
                 value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div className="field-group" style={{ marginBottom: 12 }}>
          <label className="field-label" htmlFor="password">Password</label>
          <input id="password" type="password" autoComplete="new-password" required minLength={8} className="field-input"
                 value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        <div className="field-group" style={{ marginBottom: 12 }}>
          <label className="field-label" htmlFor="confirm">Confirm Password</label>
          <input id="confirm" type="password" autoComplete="new-password" required className="field-input"
                 value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </div>

        {err && <div role="alert" className="field-error" style={{ marginBottom: 12 }}>{err}</div>}

        <p className="consent-note">
          By creating an account you agree to the{' '}
          <a href="/terms.html" target="_blank" rel="noopener">Terms &amp; Conditions</a> and{' '}
          <a href="/privacy-policy.html" target="_blank" rel="noopener">Privacy Policy</a>.
        </p>

        <button type="submit" disabled={loading} className={`btn btn--primary btn--full btn--lg ${loading ? 'btn--loading' : ''}`}>
          Create account
        </button>

        <div className="lock-footer">
          Already have an account? <Link to="/login">Sign in</Link>
        </div>
      </form>
    </div>
  );
}
