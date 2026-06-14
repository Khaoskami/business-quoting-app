import { useState } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { authClient } from '../auth-client';
import { useToast } from '../components/Toast';

export default function ResetPassword() {
  const { notify } = useToast();
  const nav = useNavigate();
  const [params] = useSearchParams();
  // Better Auth redirects invalid/expired tokens here with ?error=INVALID_TOKEN.
  const token = params.get('token') ?? '';
  const tokenError = params.get('error');

  const [password, setPassword] = useState('');
  const [confirm, setConfirm]   = useState('');
  const [err, setErr]           = useState('');
  const [loading, setLoading]   = useState(false);

  const invalidToken = !token || Boolean(tokenError);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr('');
    if (password.length < 8) { setErr('Password must be at least 8 characters.'); return; }
    if (password !== confirm) { setErr('Passwords do not match.'); return; }
    setLoading(true);
    try {
      const { error } = await authClient.resetPassword({ newPassword: password, token });
      if (error) {
        setErr(error.message ?? 'Could not reset password. The link may have expired.');
        setLoading(false);
        return;
      }
      notify('Password reset. Please sign in.');
      nav('/login', { replace: true });
    } catch (e: any) {
      setErr(e?.message ?? 'Could not reset password. The link may have expired.');
      setLoading(false);
    }
  }

  return (
    <div className="lock-screen">
      <form className="lock-card" onSubmit={submit}>
        <div className="lock-logo">BQ</div>
        <h1 className="lock-title">Choose a new password</h1>

        {invalidToken ? (
          <>
            <p className="lock-subtitle">This reset link is invalid or has expired.</p>
            <div role="alert" className="field-error" style={{ marginBottom: 12 }}>
              Please request a new password reset link.
            </div>
            <Link to="/forgot-password" className="btn btn--primary btn--full btn--lg">
              Request a new link
            </Link>
          </>
        ) : (
          <>
            <p className="lock-subtitle">Enter and confirm your new password.</p>

            <div className="field-group" style={{ marginBottom: 12 }}>
              <label className="field-label" htmlFor="password">New Password</label>
              <input id="password" type="password" autoComplete="new-password" required minLength={8} className="field-input"
                     value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
            </div>
            <div className="field-group" style={{ marginBottom: 12 }}>
              <label className="field-label" htmlFor="confirm">Confirm New Password</label>
              <input id="confirm" type="password" autoComplete="new-password" required className="field-input"
                     value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            </div>

            {err && <div role="alert" className="field-error" style={{ marginBottom: 12 }}>{err}</div>}

            <button type="submit" disabled={loading} className={`btn btn--primary btn--full btn--lg ${loading ? 'btn--loading' : ''}`}>
              Reset password
            </button>
          </>
        )}

        <div className="lock-footer">
          <Link to="/login">Back to sign in</Link>
        </div>
      </form>
    </div>
  );
}
