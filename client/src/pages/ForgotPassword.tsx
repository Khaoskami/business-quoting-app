import { useState } from 'react';
import { Link } from 'react-router-dom';
import { authClient } from '../auth-client';
import { useToast } from '../components/Toast';

const GENERIC_MESSAGE = 'If that email exists, a reset link has been sent.';

export default function ForgotPassword() {
  const { notify } = useToast();
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    try {
      // Better Auth 1.6.x core method is requestPasswordReset (not forgetPassword).
      // The reset link's destination is built server-side in sendResetPassword;
      // redirectTo is the SPA path used for invalid/expired token handling.
      await authClient.requestPasswordReset({ email, redirectTo: '/reset-password' });
    } catch {
      // Swallow errors: never reveal whether the email is registered.
    } finally {
      // Always show the same generic message regardless of the result.
      setSent(true);
      notify(GENERIC_MESSAGE);
      setLoading(false);
    }
  }

  return (
    <div className="lock-screen">
      <form className="lock-card" onSubmit={submit}>
        <div className="lock-logo">BQ</div>
        <h1 className="lock-title">Reset password</h1>
        <p className="lock-subtitle">Enter your email and we'll send you a reset link.</p>

        {sent ? (
          <div role="status" className="field-hint" style={{ marginBottom: 12 }}>{GENERIC_MESSAGE}</div>
        ) : (
          <>
            <div className="field-group" style={{ marginBottom: 12 }}>
              <label className="field-label" htmlFor="email">Email</label>
              <input id="email" type="email" autoComplete="email" className="field-input" required
                     value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />
            </div>

            <button type="submit" disabled={loading} className={`btn btn--primary btn--full btn--lg ${loading ? 'btn--loading' : ''}`}>
              Send reset link
            </button>
          </>
        )}

        <div className="lock-footer">
          Remembered it? <Link to="/login">Sign in</Link>
        </div>
      </form>
    </div>
  );
}
