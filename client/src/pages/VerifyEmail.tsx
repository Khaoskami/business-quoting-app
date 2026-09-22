import { useState } from 'react';
import { Link } from 'react-router-dom';
import { authClient } from '../auth-client';
import { useToast } from '../components/Toast';

const GENERIC_MESSAGE = 'If the account exists and still needs verification, a verification email has been sent.';

export default function VerifyEmail() {
  const { notify } = useToast();
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    try {
      await authClient.sendVerificationEmail({ email, callbackURL: '/' });
    } catch {
      // Keep the response generic so this page cannot be used to enumerate accounts.
    } finally {
      setSent(true);
      notify(GENERIC_MESSAGE);
      setLoading(false);
    }
  }

  return (
    <div className="lock-screen">
      <form className="lock-card" onSubmit={submit}>
        <div className="lock-logo">BQ</div>
        <h1 className="lock-title">Verify your email</h1>
        <p className="lock-subtitle">Enter your account email and we'll send a fresh verification link.</p>
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
              Send verification link
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
