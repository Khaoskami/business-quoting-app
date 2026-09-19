import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { authClient } from './auth-client';

type User = { id: string; name: string; email: string; isAdmin?: boolean };
type AuthCtx = {
  user: User | null;
  loading: boolean;
  signIn:  (email: string, password: string) => Promise<void>;
  signUp:  (name: string, email: string, password: string) => Promise<{ requiresVerification: boolean }>;
  resendVerification: (email: string) => Promise<void>;
  signOut: () => Promise<void>;
  refresh: () => Promise<void>;
};

const Ctx = createContext<AuthCtx>(null!);
export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  async function refresh() {
    try {
      const { data } = await authClient.getSession();
      setUser((data?.user as User) ?? null);
    } catch (error) {
      console.error('[auth-session-error]', error);
      setUser(null);
    }
  }

  useEffect(() => {
    let mounted = true;
    (async () => {
      await refresh();
      if (mounted) setLoading(false);
    })();
    return () => { mounted = false; };
  }, []);

  const signIn = async (email: string, password: string) => {
    const { error } = await authClient.signIn.email({ email, password });
    if (error) throw new Error(error.message ?? 'Sign-in failed');
    await refresh();
  };

  const signUp = async (name: string, email: string, password: string) => {
    const { error } = await authClient.signUp.email({ name, email, password });
    if (error) throw new Error(error.message ?? 'Sign-up failed');
    await refresh();
    return { requiresVerification: import.meta.env.PROD };
  };

  const resendVerification = async (email: string) => {
    const { error } = await authClient.sendVerificationEmail({ email, callbackURL: '/' });
    if (error) throw new Error(error.message ?? 'Could not resend verification email');
  };

  const signOut = async () => {
    await authClient.signOut();
    setUser(null);
  };

  return <Ctx.Provider value={{ user, loading, signIn, signUp, resendVerification, signOut, refresh }}>{children}</Ctx.Provider>;
}
