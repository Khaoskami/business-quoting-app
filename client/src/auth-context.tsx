import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { authClient } from './auth-client';

type User = { id: string; name: string; email: string; isAdmin?: boolean };
type AuthCtx = {
  user: User | null;
  loading: boolean;
  signIn:  (email: string, password: string) => Promise<void>;
  signUp:  (name: string, email: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
  refresh: () => Promise<void>;
};

const Ctx = createContext<AuthCtx>(null!);
export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  async function refresh() {
    const { data } = await authClient.getSession();
    setUser((data?.user as User) ?? null);
  }

  useEffect(() => {
    (async () => {
      await refresh();
      setLoading(false);
    })();
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
  };

  const signOut = async () => {
    await authClient.signOut();
    setUser(null);
  };

  return <Ctx.Provider value={{ user, loading, signIn, signUp, signOut, refresh }}>{children}</Ctx.Provider>;
}
