import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';

type Toast = { id: number; message: string; type: 'success' | 'error' | 'warning' };
type Ctx = { notify: (message: string, type?: Toast['type']) => void };

const ToastCtx = createContext<Ctx>(null!);
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const notify = useCallback((message: string, type: Toast['type'] = 'success') => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, message, type }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 2800);
  }, []);

  return (
    <ToastCtx.Provider value={{ notify }}>
      {children}
      {toasts.map((t) => (
        <div key={t.id} role="status" aria-live="polite" className={`toast toast--${t.type}`}>{t.message}</div>
      ))}
    </ToastCtx.Provider>
  );
}
