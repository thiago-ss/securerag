import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { ApiError, api, setCsrfToken } from './api';
import type { Me } from './types';
import { Loading } from './components/ui';

/**
 * Session gate: on boot, /auth/me resolves the session cookie (same-origin).
 * 401 → anonymous state (login page); any other failure is a distinct error
 * state. The CSRF token is cached for state-changing requests.
 */

type AuthState =
  | { kind: 'loading' }
  | { kind: 'anonymous' }
  | { kind: 'error'; message: string }
  | { kind: 'authenticated'; me: Me };

const SessionContext = createContext<{
  me: Me | null;
  tenantId: string | null;
  setTenantId: (tenantId: string) => void;
  refresh: () => Promise<void>;
}>({ me: null, tenantId: null, setTenantId: () => {}, refresh: async () => {} });

export function useSession(): {
  me: Me | null;
  tenantId: string | null;
  setTenantId: (tenantId: string) => void;
  refresh: () => Promise<void>;
} {
  return useContext(SessionContext);
}

export function SessionGate({ children }: { children: ReactNode }): ReactNode {
  const [state, setState] = useState<AuthState>({ kind: 'loading' });
  const [tenantId, setTenantIdState] = useState<string | null>(null);

  const refresh = useCallback(async (): Promise<void> => {
    setState({ kind: 'loading' });
    try {
      const me = await api.me();
      setCsrfToken(me.session.csrfToken);
      setState({ kind: 'authenticated', me });
    } catch (err) {
      setCsrfToken(null);
      if (err instanceof ApiError && err.status === 401) {
        setState({ kind: 'anonymous' });
        return;
      }
      setState({
        kind: 'error',
        message: err instanceof Error ? err.message : 'Could not reach the API',
      });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const setTenantId = useCallback((next: string): void => {
    setTenantIdState(next);
  }, []);

  if (state.kind === 'loading') {
    return <Loading label="Checking session" />;
  }
  if (state.kind === 'anonymous') {
    return children;
  }
  if (state.kind === 'error') {
    return (
      <div role="alert" className="notice error" data-testid="session-error">
        {state.message}
        <button type="button" className="button" onClick={() => void refresh()}>
          Retry
        </button>
      </div>
    );
  }
  const effectiveTenantId = tenantId ?? state.me.memberships[0]?.tenantId ?? null;
  return (
    <SessionContext.Provider
      value={{ me: state.me, tenantId: effectiveTenantId, setTenantId, refresh }}
    >
      {children}
    </SessionContext.Provider>
  );
}
