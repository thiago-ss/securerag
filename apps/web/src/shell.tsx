import { useState, type ReactNode } from 'react';
import { api } from './api';
import { env } from './env';
import { navigate, useHashRoute } from './router';
import { useSession } from './session';

/**
 * Console shell: skip link, header (tenant selector + sign out), landmark
 * navigation, main region. Active route is marked with aria-current.
 */

const NAV_ITEMS = [
  { href: '/documents', label: 'Documents' },
  { href: '/search', label: 'Search & answer' },
  { href: '/quarantine', label: 'Quarantine' },
  { href: '/audit', label: 'Audit' },
  { href: '/policy', label: 'Retention policy' },
  { href: '/memberships', label: 'Members & groups' },
  { href: '/refusals', label: 'Refusals' },
];

export function Shell({ children }: { children: ReactNode }): ReactNode {
  const route = useHashRoute();
  const session = useSession();
  const me = session.me;
  const memberships = me?.memberships ?? [];

  const signOut = async (): Promise<void> => {
    try {
      await api.logout();
    } catch {
      // local logout already happened server-side; force a reload to land on
      // the anonymous state
    }
    window.location.assign('/');
  };

  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <header className="app-header">
        <p className="brand">{env.VITE_APP_TITLE}</p>
        <nav aria-label="Primary" className="primary-nav">
          <ul>
            {NAV_ITEMS.map((item) => (
              <li key={item.href}>
                <a
                  href={`#${item.href}`}
                  aria-current={route.startsWith(item.href) ? 'page' : undefined}
                  onClick={(event) => {
                    event.preventDefault();
                    navigate(item.href);
                  }}
                >
                  {item.label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <div className="header-right">
          {memberships.length > 1 ? (
            <label className="tenant-picker">
              <span>Tenant</span>
              <select
                value={session.tenantId ?? ''}
                onChange={(event) => session.setTenantId(event.target.value)}
              >
                {memberships.map((m) => (
                  <option key={m.tenantId} value={m.tenantId}>
                    {m.tenantId.slice(0, 8)} ({m.role})
                  </option>
                ))}
              </select>
            </label>
          ) : null}
          {me !== null ? (
            <span className="whoami" data-testid="whoami">
              {me.principal.displayName}
            </span>
          ) : null}
          <button type="button" className="button button-ghost" onClick={() => void signOut()}>
            Sign out
          </button>
        </div>
      </header>
      <main id="main" className="app-main" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}

export function LoginPage(): ReactNode {
  const [busy, setBusy] = useState(false);
  return (
    <main id="main" className="app-main" tabIndex={-1}>
      <section className="login" aria-labelledby="login-heading">
        <h1 id="login-heading" className="page-heading">
          {env.VITE_APP_TITLE}
        </h1>
        <p>Sign in with your organization identity to access the knowledge platform.</p>
        <button
          type="button"
          className="button button-primary"
          data-testid="sign-in"
          onClick={() => {
            setBusy(true);
            api.login();
          }}
        >
          {busy ? 'Redirecting…' : 'Sign in'}
        </button>
        <p className="field-hint">
          You will be redirected to your identity provider and returned to this console.
        </p>
      </section>
    </main>
  );
}
