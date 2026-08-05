import type { FakeOidcProvider } from '@securerag/security/src/testkit.js';

/**
 * S1 shared E2E helper: run the FULL OIDC login flow over HTTP against the
 * fake provider (browser-like): /auth/login → provider /authorize → callback
 * → session cookie; then read /auth/me for the CSRF token.
 *
 * The provider redirects to the CONFIGURED redirect_uri, which in tests is a
 * fixed placeholder origin; the helper rewrites the callback location's
 * origin to the live test server (the real browser would hit the real origin).
 */
export interface AuthenticatedSession {
  cookieHeader: string;
  csrfToken: string;
}

export async function loginViaOidc(
  base: string,
  provider: FakeOidcProvider,
  subject: string,
): Promise<AuthenticatedSession> {
  provider.defaultSubject = subject;

  const login = await fetch(`${base}/auth/login`, { redirect: 'manual' });
  if (login.status !== 302) throw new Error(`login failed: ${login.status}`);
  const authorizeUrl = login.headers.get('location');
  if (authorizeUrl === null) throw new Error('login returned no location');

  const authorize = await fetch(authorizeUrl, { redirect: 'manual' });
  if (authorize.status !== 302) throw new Error(`authorize failed: ${authorize.status}`);
  const rawCallbackUrl = authorize.headers.get('location');
  if (rawCallbackUrl === null) throw new Error('authorize returned no location');

  const callbackUrl = new URL(rawCallbackUrl);
  const baseUrl = new URL(base);
  callbackUrl.protocol = baseUrl.protocol;
  callbackUrl.host = baseUrl.host;

  const callback = await fetch(callbackUrl, { redirect: 'manual' });
  if (callback.status !== 302) throw new Error(`callback failed: ${callback.status}`);
  const setCookie = callback.headers.get('set-cookie');
  if (setCookie === null) throw new Error('callback set no session cookie');
  const cookieHeader = setCookie.split(';')[0] ?? '';

  const me = await fetch(`${base}/auth/me`, { headers: { cookie: cookieHeader } });
  if (me.status !== 200) throw new Error(`/auth/me failed: ${me.status}`);
  const body = (await me.json()) as { session: { csrfToken: string } };
  return { cookieHeader, csrfToken: body.session.csrfToken };
}
