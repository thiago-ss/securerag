import { useEffect, useState } from 'react';

/**
 * Minimal accessible hash router. Hash routing keeps the built SPA deployable
 * behind a static server with zero rewrite config (same-origin /api proxy
 * handles the API). Focus management: on route change, focus moves to the
 * main heading so keyboard and screen-reader users land on the page content.
 */
export function parseHash(): string {
  const raw = window.location.hash.replace(/^#/, '');
  return raw === '' ? '/documents' : raw;
}

export function useHashRoute(): string {
  const [route, setRoute] = useState<string>(parseHash);
  useEffect(() => {
    const onChange = (): void => setRoute(parseHash());
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  return route;
}

export function navigate(to: string): void {
  window.location.hash = to;
}

export interface RouteParts {
  path: string;
  segments: string[];
}

export function parseRoute(route: string): RouteParts {
  const clean = route.startsWith('/') ? route : `/${route}`;
  const segments = clean.split('/').filter((s) => s.length > 0);
  return { path: clean, segments };
}

/** Focus the given element and remember to return focus later (dialogs). */
export function focusElement(el: HTMLElement | null): void {
  el?.focus();
}
