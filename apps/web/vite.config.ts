import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * SecureRAG console dev server. Same-origin convention: the console talks to
 * /api/* (the reverse proxy rewrites /api → the API in the compose stack);
 * the dev proxy forwards /api to the local API and strips the prefix. The
 * OIDC redirect_uri is always a /api/auth/callback URL on this origin.
 */
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const apiTarget = env.API_PROXY_TARGET ?? 'http://localhost:3000';
  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        '/api': {
          target: apiTarget,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, ''),
        },
      },
    },
    preview: {
      port: 4173,
    },
  };
});
