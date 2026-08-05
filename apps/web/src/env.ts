import { z } from 'zod';

/**
 * Web runtime env validation (S10): the Vite-exposed VITE_* variables are
 * validated at module load so a misconfigured console fails fast with a
 * precise error instead of failing deep inside a page fetch.
 */
const envSchema = z.object({
  /** Same-origin API base (the reverse proxy rewrites /api to the API). */
  VITE_API_BASE: z.string().min(1).default('/api'),
  VITE_APP_TITLE: z.string().min(1).default('SecureRAG Console'),
});

const raw = import.meta.env as Record<string, unknown>;
const parsed = envSchema.safeParse(raw);
if (!parsed.success) {
  throw new Error(
    `invalid web environment: ${parsed.error.issues.map((i) => `${i.path.join('.')} (${i.message})`).join(', ')}`,
  );
}

export const env = parsed.data;
