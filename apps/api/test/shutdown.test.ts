import { spawn, type ChildProcess } from 'node:child_process';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  getTestDb,
  resetData,
  seedFixtures,
  TEST_PASSWORDS,
  type TestDb,
} from '@securerag/db/src/testkit.js';

/**
 * S10 graceful shutdown (ADR-0011): the real entrypoint (server.ts) drains on
 * SIGTERM — the process exits 0 after the shutdown log line, with no hang
 * (Fastify close() waits for in-flight requests before the pool is ended).
 */
describe('S10 graceful shutdown — SIGTERM drains and exits cleanly', () => {
  let db: TestDb;
  let port: number;
  let child: ChildProcess | null = null;

  beforeAll(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    await seedFixtures(db.superuserPool);
    port = 31_000 + Math.floor(Math.random() * 2_000);
  });

  afterAll(async () => {
    if (child !== null && child.exitCode === null) {
      child.kill('SIGKILL');
      await new Promise((r) => setTimeout(r, 200));
    }
    await db.stop();
  });

  async function waitForHealth(timeoutMs: number): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      try {
        const res = await fetch(`http://127.0.0.1:${port}/healthz`);
        if (res.ok) return true;
      } catch {
        // not up yet
      }
      await new Promise((r) => setTimeout(r, 250));
    }
    return false;
  }

  it('SIGTERM triggers the graceful shutdown path and the process exits 0', async () => {
    const env = {
      ...process.env,
      PGHOST: db.host,
      PGPORT: String(db.port),
      PGPASSWORD: TEST_PASSWORDS['securerag_api'],
      PGDATABASE: 'securerag',
      PORT: String(port),
      HOST: '127.0.0.1',
      OIDC_ISSUER: 'http://issuer.invalid/realms/test',
      OIDC_CLIENT_ID: 'securerag-api',
      OIDC_REDIRECT_URI: `http://127.0.0.1:${port}/auth/callback`,
      SESSION_COOKIE_SECURE: 'false',
      SOURCE_STORE: 'memory',
    };
    child = spawn(process.execPath, ['--import', 'tsx', 'src/server.ts'], {
      cwd: new URL('..', import.meta.url).pathname,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const output: string[] = [];
    child.stdout?.on('data', (chunk: Buffer) => output.push(chunk.toString()));
    child.stderr?.on('data', (chunk: Buffer) => output.push(chunk.toString()));

    expect(await waitForHealth(30_000)).toBe(true);

    // a request completes while the server is up
    const ready = await fetch(`http://127.0.0.1:${port}/readyz`);
    expect(ready.status).toBe(200);

    const exit = new Promise<number | null>((resolve) => {
      child?.on('exit', (code) => resolve(code));
    });
    child.kill('SIGTERM');

    const code = await Promise.race([
      exit,
      new Promise<number | null>((resolve) => setTimeout(() => resolve(null), 15_000)),
    ]);
    expect(code).toBe(0);
    expect(output.join('')).toContain('securerag-api graceful shutdown (SIGTERM)');
    expect(output.join('')).toContain('securerag-api listening');
  }, 60_000);
});
