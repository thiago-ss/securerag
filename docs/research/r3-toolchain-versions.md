# R3 — Toolchain versions (Aug 2026 baseline)

Research date: 2026-08-05. All versions verified live against the npm registry
(registry.npmjs.org — the canonical version source) and official documentation
sites (fastify.dev, vite.dev, react.dev, vitest.dev, playwright.dev,
typescriptlang.org, kysely.dev, zod.dev, nodejs.org).

Local toolchain checked: Node v25.8.0, npm 11.11.0, Docker 29.2.1.

## Verified versions

| Package | Verified version | Official source URL | Notes (Node engine, ESM) |
| --- | --- | --- | --- |
| Node.js (runtime) | Active LTS: **v24 "Krypton"** (24.11.0). Current: **v26.6.0** | https://nodejs.org/dist/index.json | Node 26 enters LTS Oct 2026. Local v25.8.0 is a "Current" line (odd, short-lived) and satisfies every package engine below. |
| fastify | **5.11.2** (v5 latest) | https://registry.npmjs.org/fastify/latest · https://fastify.dev/docs/latest/Reference/LTS/ | Fastify 5.x requires Node >= 20 (docs LTS schedule lists Node 20/22 for v5; v5.0.0 released 2024-09-17). CJS package; full TS types shipped. |
| vite | **8.2.0** (8.0 stable since 2026-03-12) | https://registry.npmjs.org/vite/latest · https://vite.dev/blog/announcing-vite8 | **ESM-only.** Requires Node 20.19+ or 22.12+ (same as Vite 7). Built on Rolldown (single Rust bundler, 10–30x faster builds). `@vitejs/plugin-react` v6 (Oxc-based, no Babel) pairs with it. |
| react / react-dom | **19.2.8** (19.2 latest line) | https://registry.npmjs.org/react/latest · https://react.dev/versions | react.dev "Latest version: 19.2". Dual CJS/ESM (no engine constraint). React 19 ships its own types. |
| vitest | **4.1.10** (4.0 stable since 2025-10-22) | https://registry.npmjs.org/vitest/latest · https://vitest.dev/blog/vitest-4 · https://vitest.dev/guide/migration | **ESM-only package.** Requires Node >= 20 and Vite >= 6 (peer `^6 || ^7 || ^8` — compatible with Vite 8). Breaking: `workspace` → `projects`, pool rework (`maxWorkers`, `poolOptions` removed), browser providers split into separate packages (`@vitest/browser-playwright`), `coverage.all` removed, `basic` reporter removed. |
| playwright / @playwright/test | **1.62.1** | https://registry.npmjs.org/playwright/latest · https://playwright.dev/docs/intro | Engine `node >= 20`; docs list supported lines as latest 22.x / 24.x / 26.x (Node 25.8 works, but 24.x LTS is the safest CI line). Config is `playwright.config.ts` (ESM-friendly). |
| typescript | **7.0.2** (native Go port, announced 2026-07-08) | https://registry.npmjs.org/typescript/latest · https://www.typescriptlang.org/ · https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/ | Engine `node >= 16.20`. **7.0 ships no programmatic API until 7.1** — tools embedding the compiler (typescript-eslint, Volar, webpack loaders) must use `typescript@npm:@typescript/typescript6@^6.0.2` alias. New defaults: `strict: true`, `module: esnext`, `types: []`, `rootDir: ./`; hard errors for `es5`, `moduleResolution: node10`, `baseUrl`. CLI typecheck is the intended use. |
| kysely | **0.29.4** | https://registry.npmjs.org/kysely/latest · https://kysely.dev/docs/intro | **ESM-only package; requires Node >= 22.0.0** (dropped older lines in 0.29). Type-safe SQL builder for PostgreSQL; used for migrations and RLS-era queries. |
| zod | **4.4.3** (Zod 4 stable) | https://registry.npmjs.org/zod/latest · https://zod.dev/ | ESM-first (`type: module`), dual build. Officially tested against TS >= 5.5; requires `strict: true` in tsconfig. No Node engine constraint. |
| tsx (dev) | **4.23.6** | https://registry.npmjs.org/tsx/latest | Engine `node >= 18`. ESM/TypeScript runner for dev/watch (esbuild-based, no TS compiler API — works with TS 7). |
| pino (logging) | **10.3.1** | https://registry.npmjs.org/pino/latest | CJS package, no engine field. Fastify's default logger. Major 10 is recent — review changelog at upgrade time (no official-site doc URL beyond the registry). |
| testcontainers (testcontainers-node) | **12.1.0** (npm package `testcontainers`) | https://registry.npmjs.org/testcontainers/latest | **Requires Node >= 22.22.** The `testcontainers-node` project's npm package is `testcontainers`. Runs real PostgreSQL/pgvector in Docker for RLS integration tests; works with local Docker Engine 29.2.1. |

## Breaking-change / config notes for a new project

- **Vite 8 is ESM-only** and now Rolldown-powered. Config files are `vite.config.ts` (ESM). Node 20.19+ / 22.12+ mandatory; CJS configs and `rollupOptions`/`esbuild` options auto-migrate via a compatibility layer.
- **Vitest 4**: no more `vitest.workspace.ts` — use `projects: [...]` in `vitest.config.ts` (or `defineWorkspace`). For SecureRAG's monorepo, define one config per workspace root (`apps/web`, `apps/api`, packages) via `projects` globs. `poolOptions`, `maxThreads`/`maxForks`, `coverage.all` are gone. Browser mode is stable; if component tests are added, install `@vitest/browser-playwright` (not `@vitest/browser`).
- **TypeScript 7**: no API surface — safe for `tsc` typecheck + Vitest/tsx (esbuild transforms), but **linting with typescript-eslint requires the 6.0 alias** (`typescript@npm:@typescript/typescript6`). Decision point before scaffolding; alternative is pinning `~6.0`.
- **Kysely 0.29**: ESM-only + Node >= 22 — affects tsconfig (`moduleResolution: nodenext`/`bundler`) and any CJS code in the API package.
- **Playwright**: engine `>=20`, docs prefer latest 22.x/24.x/26.x; local Node 25.8 satisfies engines but the odd line is not in the documented list — CI should pin Node 24 LTS.
- **Node.js**: all pinned packages accept Node >= 22.22; a project `engines` floor of `>=22.22` covers the union (testcontainers is the strictest). Local Node v25.8.0 and Docker 29.2.1 satisfy everything; no conflicts.

## Baseline pin set (package.json)

```jsonc
{
  "engines": { "node": ">=22.22" },
  "dependencies": {
    "fastify": "^5.11.2",
    "react": "^19.2.8",
    "react-dom": "^19.2.8",
    "kysely": "^0.29.4",
    "zod": "^4.4.3",
    "pino": "^10.3.1"
  },
  "devDependencies": {
    "vite": "^8.2.0",
    "@vitejs/plugin-react": "^6.0.5",
    "vitest": "^4.1.10",
    "@playwright/test": "^1.62.1",
    "typescript": "^7.0.2",          // + "typescript6": "npm:@typescript/typescript6@^6.0.2" if typescript-eslint is used
    "tsx": "^4.23.6",
    "testcontainers": "^12.1.0"
  }
}
```

Runtime baseline: Node 24 LTS (Krypton) for CI/production; local v25.8.0 works for all listed packages.
