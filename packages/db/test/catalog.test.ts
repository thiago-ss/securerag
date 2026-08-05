import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { getTestDb, type TestDb } from './helpers.js';
import {
  foreignKeys,
  functionsInSchema,
  pkColumns,
  policiesFor,
  roleAttributes,
  securityDefinerFunctions,
  tableGrants,
  tenantColumns,
  tenantTables,
  viewSecurity,
} from '../src/catalog.js';
import type { Pool } from 'pg';

const TENANT_TABLES = [
  'tenants',
  'groups',
  'group_memberships',
  'tenant_admins',
  'documents',
  'document_versions',
  'document_grants',
  'chunks',
  'jobs',
  'retention_policies',
  'audit_events',
];

const GLOBAL_TABLES = ['principals', 'sessions', 'authorization_epoch'];
const GLOBAL_RLS_TABLES = ['principals', 'sessions', 'tenant_memberships'];
const RUNTIME_ROLES = ['securerag_api', 'securerag_worker'];

describe('schema catalog contract', () => {
  let db: TestDb;
  let pool: Pool;

  beforeAll(async () => {
    db = await getTestDb();
    pool = db.superuserPool;
  });

  afterAll(async () => {
    await db.stop();
  });

  it('enables and forces RLS on every tenant table with the NOLOGIN owner', async () => {
    const tables = await tenantTables(pool);
    const byName = new Map(tables.map((t) => [t.relname, t]));
    for (const name of TENANT_TABLES) {
      const t = byName.get(name);
      expect(t, `table ${name} missing`).toBeDefined();
      expect(t?.relrowsecurity, `${name} missing ENABLE RLS`).toBe(true);
      expect(t?.relforcerowsecurity, `${name} missing FORCE RLS`).toBe(true);
      expect(t?.owner, `${name} wrong owner`).toBe('securerag_owner');
    }
    for (const name of GLOBAL_RLS_TABLES) {
      const t = byName.get(name);
      expect(t, `global RLS table ${name} missing`).toBeDefined();
      expect(t?.relrowsecurity, `${name} missing ENABLE RLS`).toBe(true);
      expect(t?.relforcerowsecurity, `${name} missing FORCE RLS`).toBe(true);
    }
  });

  it('keeps runtime roles least-privileged and migration role ephemeral', async () => {
    for (const role of RUNTIME_ROLES) {
      const attrs = await roleAttributes(pool, role);
      expect(attrs.rolsuper, `${role} is superuser`).toBe(false);
      expect(attrs.rolbypassrls, `${role} bypasses RLS`).toBe(false);
      expect(attrs.rolcreatedb, `${role} can create DBs`).toBe(false);
      expect(attrs.rolcreaterole, `${role} can create roles`).toBe(false);
      expect(attrs.rolcanlogin, `${role} cannot login`).toBe(true);
      const { rows: memberships } = await pool.query<{ rolname: string }>(
        `SELECT r.rolname FROM pg_auth_members m
          JOIN pg_roles r ON r.oid = m.roleid
          JOIN pg_roles member ON member.oid = m.member
         WHERE member.rolname = $1`,
        [role],
      );
      expect(memberships.map((m) => m.rolname), `${role} holds privileged memberships`)
        .not.toContain('securerag_owner');
    }
    const owner = await roleAttributes(pool, 'securerag_owner');
    expect(owner.rolcanlogin, 'owner must be NOLOGIN').toBe(false);
    const migration = await roleAttributes(pool, 'securerag_migration');
    expect(migration.rolsuper, 'migration must not be superuser').toBe(false);
    expect(migration.rolbypassrls, 'migration must not bypass RLS').toBe(false);
  });

  it('keeps exactly one policy per RLS table, guarded by the security-context GUCs', async () => {
    for (const name of [...TENANT_TABLES, ...GLOBAL_RLS_TABLES]) {
      const policies = await policiesFor(pool, name);
      expect(policies.length, `${name} must have exactly one policy (permissive OR weakening)`).toBe(1);
      const p = policies[0]!;
      expect(p.using_expr, `${name}:${p.polname} missing USING`).toBeTruthy();
      expect(p.with_check_expr, `${name}:${p.polname} missing WITH CHECK`).toBeTruthy();
      const guard = /current_setting\('securerag\.(tenant_id|principal_id)'|securerag\.ctx_/;
      expect(p.using_expr ?? '', `${name}:${p.polname} USING must reference context GUCs`)
        .toMatch(guard);
      expect(p.with_check_expr ?? '', `${name}:${p.polname} WITH CHECK must reference context GUCs`)
        .toMatch(guard);
    }
    const memberships = await policiesFor(pool, 'tenant_memberships');
    expect(memberships[0]?.polname).toBe('memberships_access');
  });

  it('includes tenant_id in the PK of every tenant table and keeps it NOT NULL', async () => {
    for (const name of TENANT_TABLES) {
      const pk = await pkColumns(pool, name);
      expect(pk, `${name} PK does not include tenant_id (${pk.join(',')})`).toContain('tenant_id');
      const cols = await tenantColumns(pool, name);
      expect(cols, `${name} missing tenant_id column`).toContain('tenant_id');
    }
  });

  it('structurally prevents cross-tenant references via composite FKs', async () => {
    for (const name of TENANT_TABLES) {
      const fks = await foreignKeys(pool, name);
      for (const fk of fks) {
        const refsGlobal = fk.referenced_columns.length === 1 &&
          fk.referenced_columns[0] !== 'tenant_id';
        if (refsGlobal) {
          expect(fk.referenced_table, `${name}.${fk.constraint_name} global ref must be whitelisted`)
            .toMatch(/^(principals|tenants)$/);
          expect(fk.columns, `${name}.${fk.constraint_name} must not carry tenant_id to a global table`)
            .not.toContain('tenant_id');
          continue;
        }
        expect(fk.columns, `${name}.${fk.constraint_name} missing tenant_id`).toContain('tenant_id');
        expect(fk.referenced_columns, `${name}.${fk.constraint_name} referenced key missing tenant_id`)
          .toContain('tenant_id');
      }
    }
  });

  it('keeps audit events insert-only and immutables immutable for runtime roles', async () => {
    const auditGrantsApi = await tableGrants(pool, 'audit_events', 'securerag', 'securerag_api');
    expect(auditGrantsApi.sort()).toEqual(['INSERT', 'SELECT']);
    const auditGrantsWorker = await tableGrants(pool, 'audit_events', 'securerag', 'securerag_worker');
    expect(auditGrantsWorker.sort()).toEqual(['INSERT', 'SELECT']);
    for (const role of RUNTIME_ROLES) {
      const all = new Set<string>();
      for (const name of [...TENANT_TABLES, ...GLOBAL_TABLES]) {
        for (const g of await tableGrants(pool, name, 'securerag', role)) all.add(g);
      }
      expect([...all], `${role} has ${[...all].join(',')}`).not.toContain('TRUNCATE');
      expect([...all]).not.toContain('REFERENCES');
    }
    // Authorization epoch: runtime roles read only; the bump function is the sole write path.
    expect(await tableGrants(pool, 'authorization_epoch', 'securerag', 'securerag_api')).toEqual(['SELECT']);
    expect(await tableGrants(pool, 'authorization_epoch', 'securerag', 'securerag_worker')).toEqual(['SELECT']);
    // chunks immutable after publish; versions never deleted by runtime roles; tenants registry not writable.
    expect(await tableGrants(pool, 'chunks', 'securerag', 'securerag_api')).toEqual(['INSERT', 'SELECT']);
    expect(await tableGrants(pool, 'chunks', 'securerag', 'securerag_worker')).toEqual(['INSERT', 'SELECT']);
    expect(await tableGrants(pool, 'document_versions', 'securerag', 'securerag_api')).toEqual(['INSERT', 'SELECT', 'UPDATE']);
    expect(await tableGrants(pool, 'document_versions', 'securerag', 'securerag_worker')).toEqual(['INSERT', 'SELECT', 'UPDATE']);
    expect(await tableGrants(pool, 'tenants', 'securerag', 'securerag_api')).toEqual(['SELECT', 'UPDATE']);
    expect(await tableGrants(pool, 'tenants', 'securerag', 'securerag_worker')).toEqual(['SELECT']);
    // Worker never touches identity/session/grant-management data.
    expect(await tableGrants(pool, 'sessions', 'securerag', 'securerag_worker')).toEqual(['SELECT']);
    expect(await tableGrants(pool, 'principals', 'securerag', 'securerag_worker')).toEqual(['SELECT']);
  });

  it('pins the documented SECURITY DEFINER set (ADR-0014) and keeps admin_scope security_invoker', async () => {
    const definers = await securityDefinerFunctions(pool);
    expect(definers, 'only the ADR-0013/0014 functions may be SECURITY DEFINER').toEqual([
      'bump_authorization_epoch',
      'get_session',
      'revoke_session',
      'upsert_principal',
    ]);
    const definerAttrs = async (name: string): Promise<{
      prosecdef: boolean;
      owner: string;
      proconfig: string[] | null;
    }> => {
      const { rows } = await pool.query<{
        prosecdef: boolean;
        owner: string;
        proconfig: string[] | null;
      }>(
        `SELECT p.prosecdef,
                pg_get_userbyid(p.proowner) AS owner,
                p.proconfig
           FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'securerag' AND p.proname = $1`,
        [name],
      );
      const row = rows[0];
      if (!row) throw new Error(`definer function missing: ${name}`);
      return row;
    };
    const definerOwner = async (name: string): Promise<string> => {
      const { rows } = await pool.query<{ owner: string }>(
        `SELECT pg_get_userbyid(p.proowner) AS owner
           FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'securerag' AND p.proname = $1`,
        [name],
      );
      const row = rows[0];
      if (!row) throw new Error(`definer function missing: ${name}`);
      return row.owner;
    };
    for (const name of definers) {
      const attr = await definerAttrs(name);
      expect(attr.prosecdef, `${name} not SECURITY DEFINER`).toBe(true);
      const expectedOwner =
        name === 'bump_authorization_epoch' ? 'securerag_owner' : 'securerag_session_lookup';
      expect(await definerOwner(name), `${name} wrong owner`).toBe(expectedOwner);
      expect((attr.proconfig ?? []).join(';'), `${name} search_path must be pinned`)
        .toContain('search_path');
      const { rows: acl } = await pool.query<{ executeable_by_public: boolean }>(
        `SELECT EXISTS (
           SELECT 1 FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'securerag' AND p.proname = $1
             AND has_function_privilege('public', p.oid, 'EXECUTE')
         ) AS executeable_by_public`,
        [name],
      );
      expect(acl[0]?.executeable_by_public, `${name} must be revoked from PUBLIC`).toBe(false);
    }
    // The session-lookup role exists ONLY to own the S1 definers: NOLOGIN,
    // BYPASSRLS (so the functions can see sessions/principals), granted to no
    // login-capable role, with api/worker unable to reach it.
    const lookup = await roleAttributes(pool, 'securerag_session_lookup');
    expect(lookup.rolcanlogin, 'session-lookup must be NOLOGIN').toBe(false);
    expect(lookup.rolbypassrls, 'session-lookup must BYPASSRLS (ADR-0014)').toBe(true);
    expect(lookup.rolsuper).toBe(false);
    expect(lookup.rolcreaterole).toBe(false);
    const { rows: grantees } = await pool.query<{ rolname: string }>(
      `SELECT r.rolname
         FROM pg_auth_members m
         JOIN pg_roles granted ON granted.oid = m.roleid
         JOIN pg_roles r ON r.oid = m.member
        WHERE granted.rolname = $1
        ORDER BY r.rolname`,
      ['securerag_session_lookup'],
    );
    expect(grantees.map((r) => r.rolname), 'session-lookup granted only to the NOLOGIN owner')
      .toEqual(['securerag_owner']);
    for (const role of RUNTIME_ROLES) {
      const { rows: indirect } = await pool.query<{ n: number }>(
        `SELECT count(*)::int AS n
           FROM pg_auth_members m
          JOIN pg_roles member ON member.oid = m.member
          WHERE member.rolname = $1 AND m.roleid IN (
            SELECT oid FROM pg_roles
             WHERE rolname IN ('securerag_owner', 'securerag_session_lookup'))`,
        [role],
      );
      expect(indirect[0]?.n ?? 0, `${role} must not reach session-lookup via owner membership`).toBe(0);
    }
    const { rows: grants } = await pool.query<{ grantee: string }>(
      `SELECT DISTINCT grantee
         FROM information_schema.routine_privileges
        WHERE routine_schema = 'securerag'
          AND routine_name IN ('get_session', 'revoke_session', 'upsert_principal')
          AND privilege_type = 'EXECUTE'
        ORDER BY grantee`,
    );
    // The owner row is the implicit owner grant (function owner always
    // executes its own objects); the only other grantee is the api role.
    expect(grants.map((r) => r.grantee), 'session/identity definers: owner + api only').toEqual([
      'securerag_api',
      'securerag_session_lookup',
    ]);
    const views = await viewSecurity(pool);
    expect(views['admin_scope'], 'admin_scope must be security_invoker').toBe(true);
    const fns = await functionsInSchema(pool);
    expect(fns).toEqual(
      expect.arrayContaining([
        'bump_authorization_epoch',
        'ctx_tenant_id',
        'ctx_principal_id',
        'ctx_principal_is_admin',
        'get_session',
        'revoke_session',
        'upsert_principal',
      ]),
    );
  });
});
