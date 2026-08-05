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

const GLOBAL_TABLES = ['principals', 'sessions', 'tenants', 'authorization_epoch'];
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
      expect(p.using_expr ?? '', `${name}:${p.polname} USING must reference context GUCs`)
        .toMatch(/current_setting\('securerag\.(tenant_id|principal_id)'|securerag\.ctx_/);
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

  it('keeps audit events insert-only for runtime roles with no TRUNCATE/REFERENCES anywhere', async () => {
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
  });

  it('contains no SECURITY DEFINER functions and keeps admin_scope security_invoker', async () => {
    expect(await securityDefinerFunctions(pool)).toEqual([]);
    const views = await viewSecurity(pool);
    expect(views['admin_scope'], 'admin_scope must be security_invoker').toBe(true);
    const fns = await functionsInSchema(pool);
    expect(fns).toEqual(
      expect.arrayContaining([
        'bump_authorization_epoch',
        'ctx_tenant_id',
        'ctx_principal_id',
        'ctx_principal_is_admin',
      ]),
    );
  });
});
