import type { Pool } from 'pg';

export interface CatalogTable {
  relname: string;
  relrowsecurity: boolean;
  relforcerowsecurity: boolean;
  owner: string;
}

export interface CatalogPolicy {
  polname: string;
  polpermissive: boolean;
  polcmd: 'ALL' | 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE';
  using_expr: string | null;
  with_check_expr: string | null;
}

export interface CatalogRole {
  rolsuper: boolean;
  rolbypassrls: boolean;
  rolcreatedb: boolean;
  rolcreaterole: boolean;
  rolcanlogin: boolean;
}

/** Tables in the securerag schema (all relkinds r, excluding the migrations bookkeeping table). */
export async function tenantTables(pool: Pool, schema = 'securerag'): Promise<CatalogTable[]> {
  const { rows } = await pool.query<CatalogTable>(
    `SELECT c.relname,
            c.relrowsecurity,
            c.relforcerowsecurity,
            r.rolname AS owner
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
       JOIN pg_roles r ON r.oid = c.relowner
      WHERE n.nspname = $1
        AND c.relkind = 'r'
        AND c.relname <> 'migrations'
      ORDER BY c.relname`,
    [schema],
  );
  return rows;
}

export async function policiesFor(pool: Pool, table: string, schema = 'securerag'): Promise<CatalogPolicy[]> {
  const { rows } = await pool.query<CatalogPolicy>(
    `SELECT polname,
            polpermissive,
            polcmd,
            pg_get_expr(polqual, polrelid) AS using_expr,
            pg_get_expr(polwithcheck, polrelid) AS with_check_expr
       FROM pg_policy
      WHERE polrelid = to_regclass($1)::oid
      ORDER BY polname`,
    [`${schema}.${table}`],
  );
  return rows;
}

export async function roleAttributes(pool: Pool, role: string): Promise<CatalogRole> {
  const { rows } = await pool.query<CatalogRole>(
    `SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolcanlogin
       FROM pg_roles WHERE rolname = $1`,
    [role],
  );
  const row = rows[0];
  if (!row) throw new Error(`role not found: ${role}`);
  return row;
}

export async function tableGrants(
  pool: Pool,
  table: string,
  schema = 'securerag',
  grantee?: string,
): Promise<string[]> {
  const { rows } = await pool.query<{ privilege_type: string }>(
    `SELECT privilege_type
       FROM information_schema.role_table_grants
      WHERE table_schema = $1 AND table_name = $2
        AND ($3::text IS NULL OR grantee = $3)`,
    [schema, table, grantee ?? null],
  );
  return [...new Set(rows.map((r) => r.privilege_type))].sort();
}

export async function pkColumns(pool: Pool, table: string, schema = 'securerag'): Promise<string[]> {
  const { rows } = await pool.query<{ column_name: string }>(
    `SELECT kcu.column_name
       FROM information_schema.table_constraints tc
       JOIN information_schema.key_column_usage kcu
         ON kcu.constraint_name = tc.constraint_name
        AND kcu.constraint_schema = tc.constraint_schema
      WHERE tc.table_schema = $1 AND tc.table_name = $2 AND tc.constraint_type = 'PRIMARY KEY'
      ORDER BY kcu.ordinal_position`,
    [schema, table],
  );
  return rows.map((r) => r.column_name);
}

export async function tenantColumns(pool: Pool, table: string, schema = 'securerag'): Promise<string[]> {
  const { rows } = await pool.query<{ column_name: string; is_nullable: string }>(
    `SELECT column_name, is_nullable
       FROM information_schema.columns
      WHERE table_schema = $1 AND table_name = $2
      ORDER BY ordinal_position`,
    [schema, table],
  );
  return rows.map((r) => r.column_name);
}

export interface ForeignKey {
  constraint_name: string;
  columns: string[];
  referenced_table: string;
  referenced_columns: string[];
}

export async function foreignKeys(pool: Pool, table: string, schema = 'securerag'): Promise<ForeignKey[]> {
  const { rows } = await pool.query<{
    constraint_name: string;
    columns: string;
    referenced_table: string;
    referenced_columns: string;
  }>(
    `SELECT c.conname AS constraint_name,
            (SELECT array_agg(a.attname ORDER BY u.ordinality)
               FROM unnest(c.conkey) WITH ORDINALITY AS u(attnum, ordinality)
               JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = u.attnum)::text AS columns,
            c.confrelid::regclass::text AS referenced_table,
            (SELECT array_agg(a.attname ORDER BY u.ordinality)
               FROM unnest(c.confkey) WITH ORDINALITY AS u(attnum, ordinality)
               JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = u.attnum)::text AS referenced_columns
       FROM pg_constraint c
      WHERE c.conrelid = to_regclass($1)::oid AND c.contype = 'f'`,
    [`${schema}.${table}`],
  );
  return rows.map((r) => ({
    constraint_name: r.constraint_name,
    columns: parseTextArray(r.columns),
    referenced_table: r.referenced_table.replace(/^securerag\./, ''),
    referenced_columns: parseTextArray(r.referenced_columns),
  }));
}

/** Security definer functions in the schema (must be zero). */
export async function securityDefinerFunctions(pool: Pool, schema = 'securerag'): Promise<string[]> {
  const { rows } = await pool.query<{ proname: string }>(
    `SELECT p.proname
       FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = $1 AND p.prosecdef
      ORDER BY p.proname`,
    [schema],
  );
  return rows.map((r) => r.proname);
}

/** Views with/without security_invoker in the schema. */
export async function viewSecurity(pool: Pool, schema = 'securerag'): Promise<Record<string, boolean>> {
  const { rows } = await pool.query<{ relname: string; reloptions: string[] | null }>(
    `SELECT c.relname, c.reloptions
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = $1 AND c.relkind = 'v'
      ORDER BY c.relname`,
    [schema],
  );
  return Object.fromEntries(
    rows.map((r) => [r.relname, (r.reloptions ?? []).includes('security_invoker=true')]),
  );
}

export async function functionsInSchema(pool: Pool, schema = 'securerag'): Promise<string[]> {
  const { rows } = await pool.query<{ proname: string }>(
    `SELECT p.proname
       FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = $1
      ORDER BY p.proname`,
    [schema],
  );
  return rows.map((r) => r.proname);
}

function parseTextArray(value: string): string[] {
  const trimmed = value.replace(/^\{|\}$/g, '');
  if (trimmed === '') return [];
  return trimmed.split(',').map((v) => v.replace(/^"|"$/g, ''));
}
