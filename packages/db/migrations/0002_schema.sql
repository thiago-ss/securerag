-- 0002_schema.sql
-- Core schema. Every tenant-owned table: tenant_id NOT NULL, composite PK/unique/FK,
-- ENABLE + FORCE ROW LEVEL SECURITY (policies in 0003). Owner: securerag_owner.
-- Global (non-tenant) RLS tables: principals, sessions, tenant_memberships.

SET ROLE securerag_owner;

CREATE SCHEMA IF NOT EXISTS securerag AUTHORIZATION securerag_owner;

-- ---------- Global tables (no tenant_id) ----------

CREATE TABLE securerag.tenants (
  tenant_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE securerag.principals (
  principal_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider        text NOT NULL,
  external_subject text NOT NULL,
  display_name    text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT principals_provider_subject_unique UNIQUE (provider, external_subject)
);

CREATE TABLE securerag.sessions (
  session_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id uuid NOT NULL REFERENCES securerag.principals (principal_id),
  csrf_token  bytea NOT NULL,
  expires_at  timestamptz NOT NULL,
  revoked_at  timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_principal_idx ON securerag.sessions (principal_id);

-- Monotonic authorization epoch; changed by membership/group/grant/document/retention
-- decisions; checked at disclosure time to prevent stale disclosure.
CREATE TABLE securerag.authorization_epoch (
  epoch  bigint NOT NULL
);
INSERT INTO securerag.authorization_epoch (epoch) VALUES (0);

-- ---------- Tenant-owned tables ----------

CREATE TABLE securerag.tenant_memberships (
  tenant_id    uuid NOT NULL REFERENCES securerag.tenants (tenant_id),
  principal_id uuid NOT NULL REFERENCES securerag.principals (principal_id),
  membership_id uuid NOT NULL DEFAULT gen_random_uuid(),
  role         text NOT NULL CHECK (role IN ('admin', 'member', 'security_reviewer')),
  is_active    boolean NOT NULL DEFAULT true,
  joined_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, membership_id),
  CONSTRAINT tenant_memberships_tenant_principal_unique UNIQUE (tenant_id, principal_id)
);

-- Non-recursive admin mirror used by the memberships RLS policy (see ADR-0003).
-- Maintained by the application atomically with membership role changes; a row
-- exists iff the principal is an active admin of the tenant. Its own policy
-- guards both reads and writes; the memberships policy never re-enters itself.
CREATE TABLE securerag.tenant_admins (
  tenant_id    uuid NOT NULL REFERENCES securerag.tenants (tenant_id),
  principal_id uuid NOT NULL REFERENCES securerag.principals (principal_id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, principal_id)
);

CREATE TABLE securerag.groups (
  tenant_id  uuid NOT NULL REFERENCES securerag.tenants (tenant_id),
  group_id   uuid NOT NULL DEFAULT gen_random_uuid(),
  name       text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, group_id),
  CONSTRAINT groups_tenant_name_unique UNIQUE (tenant_id, name)
);

CREATE TABLE securerag.group_memberships (
  tenant_id    uuid NOT NULL,
  group_id     uuid NOT NULL,
  principal_id uuid NOT NULL,
  PRIMARY KEY (tenant_id, group_id, principal_id),
  CONSTRAINT group_memberships_group_fk
    FOREIGN KEY (tenant_id, group_id) REFERENCES securerag.groups (tenant_id, group_id),
  CONSTRAINT group_memberships_principal_fk
    FOREIGN KEY (principal_id) REFERENCES securerag.principals (principal_id)
);

CREATE TABLE securerag.documents (
  tenant_id    uuid NOT NULL REFERENCES securerag.tenants (tenant_id),
  document_id  uuid NOT NULL DEFAULT gen_random_uuid(),
  title        text NOT NULL,
  status       text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deleted')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, document_id)
);

-- One immutable source snapshot per version; one published current version per active document.
CREATE TABLE securerag.document_versions (
  tenant_id          uuid NOT NULL,
  document_id        uuid NOT NULL,
  version_id         uuid NOT NULL DEFAULT gen_random_uuid(),
  version_no         integer NOT NULL,
  source_object_key  text NOT NULL,
  content_hash       bytea NOT NULL,
  extracted_hash     bytea,
  status             text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'valid', 'quarantined', 'released', 'superseded', 'expired')),
  is_current         boolean NOT NULL DEFAULT false,
  created_at         timestamptz NOT NULL DEFAULT now(),
  published_at       timestamptz,
  PRIMARY KEY (tenant_id, version_id),
  CONSTRAINT document_versions_document_fk
    FOREIGN KEY (tenant_id, document_id) REFERENCES securerag.documents (tenant_id, document_id),
  CONSTRAINT document_versions_document_no_unique UNIQUE (tenant_id, document_id, version_no)
);
CREATE UNIQUE INDEX document_versions_current_unique
  ON securerag.document_versions (tenant_id, document_id) WHERE is_current;

CREATE TABLE securerag.document_grants (
  tenant_id    uuid NOT NULL,
  document_id  uuid NOT NULL,
  grant_id     uuid NOT NULL DEFAULT gen_random_uuid(),
  subject_type text NOT NULL CHECK (subject_type IN ('principal', 'group', 'tenant_role')),
  subject_id   text NOT NULL,
  capability   text NOT NULL CHECK (capability IN ('read', 'write', 'manage')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, grant_id),
  CONSTRAINT document_grants_document_fk
    FOREIGN KEY (tenant_id, document_id) REFERENCES securerag.documents (tenant_id, document_id),
  CONSTRAINT document_grants_unique
    UNIQUE (tenant_id, document_id, subject_type, subject_id, capability)
);

-- Immutable, redacted retrieval unit tied to one exact version.
CREATE TABLE securerag.chunks (
  tenant_id      uuid NOT NULL,
  version_id     uuid NOT NULL,
  chunk_id       uuid NOT NULL DEFAULT gen_random_uuid(),
  chunk_no       integer NOT NULL,
  text_redacted  text NOT NULL,
  span_start     integer NOT NULL,
  span_end       integer NOT NULL,
  content_hash   bytea NOT NULL,
  embedding      vector(384),
  search_vec     tsvector GENERATED ALWAYS AS (to_tsvector('english', text_redacted)) STORED,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, chunk_id),
  CONSTRAINT chunks_version_fk
    FOREIGN KEY (tenant_id, version_id)
    REFERENCES securerag.document_versions (tenant_id, version_id),
  CONSTRAINT chunks_version_no_unique UNIQUE (tenant_id, version_id, chunk_no)
);
CREATE INDEX chunks_search_vec_gin ON securerag.chunks USING gin (search_vec);

CREATE TABLE securerag.jobs (
  tenant_id        uuid NOT NULL REFERENCES securerag.tenants (tenant_id),
  job_id           uuid NOT NULL DEFAULT gen_random_uuid(),
  idempotency_key  text NOT NULL,
  job_type         text NOT NULL,
  status           text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'permanent_failed', 'cancelled')),
  payload_key      text,
  attempts         integer NOT NULL DEFAULT 0,
  max_attempts     integer NOT NULL DEFAULT 5,
  next_attempt_at  timestamptz NOT NULL DEFAULT now(),
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, job_id),
  CONSTRAINT jobs_tenant_idempotency_unique UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE securerag.retention_policies (
  tenant_id     uuid PRIMARY KEY REFERENCES securerag.tenants (tenant_id),
  source_days   integer NOT NULL DEFAULT 3650 CHECK (source_days >= 0),
  derived_days  integer NOT NULL DEFAULT 3650 CHECK (derived_days >= 0),
  audit_days    integer NOT NULL DEFAULT 1095 CHECK (audit_days >= 0),
  grace_days    integer NOT NULL DEFAULT 7 CHECK (grace_days >= 0),
  legal_hold    boolean NOT NULL DEFAULT false,
  updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Insert-only for runtime roles; hash chain for tamper evidence (app computes hashes).
CREATE TABLE securerag.audit_events (
  tenant_id        uuid NOT NULL,
  event_id         bigint GENERATED BY DEFAULT AS IDENTITY,
  event_type       text NOT NULL,
  occurred_at      timestamptz NOT NULL DEFAULT now(),
  request_id       uuid NOT NULL,
  trace_id         text,
  principal_id     uuid,
  membership_id    uuid,
  auth_epoch       bigint NOT NULL,
  redacted_query   text,
  query_hash       bytea,
  filters          jsonb,
  candidate_ids    jsonb,
  scores           jsonb,
  selected_ids     jsonb,
  policy_versions  jsonb,
  evidence_decision text,
  model_status     text,
  citations        jsonb,
  refusal_reason   text,
  latency_ms       integer,
  answer_hash      bytea,
  prev_event_hash  bytea,
  event_hash       bytea,
  PRIMARY KEY (tenant_id, event_id)
);

-- ---------- Functions (invoker rights only; never SECURITY DEFINER) ----------

-- Context helpers: unset custom GUCs read as '' with missing_ok, so normalize to
-- NULL (default deny) instead of failing the ::uuid cast.
CREATE FUNCTION securerag.ctx_tenant_id()
RETURNS uuid
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
  SELECT NULLIF(current_setting('securerag.tenant_id', true), '')::uuid
$$;

CREATE FUNCTION securerag.ctx_principal_id()
RETURNS uuid
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
  SELECT NULLIF(current_setting('securerag.principal_id', true), '')::uuid
$$;

CREATE FUNCTION securerag.ctx_principal_is_admin(tenant uuid)
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
  SELECT EXISTS (
    SELECT 1 FROM securerag.tenant_admins
    WHERE tenant_id = ctx_principal_is_admin.tenant
      AND principal_id = securerag.ctx_principal_id()
  )
$$;

-- Monotonic authorization epoch bump. SECURITY DEFINER (owned by the NOLOGIN
-- owner; see ADR-0013): the ONLY legal write path for the epoch, because runtime
-- roles hold no UPDATE on authorization_epoch. Tiny interface (no arguments),
-- pinned search_path, PUBLIC execute revoked in 0003.
CREATE FUNCTION securerag.bump_authorization_epoch()
RETURNS bigint
LANGUAGE sql
SECURITY DEFINER
SET search_path = securerag, pg_catalog
PARALLEL SAFE
AS $$
  UPDATE securerag.authorization_epoch SET epoch = epoch + 1 RETURNING epoch;
$$;

-- ---------- Views (security_invoker) ----------

-- Tenants the context principal administers (reads the admin mirror; used by
-- admin management flows without re-entering tenant_memberships).
CREATE VIEW securerag.admin_scope
WITH (security_invoker) AS
SELECT DISTINCT tenant_id
FROM securerag.tenant_admins
WHERE principal_id = securerag.ctx_principal_id();

RESET ROLE;
