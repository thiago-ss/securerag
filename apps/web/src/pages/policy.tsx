import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { api, ApiError } from '../api';
import type { RetentionPolicy } from '../types';
import { useSession } from '../session';
import { ErrorNotice, FocusHeading, Loading, SuccessNotice, TextField } from '../components/ui';

type LoadState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; policy: RetentionPolicy };

/** Retention policy: read for every member, edit for tenant admins (the API
 * enforces the admin gate — non-admins' PUTs are indistinguishable 404s). */
export function PolicyPage(): ReactNode {
  const session = useSession();
  const tenantId = session.tenantId;
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async (): Promise<void> => {
    if (tenantId === null) {
      setState({ kind: 'error', message: 'You have no tenant membership yet.' });
      return;
    }
    setState({ kind: 'loading' });
    try {
      const policy = await api.getRetentionPolicy(tenantId);
      setState({ kind: 'ready', policy });
    } catch (err) {
      setState({
        kind: 'error',
        message: err instanceof ApiError ? err.message : 'Could not load the retention policy',
      });
    }
  }, [tenantId]);

  useEffect(() => {
    void load();
  }, [load]);

  const role = session.me?.memberships.find((m) => m.tenantId === tenantId)?.role ?? null;
  const isAdmin = role === 'admin';

  const save = async (patch: Omit<Partial<RetentionPolicy>, 'tenantId' | 'updatedAt'>): Promise<void> => {
    if (tenantId === null) return;
    setSaving(true);
    try {
      const policy = await api.putRetentionPolicy({ ...patch, tenantId });
      setState({ kind: 'ready', policy });
      setNotice('Retention policy updated.');
    } catch (err) {
      setNotice(err instanceof ApiError ? err.message : 'Could not update the retention policy');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="page">
      <FocusHeading>Retention policy</FocusHeading>
      {state.kind === 'loading' ? <Loading label="Loading policy" /> : null}
      {state.kind === 'error' ? <ErrorNotice message={state.message} /> : null}
      {state.kind === 'ready' ? (
        <>
          <p>
            Tenant <code>{state.policy.tenantId}</code> — updated {state.policy.updatedAt}. Days until
            expiry: source {state.policy.sourceDays}, derived {state.policy.derivedDays}, audit{' '}
            {state.policy.auditDays}, grace {state.policy.graceDays}. Legal hold:{' '}
            {state.policy.legalHold ? 'on' : 'off'}.
          </p>
          {isAdmin ? (
            <PolicyForm policy={state.policy} saving={saving} onSave={save} />
          ) : (
            <p className="status-text">
              Only tenant admins can edit the policy. Changes are audited and bump the authorization
              epoch.
            </p>
          )}
        </>
      ) : null}
      {notice !== null ? <SuccessNotice>{notice}</SuccessNotice> : null}
    </div>
  );
}

function PolicyForm({
  policy,
  saving,
  onSave,
}: {
  policy: RetentionPolicy;
  saving: boolean;
  onSave: (patch: Omit<Partial<RetentionPolicy>, 'tenantId' | 'updatedAt'>) => Promise<void>;
}): ReactNode {
  const [sourceDays, setSourceDays] = useState(String(policy.sourceDays));
  const [derivedDays, setDerivedDays] = useState(String(policy.derivedDays));
  const [auditDays, setAuditDays] = useState(String(policy.auditDays));
  const [graceDays, setGraceDays] = useState(String(policy.graceDays));
  const [legalHold, setLegalHold] = useState(policy.legalHold);

  const submit = (event: FormEvent): void => {
    event.preventDefault();
    void onSave({
      sourceDays: Number(sourceDays),
      derivedDays: Number(derivedDays),
      auditDays: Number(auditDays),
      graceDays: Number(graceDays),
      legalHold,
    });
  };

  return (
    <form className="policy-form" onSubmit={submit}>
      <TextField label="Source retention (days)" type="number" min={0} value={sourceDays} onChange={(e) => setSourceDays(e.target.value)} />
      <TextField label="Derived retention (days)" type="number" min={0} value={derivedDays} onChange={(e) => setDerivedDays(e.target.value)} />
      <TextField label="Audit retention (days)" type="number" min={0} value={auditDays} onChange={(e) => setAuditDays(e.target.value)} />
      <TextField label="Grace period (days)" type="number" min={0} value={graceDays} onChange={(e) => setGraceDays(e.target.value)} />
      <label className="checkbox-row">
        <input type="checkbox" checked={legalHold} onChange={(e) => setLegalHold(e.target.checked)} />
        Legal hold (blocks deletion)
      </label>
      <button type="submit" className="button button-primary" disabled={saving}>
        {saving ? 'Saving…' : 'Save policy'}
      </button>
    </form>
  );
}
