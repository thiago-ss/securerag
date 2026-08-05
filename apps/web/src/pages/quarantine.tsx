import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { api, ApiError } from '../api';
import type { QuarantineRecord } from '../types';
import { useSession } from '../session';
import { EmptyState, ErrorNotice, FocusHeading, Loading, SuccessNotice } from '../components/ui';
import { StatusBadge } from './documents';

type LoadState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; versions: QuarantineRecord[] };

/** Quarantine review: list quarantined versions and release or keep them.
 * Review is audited; only security reviewers/admins may act (API 404 for
 * everyone else — the UI shows the empty state). */
export function QuarantinePage(): ReactNode {
  const session = useSession();
  const tenantId = session.tenantId;
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async (): Promise<void> => {
    if (tenantId === null) {
      setState({ kind: 'error', message: 'You have no tenant membership yet.' });
      return;
    }
    setState({ kind: 'loading' });
    try {
      const { versions } = await api.listQuarantine(tenantId);
      setState({ kind: 'ready', versions });
    } catch (err) {
      setState({
        kind: 'error',
        message: err instanceof ApiError ? err.message : 'Could not load the quarantine list',
      });
    }
  }, [tenantId]);

  useEffect(() => {
    void load();
  }, [load]);

  const review = async (versionId: string, decision: 'release' | 'keep'): Promise<void> => {
    if (tenantId === null) return;
    try {
      await api.reviewQuarantine(versionId, { tenantId, decision });
      setNotice(`Version ${versionId.slice(0, 8)} ${decision === 'release' ? 'released' : 'kept in quarantine'}.`);
      await load();
    } catch (err) {
      setNotice(err instanceof ApiError ? err.message : 'Review failed');
    }
  };

  return (
    <div className="page">
      <FocusHeading>Quarantine review</FocusHeading>
      <p>
        Versions flagged by injection detection wait for a deterministic, audited review. They are never
        searchable while quarantined.
      </p>
      {notice !== null ? <SuccessNotice>{notice}</SuccessNotice> : null}
      {state.kind === 'loading' ? <Loading label="Loading quarantine" /> : null}
      {state.kind === 'error' ? <ErrorNotice message={state.message} /> : null}
      {state.kind === 'ready' ? (
        state.versions.length === 0 ? (
          <EmptyState>No quarantined versions.</EmptyState>
        ) : (
          <table className="data-table">
            <caption className="sr-only">Quarantined document versions</caption>
            <thead>
              <tr>
                <th scope="col">Title</th>
                <th scope="col">Version</th>
                <th scope="col">Status</th>
                <th scope="col">Created</th>
                <th scope="col">Review</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {state.versions.map((version) => (
                <tr key={version.versionId}>
                  <td>{version.title}</td>
                  <td>{version.versionNo}</td>
                  <td>
                    <StatusBadge status={version.status} />
                  </td>
                  <td>{version.createdAt}</td>
                  <td>
                    {version.reviewDecision !== null
                      ? `${version.reviewDecision} by ${version.reviewedBy ?? 'unknown'}`
                      : 'Pending'}
                  </td>
                  <td>
                    <div className="row-actions">
                      <button
                        type="button"
                        className="button button-small button-primary"
                        onClick={() => void review(version.versionId, 'release')}
                      >
                        Release
                      </button>
                      <button
                        type="button"
                        className="button button-small"
                        onClick={() => void review(version.versionId, 'keep')}
                      >
                        Keep quarantined
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      ) : null}
    </div>
  );
}
