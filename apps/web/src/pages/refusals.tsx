import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { api, ApiError } from '../api';
import type { AuditRecord } from '../types';
import { useSession } from '../session';
import { EmptyState, ErrorNotice, FocusHeading, Loading } from '../components/ui';

type LoadState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; events: AuditRecord[] };

/** Refusals log: every deterministic refusal recorded for your tenants
 * (derived from the retrieval audit trail — refusalReason is set only on
 * refused runs). */
export function RefusalsPage(): ReactNode {
  const session = useSession();
  const [state, setState] = useState<LoadState>({ kind: 'loading' });

  const load = useCallback(async (): Promise<void> => {
    setState({ kind: 'loading' });
    try {
      const { events } = await api.listAudit(100);
      const refusals = events.filter((event) => event.refusalReason !== null);
      setState({ kind: 'ready', events: refusals });
    } catch (err) {
      setState({
        kind: 'error',
        message: err instanceof ApiError ? err.message : 'Could not load the refusals log',
      });
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="page">
      <FocusHeading>Refusals log</FocusHeading>
      <p>
        Every retrieval that was refused — with the deterministic reason and the redacted question.
        Refusals are audited and cannot be overridden by the model.
      </p>
      {state.kind === 'loading' ? <Loading label="Loading refusals" /> : null}
      {state.kind === 'error' ? <ErrorNotice message={state.message} /> : null}
      {state.kind === 'ready' ? (
        state.events.length === 0 ? (
          <EmptyState>No refusals recorded.</EmptyState>
        ) : (
          <table className="data-table">
            <caption className="sr-only">Refused retrieval runs</caption>
            <thead>
              <tr>
                <th scope="col">When</th>
                <th scope="col">Reason</th>
                <th scope="col">Question (redacted)</th>
                <th scope="col">Request</th>
              </tr>
            </thead>
            <tbody>
              {state.events.map((event) => (
                <tr key={event.eventId}>
                  <td>{event.occurredAt}</td>
                  <td>
                    <code>{event.refusalReason}</code>
                  </td>
                  <td>{event.redactedQuery ?? '—'}</td>
                  <td>
                    <code>{event.requestId.slice(0, 8)}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      ) : null}
      <p className="status-text">
        Showing refusals across {session.tenantId !== null ? 'your current tenant' : 'your tenants'} (up to
        100 events).
      </p>
    </div>
  );
}
