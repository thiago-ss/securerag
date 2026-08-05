import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, ApiError } from '../api';
import type { AuditRecord } from '../types';
import { EmptyState, ErrorNotice, FocusHeading, Loading, SelectField } from '../components/ui';

type LoadState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; events: AuditRecord[] };

const EVENT_TYPES = [
  'retrieval:allowed',
  'retrieval:refused',
  'document:read',
  'document:created',
  'citation:resolved',
  'membership:changed',
  'group:changed',
  'grant:changed',
  'version:review',
  'retention:changed',
  'ingest:published',
  'ingest:rejected',
];

function csvCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  const text = Array.isArray(value) ? JSON.stringify(value) : String(value);
  return `"${text.replace(/"/g, '""')}"`;
}

/** Audit log: tenant-isolated retrieval/security events with filters and a
 * client-side CSV export (identifiers + redacted derivatives only — the API
 * never returns raw content). */
export function AuditPage(): ReactNode {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [eventType, setEventType] = useState<string>('all');
  const [limit, setLimit] = useState(50);

  const load = useCallback(async (): Promise<void> => {
    setState({ kind: 'loading' });
    try {
      const { events } = await api.listAudit(limit);
      setState({ kind: 'ready', events });
    } catch (err) {
      setState({
        kind: 'error',
        message: err instanceof ApiError ? err.message : 'Could not load the audit log',
      });
    }
  }, [limit]);

  useEffect(() => {
    void load();
  }, [load]);

  const filtered = useMemo(() => {
    if (state.kind !== 'ready') return [];
    return eventType === 'all' ? state.events : state.events.filter((e) => e.eventType === eventType);
  }, [state, eventType]);

  const exportCsv = (): void => {
    const header = [
      'eventId',
      'occurredAt',
      'eventType',
      'requestId',
      'principalId',
      'tenantId',
      'redactedQuery',
      'refusalReason',
      'latencyMs',
      'citationCount',
    ];
    const rows = filtered.map((event) =>
      [
        event.eventId,
        event.occurredAt,
        event.eventType,
        event.requestId,
        event.principalId,
        event.tenantId,
        event.redactedQuery,
        event.refusalReason,
        event.latencyMs,
        event.citations?.length ?? '',
      ]
        .map(csvCell)
        .join(','),
    );
    const blob = new Blob([`${header.map(csvCell).join(',')}\n${rows.join('\n')}`], {
      type: 'text/csv;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'securerag-audit.csv';
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="page">
      <div className="page-header-row">
        <FocusHeading>Audit log</FocusHeading>
        <button
          type="button"
          className="button button-primary"
          data-testid="audit-export"
          onClick={exportCsv}
          disabled={filtered.length === 0}
        >
          Export CSV
        </button>
      </div>
      <div className="filter-row">
        <SelectField label="Event type" value={eventType} onChange={(event) => setEventType(event.target.value)}>
          <option value="all">All events</option>
          {EVENT_TYPES.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </SelectField>
        <SelectField label="Limit" value={limit} onChange={(event) => setLimit(Number(event.target.value))}>
          <option value={25}>25</option>
          <option value={50}>50</option>
          <option value={100}>100</option>
        </SelectField>
      </div>
      {state.kind === 'loading' ? <Loading label="Loading audit events" /> : null}
      {state.kind === 'error' ? <ErrorNotice message={state.message} /> : null}
      {state.kind === 'ready' ? (
        filtered.length === 0 ? (
          <EmptyState>No audit events match the current filter.</EmptyState>
        ) : (
          <table className="data-table">
            <caption className="sr-only">Audit events for your tenants</caption>
            <thead>
              <tr>
                <th scope="col">When</th>
                <th scope="col">Event</th>
                <th scope="col">Principal</th>
                <th scope="col">Query (redacted)</th>
                <th scope="col">Refusal</th>
                <th scope="col">Latency</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((event) => (
                <tr key={event.eventId}>
                  <td>{event.occurredAt}</td>
                  <td>
                    <code>{event.eventType}</code>
                  </td>
                  <td>
                    <code>{event.principalId.slice(0, 8)}</code>
                  </td>
                  <td>{event.redactedQuery ?? '—'}</td>
                  <td>{event.refusalReason ?? '—'}</td>
                  <td>{event.latencyMs !== null ? `${event.latencyMs} ms` : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      ) : null}
    </div>
  );
}
