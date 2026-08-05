import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { api, ApiError } from '../api';
import type { DocumentInfo, GrantEntry, VersionMetadata } from '../types';
import {
  EmptyState,
  ErrorNotice,
  FocusHeading,
  Loading,
  PageSection,
  SelectField,
  SuccessNotice,
  TextField,
} from '../components/ui';
import { StatusBadge } from './documents';

type DocState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; document: DocumentInfo; versions: VersionMetadata[] };

type GrantState =
  | { kind: 'loading' }
  | { kind: 'denied' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; grants: GrantEntry[] };

/** Document detail: metadata, version history, authorized source link, and
 * manage-gated grants management. */
export function DocumentDetailPage({ documentId }: { documentId: string }): ReactNode {
  const [docState, setDocState] = useState<DocState>({ kind: 'loading' });
  const [grantState, setGrantState] = useState<GrantState>({ kind: 'loading' });
  const [notice, setNotice] = useState<string | null>(null);

  const loadDocument = useCallback(async (): Promise<void> => {
    setDocState({ kind: 'loading' });
    try {
      const [document, versions] = await Promise.all([
        api.getDocument(documentId),
        api.listVersions(documentId),
      ]);
      setDocState({ kind: 'ready', document, versions: versions.versions });
    } catch (err) {
      setDocState({
        kind: 'error',
        message: err instanceof ApiError ? err.message : 'Could not load the document',
      });
    }
  }, [documentId]);

  const loadGrants = useCallback(async (): Promise<void> => {
    setGrantState({ kind: 'loading' });
    try {
      const { grants } = await api.listGrants(documentId);
      setGrantState({ kind: 'ready', grants });
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setGrantState({ kind: 'denied' });
        return;
      }
      setGrantState({
        kind: 'error',
        message: err instanceof ApiError ? err.message : 'Could not load grants',
      });
    }
  }, [documentId]);

  useEffect(() => {
    void loadDocument();
    void loadGrants();
  }, [loadDocument, loadGrants]);

  const currentVersion = docState.kind === 'ready'
    ? docState.versions.find((v) => v.isCurrent && (v.status === 'valid' || v.status === 'released'))
    : undefined;

  return (
    <div className="page">
      <FocusHeading>
        {docState.kind === 'ready' ? docState.document.title : 'Document'}
      </FocusHeading>
      {docState.kind === 'loading' ? <Loading label="Loading document" /> : null}
      {docState.kind === 'error' ? (
        <ErrorNotice message={docState.message} />
      ) : null}
      {docState.kind === 'ready' ? (
        <>
          <p>
            Status <StatusBadge status={docState.document.status} /> — ID {docState.document.documentId}
          </p>
          <PageSection title="Versions">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Version</th>
                  <th scope="col">Status</th>
                  <th scope="col">Published</th>
                  <th scope="col">Content hash</th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {docState.versions.map((version) => (
                  <tr key={version.versionId}>
                    <td>
                      {version.versionNo}
                      {version.isCurrent ? ' (current)' : ''}
                    </td>
                    <td>
                      <StatusBadge status={version.status} />
                    </td>
                    <td>{version.publishedAt ?? '—'}</td>
                    <td>
                      <code className="hash">{version.hash.slice(0, 12)}…</code>
                    </td>
                    <td>
                      {currentVersion !== undefined && version.versionId === currentVersion.versionId ? (
                        <a
                          className="button button-small"
                          href={api.sourceUrl(version.documentId, version.versionId)}
                          target="_blank"
                          rel="noreferrer"
                          download
                        >
                          View source
                        </a>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {docState.versions.length === 0 ? (
              <EmptyState>No versions yet — upload one from the document library.</EmptyState>
            ) : null}
          </PageSection>
        </>
      ) : null}
      <PageSection title="Grants">
        {grantState.kind === 'loading' ? <Loading label="Loading grants" /> : null}
        {grantState.kind === 'denied' ? (
          <EmptyState>You do not have manage access to this document’s grants.</EmptyState>
        ) : null}
        {grantState.kind === 'error' ? <ErrorNotice message={grantState.message} /> : null}
        {grantState.kind === 'ready' ? (
          <GrantManager
            documentId={documentId}
            grants={grantState.grants}
            onChanged={() => {
              void loadGrants();
              setNotice('Grants updated.');
            }}
            onError={(message) => setNotice(message)}
          />
        ) : null}
      </PageSection>
      {notice !== null ? <SuccessNotice>{notice}</SuccessNotice> : null}
    </div>
  );
}

function GrantManager({
  documentId,
  grants,
  onChanged,
  onError,
}: {
  documentId: string;
  grants: GrantEntry[];
  onChanged: () => void;
  onError: (message: string) => void;
}): ReactNode {
  const [subjectType, setSubjectType] = useState<GrantEntry['subjectType']>('principal');
  const [subjectId, setSubjectId] = useState('');
  const [capability, setCapability] = useState<GrantEntry['capability']>('read');
  const [busy, setBusy] = useState(false);

  const add = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    if (subjectId.trim() === '') return;
    setBusy(true);
    try {
      await api.addGrant(documentId, {
        subjectType,
        subjectId: subjectId.trim(),
        capability,
      });
      setSubjectId('');
      onChanged();
    } catch (err) {
      onError(err instanceof ApiError ? err.message : 'Could not add the grant');
    } finally {
      setBusy(false);
    }
  };

  const remove = async (grantId: string): Promise<void> => {
    try {
      await api.removeGrant(documentId, grantId);
      onChanged();
    } catch (err) {
      onError(err instanceof ApiError ? err.message : 'Could not remove the grant');
    }
  };

  return (
    <div>
      {grants.length === 0 ? <EmptyState>No grants yet — default deny.</EmptyState> : (
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">Subject type</th>
              <th scope="col">Subject</th>
              <th scope="col">Capability</th>
              <th scope="col">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {grants.map((grant) => (
              <tr key={grant.grantId}>
                <td>{grant.subjectType}</td>
                <td>
                  <code>{grant.subjectId}</code>
                </td>
                <td>{grant.capability}</td>
                <td>
                  <button
                    type="button"
                    className="button button-small button-danger"
                    onClick={() => void remove(grant.grantId)}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <form className="inline-form" onSubmit={(event) => void add(event)}>
        <SelectField
          label="Subject type"
          value={subjectType}
          onChange={(event) => setSubjectType(event.target.value as GrantEntry['subjectType'])}
        >
          <option value="principal">Principal</option>
          <option value="group">Group</option>
          <option value="tenant_role">Tenant role</option>
        </SelectField>
        <TextField
          label="Subject id"
          value={subjectId}
          onChange={(event) => setSubjectId(event.target.value)}
          placeholder={subjectType === 'tenant_role' ? 'member / admin / security_reviewer' : 'uuid'}
        />
        <SelectField
          label="Capability"
          value={capability}
          onChange={(event) => setCapability(event.target.value as GrantEntry['capability'])}
        >
          <option value="read">read</option>
          <option value="write">write</option>
          <option value="manage">manage</option>
        </SelectField>
        <button type="submit" className="button button-primary" disabled={busy || subjectId.trim() === ''}>
          {busy ? 'Adding…' : 'Add grant'}
        </button>
      </form>
    </div>
  );
}
