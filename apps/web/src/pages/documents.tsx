import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { api, ApiError } from '../api';
import type { DocumentListItem } from '../types';
import { navigate } from '../router';
import { useSession } from '../session';
import { EmptyState, ErrorNotice, FocusHeading, Loading, SuccessNotice, TextField } from '../components/ui';

type LoadState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; documents: DocumentListItem[] };

export function DocumentsPage(): ReactNode {
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
      const { documents } = await api.listDocuments(tenantId);
      setState({ kind: 'ready', documents });
    } catch (err) {
      setState({
        kind: 'error',
        message: err instanceof ApiError ? err.message : 'Could not load documents',
      });
    }
  }, [tenantId]);

  useEffect(() => {
    void load();
  }, [load]);

  const createDocument = async (title: string): Promise<void> => {
    if (tenantId === null) return;
    try {
      const { document } = await api.createDocument(tenantId, title);
      setNotice(`Document “${document.title}” created — you can now upload a version.`);
      await load();
    } catch (err) {
      setNotice(null);
      setState({
        kind: 'error',
        message: err instanceof ApiError ? err.message : 'Could not create the document',
      });
    }
  };

  return (
    <div className="page">
      <div className="page-header-row">
        <FocusHeading>Document library</FocusHeading>
        <CreateDocumentForm onSubmit={createDocument} disabled={tenantId === null} />
      </div>
      {notice !== null ? <SuccessNotice>{notice}</SuccessNotice> : null}
      {state.kind === 'loading' ? <Loading label="Loading documents" /> : null}
      {state.kind === 'error' ? <ErrorNotice message={state.message} /> : null}
      {state.kind === 'ready' ? (
        state.documents.length === 0 ? (
          <EmptyState>No documents are visible to you yet. Create one to get started.</EmptyState>
        ) : (
          <DocumentTable documents={state.documents} onChanged={load} />
        )
      ) : null}
    </div>
  );
}

function CreateDocumentForm({
  onSubmit,
  disabled,
}: {
  onSubmit: (title: string) => Promise<void>;
  disabled: boolean;
}): ReactNode {
  const [title, setTitle] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    if (title.trim() === '') return;
    setBusy(true);
    try {
      await onSubmit(title.trim());
      setTitle('');
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="inline-form" onSubmit={(event) => void submit(event)}>
      <TextField
        label="New document title"
        value={title}
        onChange={(event) => setTitle(event.target.value)}
        placeholder="e.g. Acme sales playbook"
        disabled={disabled || busy}
      />
      <button type="submit" className="button button-primary" disabled={disabled || busy || title.trim() === ''}>
        {busy ? 'Creating…' : 'Create document'}
      </button>
    </form>
  );
}

function DocumentTable({
  documents,
  onChanged,
}: {
  documents: DocumentListItem[];
  onChanged: () => Promise<void>;
}): ReactNode {
  return (
    <table className="data-table">
      <caption className="sr-only">Documents you can access in this tenant</caption>
      <thead>
        <tr>
          <th scope="col">Title</th>
          <th scope="col">Status</th>
          <th scope="col">Access</th>
          <th scope="col">
            <span className="sr-only">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {documents.map((document) => (
          <DocumentRow key={document.documentId} document={document} onChanged={onChanged} />
        ))}
      </tbody>
    </table>
  );
}

function DocumentRow({
  document,
  onChanged,
}: {
  document: DocumentListItem;
  onChanged: () => Promise<void>;
}): ReactNode {
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const upload = async (file: File): Promise<void> => {
    setUploading(true);
    setMessage(null);
    try {
      const job = await api.uploadVersion(document.documentId, file);
      setMessage(`Upload received — processing job ${job.jobId.slice(0, 8)}.`);
      await onChanged();
    } catch (err) {
      setMessage(err instanceof ApiError ? err.message : 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  const capabilities = [
    document.canRead ? 'read' : null,
    document.canWrite ? 'write' : null,
    document.canManage ? 'manage' : null,
  ].filter((c) => c !== null);

  return (
    <tr>
      <td>
        <a
          href={`#/documents/${document.documentId}`}
          onClick={(event) => {
            event.preventDefault();
            navigate(`/documents/${document.documentId}`);
          }}
        >
          {document.title}
        </a>
      </td>
      <td>
        <StatusBadge status={document.status} />
      </td>
      <td>{capabilities.length > 0 ? capabilities.join(', ') : '—'}</td>
      <td>
        <div className="row-actions">
          <a
            className="button button-small"
            href={`#/documents/${document.documentId}`}
            onClick={(event) => {
              event.preventDefault();
              navigate(`/documents/${document.documentId}`);
            }}
          >
            Open
          </a>
          {document.canManage ? (
            <UploadControl documentId={document.documentId} title={document.title} uploading={uploading} onUpload={upload} />
          ) : null}
          {message !== null ? (
            <span role="status" className="status-text">
              {message}
            </span>
          ) : null}
        </div>
      </td>
    </tr>
  );
}

function UploadControl({
  documentId,
  title,
  uploading,
  onUpload,
}: {
  documentId: string;
  title: string;
  uploading: boolean;
  onUpload: (file: File) => Promise<void>;
}): ReactNode {
  const [file, setFile] = useState<File | null>(null);
  const id = `upload-${documentId}`;
  const change = (event: React.ChangeEvent<HTMLInputElement>): void => {
    setFile(event.target.files?.[0] ?? null);
  };
  return (
    <span className="upload-control">
      <label htmlFor={id} className="button button-small">
        Upload version
      </label>
      <input
        id={id}
        type="file"
        className="sr-only"
        accept=".pdf,.docx,.txt"
        disabled={uploading}
        onChange={change}
      />
      {file !== null ? (
        <>
          <span className="status-text">{file.name}</span>
          <button
            type="button"
            className="button button-small button-primary"
            disabled={uploading}
            onClick={() => void onUpload(file)}
          >
            {uploading ? 'Uploading…' : `Upload to “${title}”`}
          </button>
        </>
      ) : null}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }): ReactNode {
  return <span className={`badge badge-${status.replace(/[^a-z0-9-]/g, '')}`}>{status}</span>;
}
