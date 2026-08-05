import { useState, type FormEvent, type ReactNode } from 'react';
import { api, ApiError } from '../api';
import type { RetrievalOutcome } from '../types';
import { useSession } from '../session';
import { ErrorNotice, FocusHeading, TextAreaField } from '../components/ui';
import { OutcomePanel } from '../components/outcome';

type ResultState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'done'; outcome: RetrievalOutcome };

/** Search/answer: ask a question, render the answer + citations or the typed
 * refusal state. Answers are text-only (never HTML). */
export function SearchPage(): ReactNode {
  const session = useSession();
  const tenantId = session.tenantId;
  const [question, setQuestion] = useState('');
  const [result, setResult] = useState<ResultState>({ kind: 'idle' });

  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    if (tenantId === null || question.trim() === '') return;
    setResult({ kind: 'loading' });
    try {
      const outcome = await api.queryRetrieval(tenantId, question.trim());
      setResult({ kind: 'done', outcome });
    } catch (err) {
      setResult({
        kind: 'error',
        message: err instanceof ApiError ? err.message : 'The search could not be completed',
      });
    }
  };

  return (
    <div className="page">
      <FocusHeading>Search and answer</FocusHeading>
      <form className="search-form" onSubmit={(event) => void submit(event)}>
        <TextAreaField
          label="Question"
          hint="Ask about the documents you are authorized to read. Answers cite exact sources."
          value={question}
          onChange={(event) => setQuestion(event.target.value)}
          rows={3}
          placeholder="e.g. What is the approved sales playbook for the launch?"
          disabled={tenantId === null}
        />
        <button
          type="submit"
          className="button button-primary"
          disabled={tenantId === null || question.trim() === '' || result.kind === 'loading'}
        >
          {result.kind === 'loading' ? 'Searching…' : 'Search'}
        </button>
      </form>
      <div aria-live="polite" className="outcome-region">
        {result.kind === 'error' ? <ErrorNotice message={result.message} /> : null}
        {result.kind === 'loading' ? (
          <p role="status" className="status-text" data-testid="loading">
            Retrieving and verifying evidence…
          </p>
        ) : null}
        {result.kind === 'done' ? <OutcomePanel outcome={result.outcome} /> : null}
        {result.kind === 'idle' ? (
          <p role="status" className="empty-state">
            Enter a question to search your authorized documents.
          </p>
        ) : null}
      </div>
    </div>
  );
}
