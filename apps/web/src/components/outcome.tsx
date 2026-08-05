import type { Citation, RefusalCode, RetrievalOutcome } from '../types';
import { navigate } from '../router';

/**
 * Retrieval outcome rendering. Answers are TEXT ONLY — never rendered as
 * HTML (no dangerouslySetInnerHTML anywhere in the console); citations are
 * plain links/lists.
 */

const REFUSAL_MESSAGES: Record<RefusalCode, string> = {
  INSUFFICIENT_EVIDENCE:
    'There is not enough authorized evidence to answer this question. Nothing was generated.',
  CONFLICTING_EVIDENCE:
    'The authorized evidence contains conflicting statements, so no answer was produced.',
  CITATION_UNSUPPORTED:
    'The candidate answer could not be supported by exact citations, so no answer was produced.',
};

export function RefusalPanel({ code, message }: { code: RefusalCode; message: string }): React.ReactNode {
  return (
    <div role="alert" className="refusal" data-testid={`refusal-${code}`} aria-live="polite">
      <h2 className="section-title">Refused</h2>
      <p className="refusal-code">
        <strong>{code}</strong> — {message}
      </p>
      <p className="refusal-detail">{REFUSAL_MESSAGES[code]}</p>
    </div>
  );
}

export function CitationLink({ citation }: { citation: Citation }): React.ReactNode {
  return (
    <li className="citation-item">
      <a
        href={`#/documents/${citation.documentId}`}
        className="citation-link"
        onClick={(event) => {
          event.preventDefault();
          navigate(`/documents/${citation.documentId}`);
        }}
      >
        Document {citation.documentId.slice(0, 8)} — version {citation.versionId.slice(0, 8)}
      </a>
      <span className="citation-excerpt">“{citation.excerpt}”</span>
    </li>
  );
}

export function AnswerPanel({ answer, citations }: { answer: string; citations: Citation[] }): React.ReactNode {
  return (
    <div role="region" aria-label="Answer" className="answer" data-testid="answer-panel">
      <h2 className="section-title">Answer</h2>
      <p className="answer-text">{answer}</p>
      {citations.length > 0 ? (
        <>
          <h3 className="citations-title">Citations</h3>
          <ol className="citations-list">
            {citations.map((citation, index) => (
              <CitationLink key={`${citation.chunkId}-${index}`} citation={citation} />
            ))}
          </ol>
        </>
      ) : (
        <p className="status-text">No citations were produced.</p>
      )}
    </div>
  );
}

export function OutcomePanel({ outcome }: { outcome: RetrievalOutcome }): React.ReactNode {
  if (outcome.decision === 'answered') {
    return <AnswerPanel answer={outcome.answer} citations={outcome.citations} />;
  }
  return <RefusalPanel code={outcome.code} message={outcome.message} />;
}
