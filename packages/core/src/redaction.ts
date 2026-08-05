/**
 * Redaction pipeline helpers (S4; ADR-0005 pipeline placement, r5 §5).
 *
 * Every boundary where content leaves a trust domain runs the SAME detector
 * with the SAME canonical tokens:
 *  - redactQuestion: before embedding AND before the provider payload AND
 *    before audit storage (corpus<->query token alignment).
 *  - redactBundleChunks: the evidence bundle that reaches the model is
 *    RE-redacted at the retrieval boundary — raw PII must NEVER reach model
 *    context, even for `pii:read` principals (ADR-0005: derived data is
 *    redacted for everyone, always; the model never needs raw values).
 *  - redactForSurface: human surfaces honor `pii:read`; without it the text
 *    is redacted (preview/source/export/citation excerpts).
 *
 * Redaction is defense-in-depth, never authorization: a detector miss never
 * weakens RLS/ACL enforcement (threat-model policy).
 */
import {
  DeterministicPiiDetector,
  redactText,
  type PiiDetector,
} from '@securerag/providers';
import type { EvidenceChunk } from './types.js';

export interface PiiConfig {
  /** Detector used at every redaction boundary (v1: the deterministic adapter). */
  detector: PiiDetector;
  /** Tenant-configurable feature flag; disabled passes text through untouched. */
  enabled: boolean;
}

/** Default: deterministic adapter, feature on (ADR-0005). */
export const DEFAULT_PII_CONFIG: PiiConfig = Object.freeze({
  detector: new DeterministicPiiDetector(),
  enabled: true,
});

/**
 * Redact the user question before it is embedded, sent to the provider, or
 * stored in audit. Redacted questions still retrieve redacted chunks because
 * the token vocabulary is identical in corpus and query (r5 §4.3).
 */
export function redactQuestion(question: string, pii: PiiConfig = DEFAULT_PII_CONFIG): string {
  if (!pii.enabled) return question;
  return redactText(question, pii.detector.detect(question));
}

/**
 * Redact every evidence chunk at the retrieval boundary. ALWAYS applied to
 * what reaches the model (question, bundle, citations), regardless of
 * `pii:read` — the provider context never carries raw PII (ADR-0005).
 */
export function redactBundleChunks(
  chunks: readonly EvidenceChunk[],
  pii: PiiConfig = DEFAULT_PII_CONFIG,
): EvidenceChunk[] {
  if (!pii.enabled) return [...chunks];
  return chunks.map((chunk) => {
    const matches = pii.detector.detect(chunk.text);
    return matches.length === 0 ? chunk : { ...chunk, text: redactText(chunk.text, matches) };
  });
}

/**
 * Human-surface redaction: principals holding `pii:read` see the original
 * text for documents they are already authorized to read; everyone else gets
 * the redacted derivative. Never used for model/provider payloads.
 */
export function redactForSurface(
  text: string,
  pii: PiiConfig = DEFAULT_PII_CONFIG,
  piiRead: boolean,
): string {
  if (!pii.enabled || piiRead) return text;
  return redactText(text, pii.detector.detect(text));
}
