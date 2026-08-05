import type { EvidenceChunk } from './types.js';

export type EvidenceDecision = 'answered' | 'INSUFFICIENT_EVIDENCE';

/**
 * Calibrated evidence floor (ADR-0009): a bundle below this many authorized
 * chunks cannot support a material claim with citation coverage. T3 value: 2
 * (a single chunk — even when authorized — is refused until the corpus
 * calibrates higher).
 */
export const EVIDENCE_MIN_CHUNKS = 2;

/**
 * Deterministic evidence gate. `question` is part of the contract signature
 * (entity-coverage scoring lands later); today it only guards the degenerate
 * empty-query case. Never raw scores — count semantics only.
 */
export function decide(bundle: readonly EvidenceChunk[], question: string): EvidenceDecision {
  if (question.trim().length === 0) return 'INSUFFICIENT_EVIDENCE';
  if (bundle.length === 0) return 'INSUFFICIENT_EVIDENCE';
  if (bundle.length < EVIDENCE_MIN_CHUNKS) return 'INSUFFICIENT_EVIDENCE';
  return 'answered';
}
