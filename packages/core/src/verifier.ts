import type { Citation } from './types.js';

/**
 * Deterministic citation verifier (ADR-0009, S7) — INDEPENDENT of the
 * generating model: no model, no randomness, no heuristics beyond the
 * documented claim detector. The SpyGenerator contract is preserved; this
 * module never touches it.
 *
 * v1 rules:
 *  (a) MEMBERSHIP — every citation id returned by the generator must be a
 *      bundle chunk id. A generator returning a foreign/fabricated id fails
 *      here, before any resolution work.
 *  (b) CLAIMS-TO-CITATIONS — the answer is split into sentences (on .!?); a
 *      sentence is a MATERIAL CLAIM when it contains a claim verb
 *      (is|are|was|were|reached|stood at|equals|amounts to|... — the labeled
 *      fixtures in core/test/verifier.test.ts define detection). When the
 *      answer contains >= 1 claim sentence:
 *        - the answer must return >= 1 citation, and
 *        - EVERY claim sentence must reference >= 1 citation id IN ITS
 *          SENTENCE, and every in-sentence reference must be one of the
 *          returned citations.
 *      Sentences without a claim verb (e.g. "Synthesis of authorized evidence
 *      [id]") are meta and carry no citation obligation.
 *
 * Documented limits (v1): no paraphrase/substring claim matching; the claim
 * detector is verb-based; citation ids are expected in UUID shape
 * (xxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx) as produced by the corpus tooling.
 */

export const CITATION_ID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;

/** Claim verbs (lowercase, word-bounded) — the labeled claim-detection set. */
const CLAIM_VERB_RE =
  /\b(?:is|are|was|were|reached|stood at|equals|amounts to|contains|states that|reports that|shows that|says that|indicates that|provides that|requires|allows|includes|rises to|falls to|changed to|has|have)\b/i;

/** Telegraphic material claims without verbs (S7 review 5): "Q3 revenue: 5
 * million." / "Revenue 5M" / "Price $12.50". A colon-separated value
 * statement or an entity+quantity without a verb is still a material claim
 * that must carry a citation. */
const TELEGRAPHIC_CLAIM_RE =
  /(?:^|[.!?]\s+)[A-Z][^.!?]{0,80}?:\s*(?:[A-Z$€£]|\d|['"“])/;

/** Telegraphic entity+quantity: "Revenue 5 million" / "Revenue was..." is
 * covered by verbs; without a verb ("Revenue 5M", "Headcount 40") the pattern
 * below fires only on explicit quantity shapes to limit false positives. */
const QUANTITY_CLAIM_RE =
  /(?:^|[.!?]\s+)[A-Z][A-Za-z ]{1,40}\s\d[\d,.]*\s*(?:million|billion|thousand|M|K|%|\$|USD|EUR)?\b/i;

export function splitSentences(text: string): string[] {
  return text
    .split(/(?<=[.!?])\s+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** Material-claim sentence (verb + telegraphic shapes; labeled fixtures
 * define the set). Telegraphic answers like "Q3 revenue: 5 million." are
 * claims and must carry a citation (S7 review 5). */
export function isClaimSentence(sentence: string): boolean {
  return CLAIM_VERB_RE.test(sentence) ||
    TELEGRAPHIC_CLAIM_RE.test(sentence) ||
    QUANTITY_CLAIM_RE.test(sentence);
}

/** Citation ids referenced inside a sentence/answer (UUID shape). */
export function citationIdsIn(text: string): string[] {
  return [...text.matchAll(CITATION_ID_RE)].map((m) => m[0]);
}

export interface CitationVerification {
  ok: boolean;
  issues: string[];
  /** Detected material-claim sentences (for tests and diagnostics). */
  claims: string[];
}

export interface VerifyCitationsInput {
  answer: string;
  citations: readonly Citation[];
  /** Chunk ids that were actually in the evidence bundle. */
  bundleChunkIds: ReadonlySet<string>;
}

export function verifyCitations(input: VerifyCitationsInput): CitationVerification {
  const issues: string[] = [];
  const citedIds = input.citations.map((c) => c.chunkId);

  for (const citation of input.citations) {
    if (!input.bundleChunkIds.has(citation.chunkId)) {
      issues.push(`citation ${citation.chunkId} is not in the evidence bundle (fabricated or foreign)`);
    }
  }

  const claims = splitSentences(input.answer).filter(isClaimSentence);
  if (claims.length > 0 && citedIds.length === 0) {
    issues.push('answer makes material claims but returns no citations');
  }
  for (const sentence of claims) {
    const inSentence = citationIdsIn(sentence);
    if (inSentence.length === 0) {
      issues.push(`material claim sentence cites nothing: "${sentence.slice(0, 100)}"`);
      continue;
    }
    for (const id of inSentence) {
      if (!citedIds.includes(id)) {
        issues.push(`sentence references citation ${id} which is not in the returned citation list`);
      }
    }
  }

  return { ok: issues.length === 0, issues, claims };
}
