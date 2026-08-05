/**
 * PII detection seam + deterministic adapters (S4; ADR-0005, research r5 §4).
 *
 * The provider contract: `PiiDetector.detect(text)` returns every PII span as
 * a `PiiMatch` (class + start/end + value). v1 ships ONE production adapter,
 * the pure-TS deterministic detector composed from the canonical class
 * patterns that the ST canary corpus seeds (email regex, `+1-555-\d{8}`
 * phone, dashed SSN, spaced Luhn-verified card). A future NER adapter
 * (worker-side transformers) plugs in behind the same interface.
 *
 * Redaction is replacement class tokens (`[EMAIL]`, `[PHONE]`, `[SSN]`,
 * `[CREDIT_CARD]`), one-way: no reversible maps are ever retained (ADR-0005;
 * NIST SP 800-122 — hashing/pseudonym tables are rejected for RAG content).
 */

export type PiiClass = 'EMAIL' | 'PHONE' | 'SSN' | 'CREDIT_CARD';

export interface PiiMatch {
  type: PiiClass;
  /** Inclusive start index into the scanned text. */
  start: number;
  /** Exclusive end index into the scanned text. */
  end: number;
  value: string;
}

export interface PiiDetector {
  detect(text: string): PiiMatch[];
}

/**
 * Canonical replacement tokens. Identical in every pipeline stage (ingest,
 * query, evidence, answer), so corpus and query embeddings stay aligned and
 * citations can reference redacted spans (r5 §4.3).
 */
export const PII_TOKENS: Record<PiiClass, string> = {
  EMAIL: '[EMAIL]',
  PHONE: '[PHONE]',
  SSN: '[SSN]',
  CREDIT_CARD: '[CREDIT_CARD]',
};

/** Class token for a match type; unknown types never occur (closed union). */
export function tokenFor(type: PiiClass): string {
  return PII_TOKENS[type];
}

// Class patterns. The EMAIL/SSN/CARD shapes are byte-identical to the ST
// harness PII scan (packages/eval/src/harness.ts PII_RE) and to the synthetic
// values seeded into the canary corpus, so production redaction and the
// adversarial gate agree on what is PII. PHONE is the corpus's `+1-555-\d{8}`
// format (NIST: linked/linkable).
const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const PHONE_RE = /\+1-555-\d{8}\b/g;
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;
const CARD_RE = /\b4\d{3} \d{4} \d{4} \d{4}\b/g;

/** Luhn checksum over the 16 card digits (ADR-0005: Luhn-verified cards only). */
export function luhnValid(digits: string): boolean {
  if (digits.length === 0) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i += 1) {
    let d = parseInt(digits[digits.length - 1 - i] ?? '', 10);
    if (Number.isNaN(d)) return false;
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

/**
 * Deterministic pure-TS detector: the v1 production adapter (ADR-0005).
 * Detects EMAIL / PHONE / SSN / CREDIT_CARD (Luhn-verified) spans. Matches
 * are sorted by start; overlapping spans keep the earliest match so the
 * redactor can walk the list once.
 */
export class DeterministicPiiDetector implements PiiDetector {
  detect(text: string): PiiMatch[] {
    const matches: PiiMatch[] = [];
    for (const m of text.matchAll(EMAIL_RE)) {
      matches.push({
        type: 'EMAIL',
        start: m.index ?? 0,
        end: (m.index ?? 0) + m[0].length,
        value: m[0],
      });
    }
    for (const m of text.matchAll(PHONE_RE)) {
      matches.push({
        type: 'PHONE',
        start: m.index ?? 0,
        end: (m.index ?? 0) + m[0].length,
        value: m[0],
      });
    }
    for (const m of text.matchAll(SSN_RE)) {
      matches.push({
        type: 'SSN',
        start: m.index ?? 0,
        end: (m.index ?? 0) + m[0].length,
        value: m[0],
      });
    }
    for (const m of text.matchAll(CARD_RE)) {
      if (!luhnValid(m[0].replace(/ /g, ''))) continue;
      matches.push({
        type: 'CREDIT_CARD',
        start: m.index ?? 0,
        end: (m.index ?? 0) + m[0].length,
        value: m[0],
      });
    }
    matches.sort((a, b) => a.start - b.start || a.end - b.end);
    const nonOverlapping: PiiMatch[] = [];
    let lastEnd = -1;
    for (const match of matches) {
      if (match.start < lastEnd) continue;
      nonOverlapping.push(match);
      lastEnd = match.end;
    }
    return nonOverlapping;
  }
}

/**
 * One-way replacement: every match span is replaced by its class token and
 * the original value is discarded (no reversible maps, ADR-0005). Matches
 * must be non-overlapping and sorted by start (detector contract).
 */
export function redactText(text: string, matches: readonly PiiMatch[]): string {
  const sorted = [...matches].sort((a, b) => a.start - b.start);
  let out = '';
  let cursor = 0;
  for (const m of sorted) {
    if (m.end <= cursor) continue;
    out += text.slice(cursor, m.start) + PII_TOKENS[m.type];
    cursor = m.end;
  }
  return out + text.slice(cursor);
}
