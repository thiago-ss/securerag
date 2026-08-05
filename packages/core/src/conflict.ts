import type { EvidenceChunk } from './types.js';

/**
 * Deterministic conflicting-evidence detector (ADR-0009, S7).
 *
 * v1 heuristics — deliberately small, deterministic, and documented:
 *
 *  1. numeric-disagreement — two chunks state a VALUE for the SAME entity and
 *     the values differ. Entity = 2-4 non-stopword words immediately before
 *     an assertion verb (is|are|was|were|reached|stood at|equals|of|at) and a
 *     numeric value with an optional unit. Values are only compared when they
 *     share a unit CLASS (percent vs scale vs currency ...) — "5%" vs "10%"
 *     conflicts, "5%" vs "5 million" does not (different unit classes).
 *
 *  2. negation-contradiction — one chunk negates a phrase (is not, no, never,
 *     without, has no, ...) while another chunk asserts the same phrase
 *     positively (no negation marker in the preceding context).
 *
 * Documented limits (v1):
 *  - English only; entity extraction is regex-based, no semantics — a
 *    "contradiction" is a lexical/numeric disagreement, never a paraphrase
 *    understanding (paraphrase conflicts are the calibrated model's job).
 *  - Numbers are compared raw (after comma stripping); "1.5%" vs "1.50%"
 *    parse equal and do NOT conflict; no tolerance band.
 *  - Within-chunk disagreements are ignored (contradictions are between
 *    different evidence chunks).
 *  - Single-word entities ("figure 42", "milestone 42") are intentionally not
 *    extracted to avoid generic-label false positives on operational texts.
 *
 * Determinism: chunks are compared in bundle order (i < j), extraction order
 * is document order, and the returned list is sorted by
 * (entity, kind, chunkIds) — identical input always yields identical output.
 */

export type ConflictKind = 'numeric-disagreement' | 'negation-contradiction';

export interface ConflictIssue {
  kind: ConflictKind;
  /** Normalized entity (numeric) or negated phrase (negation). */
  entity: string;
  /** The two disagreeing chunks, in bundle order. */
  chunkIds: [string, string];
  /** Deterministic human-readable detail (non-PII derivatives only). */
  detail: string;
}

/** Words that never form an entity phrase (deterministic, English, v1). */
const ENTITY_STOPWORDS: ReadonlySet<string> = new Set([
  'a', 'an', 'the', 'of', 'in', 'on', 'for', 'and', 'or', 'to', 'with', 'at',
  'by', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'not', 'no', 'from',
  'as', 'into', 'that', 'this', 'these', 'those', 'it', 'its', 'all', 'any',
  'each', 'every', 'more', 'most', 'other', 'some', 'such', 'than', 'then',
  'there', 'here', 'we', 'you', 'they', 'he', 'she', 'do', 'does', 'did',
]);

interface NumericFact {
  entity: string;
  value: number;
  unitClass: string;
  rawValue: string;
}

const ENTITY_WORD = "[a-z][a-z0-9'-]*";
const VALUE = String.raw`\d[\d,]{0,12}(?:\.\d+)?`;
const UNIT = String.raw`(?:%|percent|pp|bps|million|billion|thousand|k|m|usd|dollars|points|units|degrees|gb|tb|mb|hz|ghz|years|months|days|ms|seconds|minutes|hours)`;

const NUMERIC_FACT_RE = new RegExp(
  String.raw`\b((?:${ENTITY_WORD}\s+){0,3}${ENTITY_WORD})\s+(is|are|was|were|reached|stood at|equals|of|at)\s+(${VALUE})\s*(${UNIT})?\b`,
  'gi',
);

/** Negation phrases may contain numbers ("refunds after 30 days"). */
const PHRASE_WORD = "[a-z0-9][a-z0-9'-]*";

const NEGATION_RE = new RegExp(
  String.raw`\b(?:is not|are not|was not|were not|isn't|aren't|wasn't|weren't|does not|do not|did not|has no|have no|never|no longer|without|no)\s+(?:(?:allow|allows|permit|permits|support|supports|include|includes|provide|provides|grant|grants|offer|offers|accept|accepts|require|requires|state|states|say|says|report|reports|show|shows|indicate|indicates|give|gives|make|makes|take|takes|have|holds?|apply|applies|cover|covers|extend|extends|consider|considers|exist|exists)\w*\s+)?((?:${PHRASE_WORD}\s+){0,3}${PHRASE_WORD})`,
  'gi',
);

/** Negation marker within the 40 chars before a phrase = negative context. */
const NEG_CONTEXT_RE =
  /\b(?:is not|are not|was not|were not|isn't|aren't|wasn't|weren't|does not|do not|did not|has no|have no|never|no longer|without|no|not|nor|neither)\b/i;

function unitClassOf(unit: string): string {
  switch (unit) {
    case '%': case 'percent': case 'pp': case 'bps': return 'percent';
    case 'million': case 'billion': case 'thousand': case 'k': case 'm': return 'scale';
    case 'usd': case 'dollars': return 'currency';
    case 'gb': case 'tb': case 'mb': return 'bytes';
    case 'hz': case 'ghz': return 'frequency';
    case 'degrees': return 'degrees';
    case 'years': case 'months': case 'days': case 'hours': case 'minutes': case 'seconds': case 'ms': return 'time';
    default: return 'count';
  }
}

function extractNumericFacts(text: string): NumericFact[] {
  const facts: NumericFact[] = [];
  for (const match of text.matchAll(NUMERIC_FACT_RE)) {
    const connector = (match[2] ?? '').toLowerCase();
    const entityWords = (match[1] ?? '')
      .toLowerCase()
      .split(/\s+/)
      .filter((word) => !ENTITY_STOPWORDS.has(word));
    const entity = entityWords.join(' ');
    // A bare noun + number ("figure 42", "milestone 42") is only extracted
    // through an explicit assertion: verb connectors accept a single-word
    // entity ("headcount was 40"); the looser of/at connectors require 2+
    // content words ("rate of 5%") to keep generic labels out.
    if (connector === 'of' || connector === 'at') {
      if (entityWords.length < 2) continue;
    } else if (entityWords.length < 1) {
      continue;
    }
    if (entity.length > 60) continue;
    const value = Number((match[3] ?? '').replace(/,/g, ''));
    if (!Number.isFinite(value)) continue;
    const unit = (match[4] ?? '').toLowerCase();
    facts.push({
      entity,
      value,
      unitClass: unitClassOf(unit),
      rawValue: `${match[3]}${unit.length > 0 ? ` ${unit}` : ''}`,
    });
  }
  return facts;
}

function extractNegationPhrases(text: string): string[] {
  const phrases: string[] = [];
  for (const match of text.matchAll(NEGATION_RE)) {
    const phrase = (match[1] ?? '').toLowerCase().trim();
    if (phrase.length > 0 && phrase.length <= 80) phrases.push(phrase);
  }
  return phrases;
}

/** True when `phrase` appears in `text` without a negation marker nearby. */
function hasPositiveAssertion(text: string, phrase: string): boolean {
  const lower = text.toLowerCase();
  let from = 0;
  for (;;) {
    const at = lower.indexOf(phrase, from);
    if (at === -1) return false;
    const before = lower.slice(Math.max(0, at - 40), at);
    if (!NEG_CONTEXT_RE.test(before)) return true;
    from = at + phrase.length;
  }
}

export function detectConflicts(bundle: readonly EvidenceChunk[]): ConflictIssue[] {
  const issues: ConflictIssue[] = [];
  for (let i = 0; i < bundle.length; i += 1) {
    for (let j = i + 1; j < bundle.length; j += 1) {
      const a = bundle[i]!;
      const b = bundle[j]!;

      const factsA = extractNumericFacts(a.text);
      const factsB = extractNumericFacts(b.text);
      for (const fa of factsA) {
        for (const fb of factsB) {
          if (fa.entity !== fb.entity) continue;
          if (fa.unitClass !== fb.unitClass) continue;
          if (fa.value === fb.value) continue;
          issues.push({
            kind: 'numeric-disagreement',
            entity: fa.entity,
            chunkIds: [a.chunkId, b.chunkId],
            detail: `${fa.entity}: '${fa.rawValue}' in chunk ${a.chunkId} vs '${fb.rawValue}' in chunk ${b.chunkId}`,
          });
        }
      }

      for (const phrase of extractNegationPhrases(a.text)) {
        if (hasPositiveAssertion(b.text, phrase)) {
          issues.push({
            kind: 'negation-contradiction',
            entity: phrase,
            chunkIds: [a.chunkId, b.chunkId],
            detail: `'${phrase}' negated in chunk ${a.chunkId} but asserted in chunk ${b.chunkId}`,
          });
        }
      }
      for (const phrase of extractNegationPhrases(b.text)) {
        if (hasPositiveAssertion(a.text, phrase)) {
          issues.push({
            kind: 'negation-contradiction',
            entity: phrase,
            chunkIds: [a.chunkId, b.chunkId],
            detail: `'${phrase}' negated in chunk ${b.chunkId} but asserted in chunk ${a.chunkId}`,
          });
        }
      }
    }
  }
  return issues.sort(
    (x, y) =>
      x.entity.localeCompare(y.entity) ||
      x.kind.localeCompare(y.kind) ||
      x.chunkIds[0]!.localeCompare(y.chunkIds[0]!) ||
      x.chunkIds[1]!.localeCompare(y.chunkIds[1]!),
  );
}

export function hasConflicts(bundle: readonly EvidenceChunk[]): boolean {
  return detectConflicts(bundle).length > 0;
}
