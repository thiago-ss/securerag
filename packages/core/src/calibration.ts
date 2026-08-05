import { decide } from './refusal.js';
import type { EvidenceChunk } from './types.js';

/**
 * Calibrated answerability gate (ADR-0009, S7).
 *
 * The raw count heuristic (EVIDENCE_MIN_CHUNKS) is replaced by a composite
 * score over the post-authorization evidence bundle, calibrated on a LABELED
 * fixture set (eval/test/calibration-fixtures.ts). The gate is fully
 * deterministic: no randomness anywhere — the fixture set is fixed constants
 * (stronger than a seeded generator), the scoring is pure, and the threshold
 * calibration is an exhaustive deterministic grid search.
 *
 * Score components (each in [0, 1]):
 *  - countScore:    authorized chunk count, saturating at the hard floor of 2
 *                   (a single authorized chunk is refused by decide()).
 *  - rankScore:     mean of 1/(1 + rank) over the bundle — a saturating
 *                   transform of the ABSOLUTE rank value. Higher ranks
 *                   (hybrid-arm RRF fused scores, keyword ts_rank_cd) yield
 *                   higher scores; the transform is flat near the top of
 *                   either scale, so it is tolerant of the scale difference.
 *                   The vector arm's distance ranks are a test seam only and
 *                   are NOT calibrated (documented in ADR-0008).
 *  - coverageScore: token-overlap of the query's (stopword-stripped) tokens
 *                   against the union of bundle chunk texts — the
 *                   query-entity coverage term.
 *  - citationScore: fraction of chunks carrying a complete, citable reference
 *                   (chunk/version/document ids + a non-empty span).
 *
 * score = wC*count + wR*rank + wV*coverage + wT*citation.
 *
 * The threshold and weights are the deterministic output of the calibration
 * procedure (calibrateThreshold) run over the labeled fixtures; the committed
 * constants below MUST equal the search result for the committed grid
 * (enforced by core/test/calibration.test.ts).
 */

export interface EvidenceWeights {
  count: number;
  rank: number;
  coverage: number;
  citation: number;
}

export interface EvidenceScore {
  countScore: number;
  rankScore: number;
  coverageScore: number;
  citationScore: number;
  score: number;
}

/** Committed weights — the calibration search optimum (see calibration.test.ts). */
export const DEFAULT_WEIGHTS: EvidenceWeights = { count: 1, rank: 5, coverage: 2, citation: 0.5 };

/**
 * Committed threshold: score >= CALIBRATED_THRESHOLD is answerable (given the
 * decide() hard floor). Produced by calibrateThreshold over the labeled set
 * (min answerable 3.9583 vs max unanswerable 2.9583; threshold midpoint).
 */
export const CALIBRATED_THRESHOLD = 3.458333333333333;

/** Deterministic stopword list for the coverage term (English, v1). */
export const COVERAGE_STOPWORDS: ReadonlySet<string> = new Set([
  'a', 'an', 'the', 'of', 'in', 'on', 'for', 'and', 'or', 'to', 'with', 'at',
  'by', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'what', 'which',
  'how', 'when', 'where', 'who', 'whom', 'whose', 'do', 'does', 'did', 'from',
  'as', 'into', 'that', 'this', 'these', 'those', 'its', 'it', 'we', 'you',
  'they', 'he', 'she', 'not', 'no', 'any', 'all', 'each', 'every', 'more',
  'most', 'other', 'some', 'such', 'than', 'then', 'them', 'there', 'here',
]);

export function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9]+/i)
    .filter((t) => t.length > 0 && !COVERAGE_STOPWORDS.has(t));
}

/**
 * Saturating absolute-rank scores: 1/(1 + rank) per chunk. Absolute rank is
 * the RRF fused score on the hybrid arm (production) and ts_rank_cd on the
 * keyword arm; both are higher-is-better, and 1/(1+x) compresses both scales
 * into [~0.3, 1.0] with the top of either scale nearly flat. Deterministic
 * and bundle-order independent.
 */
export function rankScores(bundle: readonly EvidenceChunk[]): number[] {
  return bundle.map((chunk) => 1 / (1 + Math.max(chunk.rank, 0)));
}

export function coverageScore(question: string, bundle: readonly EvidenceChunk[]): number {
  const queryTokens = tokenize(question);
  if (queryTokens.length === 0) return 0;
  const bundleTokens = new Set<string>();
  for (const chunk of bundle) {
    for (const token of tokenize(chunk.text)) bundleTokens.add(token);
  }
  let covered = 0;
  for (const token of queryTokens) {
    if (bundleTokens.has(token)) covered += 1;
  }
  return covered / queryTokens.length;
}

export function citationScore(bundle: readonly EvidenceChunk[]): number {
  if (bundle.length === 0) return 0;
  let citable = 0;
  for (const chunk of bundle) {
    if (
      chunk.chunkId.length > 0 &&
      chunk.documentId.length > 0 &&
      chunk.versionId.length > 0 &&
      chunk.spanStart < chunk.spanEnd
    ) {
      citable += 1;
    }
  }
  return citable / bundle.length;
}

export function scoreEvidence(
  bundle: readonly EvidenceChunk[],
  question: string,
  weights: EvidenceWeights = DEFAULT_WEIGHTS,
): EvidenceScore {
  const count = Math.min(bundle.length, 2) / 2;
  const rank = rankScores(bundle).reduce((sum, value) => sum + value, 0) / Math.max(bundle.length, 1);
  const coverage = coverageScore(question, bundle);
  const citation = citationScore(bundle);
  return {
    countScore: count,
    rankScore: rank,
    coverageScore: coverage,
    citationScore: citation,
    score: weights.count * count + weights.rank * rank + weights.coverage * coverage + weights.citation * citation,
  };
}

/**
 * Deterministic calibrated gate. Wraps decide() (the count/empty-question
 * hard floor stays — a single authorized chunk is always refused) and then
 * applies the calibrated threshold. score < threshold OR bundle empty ->
 * INSUFFICIENT_EVIDENCE. Existing decide() callers keep their behavior.
 */
export function decideCalibrated(
  bundle: readonly EvidenceChunk[],
  question: string,
  threshold: number = CALIBRATED_THRESHOLD,
  weights: EvidenceWeights = DEFAULT_WEIGHTS,
): 'answered' | 'INSUFFICIENT_EVIDENCE' {
  if (decide(bundle, question) === 'INSUFFICIENT_EVIDENCE') return 'INSUFFICIENT_EVIDENCE';
  return scoreEvidence(bundle, question, weights).score >= threshold ? 'answered' : 'INSUFFICIENT_EVIDENCE';
}

/** A labeled calibration fixture (see eval/test/calibration-fixtures.ts). */
export interface CalibrationFixture {
  id: string;
  label: 'answerable' | 'unanswerable' | 'foreign-only';
  question: string;
  bundle: readonly EvidenceChunk[];
  note: string;
}

export interface CalibrationResult {
  weights: EvidenceWeights;
  threshold: number;
  /** min(answerable scores) - max(unanswerable >= 2 chunk scores); > 0 separates. */
  margin: number;
  answerableRecall: number;
  refusalRecall: number;
}

/**
 * Deterministic calibration procedure (ADR-0009): exhaustive grid search over
 * a fixed weight grid; for every weight vector that SEPARATES the labeled set
 * (every answerable fixture scores above every count >= 2 unanswerable
 * fixture), evaluate the full gate (decide() floor + threshold) and keep the
 * best by margin (tie: first in grid order). Count < 2 and foreign-only
 * fixtures are refused by decide() itself, so they need no score separation.
 */
export function calibrateThreshold(
  fixtures: readonly CalibrationFixture[],
  grid: readonly EvidenceWeights[] = DEFAULT_WEIGHTS_GRID,
): CalibrationResult | null {
  const answerable = fixtures.filter((f) => f.label === 'answerable');
  const unanswerable = fixtures.filter((f) => f.label === 'unanswerable');
  const foreignOnly = fixtures.filter((f) => f.label === 'foreign-only');
  if (answerable.length === 0) return null;

  let best: CalibrationResult | null = null;
  for (const weights of grid) {
    const answerableScores = answerable.map((f) => scoreEvidence(f.bundle, f.question, weights).score);
    const minAnswerable = Math.min(...answerableScores);
    const unanswerableAboveFloor = unanswerable.filter((f) => f.bundle.length >= 2);
    const maxUnanswerable =
      unanswerableAboveFloor.length === 0
        ? Number.NEGATIVE_INFINITY
        : Math.max(...unanswerableAboveFloor.map((f) => scoreEvidence(f.bundle, f.question, weights).score));
    if (!(minAnswerable > maxUnanswerable)) continue;

    const threshold = (minAnswerable + maxUnanswerable) / 2;
    let answerableRecall = 0;
    let refusalRecall = 0;
    for (const f of answerable) {
      if (decideCalibrated(f.bundle, f.question, threshold, weights) === 'answered') answerableRecall += 1;
    }
    for (const f of [...unanswerable, ...foreignOnly]) {
      if (decideCalibrated(f.bundle, f.question, threshold, weights) === 'INSUFFICIENT_EVIDENCE') refusalRecall += 1;
    }
    answerableRecall /= answerable.length;
    refusalRecall /= [...unanswerable, ...foreignOnly].length;

    const result: CalibrationResult = {
      weights,
      threshold,
      margin: minAnswerable - maxUnanswerable,
      answerableRecall,
      refusalRecall,
    };
    if (best === null || result.margin > best.margin) best = result;
  }
  return best;
}

/** Fixed calibration grid (deterministic order; keep small — it is exhaustive). */
export const DEFAULT_WEIGHTS_GRID: readonly EvidenceWeights[] = (() => {
  const grid: EvidenceWeights[] = [];
  for (const count of [1, 2, 3]) {
    for (const rank of [1, 2, 3, 4, 5]) {
      for (const coverage of [1, 2, 3, 4]) {
        for (const citation of [0.5, 1, 2]) {
          grid.push({ count, rank, coverage, citation });
        }
      }
    }
  }
  return grid;
})();
