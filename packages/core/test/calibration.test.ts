import { describe, expect, it } from 'vitest';
import { CALIBRATION_FIXTURES } from '../../eval/test/calibration-fixtures.js';
import {
  CALIBRATED_THRESHOLD,
  DEFAULT_WEIGHTS,
  DEFAULT_WEIGHTS_GRID,
  calibrateThreshold,
  coverageScore,
  decideCalibrated,
  rankScores,
  scoreEvidence,
  tokenize,
} from '../src/calibration.js';
import { decide } from '../src/refusal.js';
import type { EvidenceChunk } from '../src/types.js';

function chunk(
  id: string,
  text = 'authorized evidence text',
  rank = 1,
  overrides: Partial<EvidenceChunk> = {},
): EvidenceChunk {
  return {
    chunkId: id,
    chunkNo: 1,
    text,
    spanStart: 0,
    spanEnd: text.length,
    versionId: `version-${id}`,
    versionNo: 1,
    documentId: `document-${id}`,
    title: `Title ${id}`,
    rank,
    ...overrides,
  };
}

describe('calibrated answerability gate (S7, ADR-0009)', () => {
  it('calibration procedure (deterministic grid search over the fixed labeled set) reproduces the committed constants', () => {
    const result = calibrateThreshold(CALIBRATION_FIXTURES, DEFAULT_WEIGHTS_GRID);
    expect(result).not.toBeNull();
    if (result === null) return;
    expect(result.weights).toEqual(DEFAULT_WEIGHTS);
    expect(result.threshold).toBeCloseTo(CALIBRATED_THRESHOLD, 9);
    expect(result.margin).toBeGreaterThan(0);
    expect(result.answerableRecall).toBeGreaterThanOrEqual(0.95);
    expect(result.refusalRecall).toBe(1);
  });

  it('answerability recall >= 95% and refusal recall 100% on the labeled set (committed constants)', () => {
    const answerable = CALIBRATION_FIXTURES.filter((f) => f.label === 'answerable');
    const refused = CALIBRATION_FIXTURES.filter((f) => f.label !== 'answerable');
    let answered = 0;
    for (const fixture of answerable) {
      if (decideCalibrated(fixture.bundle, fixture.question) === 'answered') answered += 1;
    }
    let refusedOk = 0;
    for (const fixture of refused) {
      if (decideCalibrated(fixture.bundle, fixture.question) === 'INSUFFICIENT_EVIDENCE') {
        refusedOk += 1;
      }
    }
    expect(answered / answerable.length).toBeGreaterThanOrEqual(0.95);
    expect(refusedOk / refused.length).toBe(1);
    expect(answered).toBe(answerable.length);
  });

  it('labeled set is cleanly separable: min answerable score > max unanswerable score (count >= 2)', () => {
    const answerableScores = CALIBRATION_FIXTURES.filter((f) => f.label === 'answerable').map(
      (f) => scoreEvidence(f.bundle, f.question).score,
    );
    const unanswerableScores = CALIBRATION_FIXTURES.filter(
      (f) => f.label === 'unanswerable' && f.bundle.length >= 2,
    ).map((f) => scoreEvidence(f.bundle, f.question).score);
    expect(Math.min(...answerableScores)).toBeGreaterThan(Math.max(...unanswerableScores));
  });

  it('score < threshold refuses; score >= threshold answers (given the count floor)', () => {
    // The strongest unanswerable fixture (max unanswerable score) refuses.
    const unanswerable = CALIBRATION_FIXTURES.find((f) => f.id === 'retrieved-unrelated');
    expect(unanswerable).toBeDefined();
    if (unanswerable !== undefined) {
      const scored = scoreEvidence(unanswerable.bundle, unanswerable.question);
      expect(scored.score).toBeLessThan(CALIBRATED_THRESHOLD);
      expect(decideCalibrated(unanswerable.bundle, unanswerable.question)).toBe('INSUFFICIENT_EVIDENCE');
    }

    // The weakest answerable fixture (min answerable score) answers.
    const weakest = CALIBRATION_FIXTURES.find((f) => f.id === 'low-rank-partial');
    expect(weakest).toBeDefined();
    if (weakest !== undefined) {
      const scored = scoreEvidence(weakest.bundle, weakest.question);
      expect(scored.score).toBeGreaterThanOrEqual(CALIBRATED_THRESHOLD);
      expect(decideCalibrated(weakest.bundle, weakest.question)).toBe('answered');
    }

    // An at-threshold bundle answers (>= semantics).
    const at = chunk('at', 'revenue growth data', 1);
    const atScore = scoreEvidence([at, { ...at, chunkId: 'at2', rank: 1 }], 'revenue growth data');
    expect(decideCalibrated([at, { ...at, chunkId: 'at2', rank: 1 }], 'revenue growth data')).toBe('answered');
    expect(atScore.score).toBeGreaterThanOrEqual(CALIBRATED_THRESHOLD);
  });

  it('decide() compat contract stays green: the calibrated gate answers the same answerable cases', () => {
    // The T3 unit-test shapes (2+ chunks, rank 1) must remain answered.
    expect(decide([chunk('a', 'authorized evidence text', 1), chunk('b', 'authorized evidence text', 1)], 'question')).toBe('answered');
    expect(decideCalibrated([chunk('a', 'authorized evidence text', 1), chunk('b', 'authorized evidence text', 1)], 'question')).toBe('answered');
    expect(decideCalibrated([chunk('a'), chunk('b'), chunk('c')], 'question')).toBe('answered');
    // ... and the refusal floors are unchanged.
    expect(decideCalibrated([], 'question')).toBe('INSUFFICIENT_EVIDENCE');
    expect(decideCalibrated([chunk('a', 'authorized evidence text', 1)], 'question')).toBe('INSUFFICIENT_EVIDENCE');
    expect(decideCalibrated([chunk('a'), chunk('b')], '   ')).toBe('INSUFFICIENT_EVIDENCE');
  });

  it('deterministic: identical inputs produce identical scores, bundle order does not matter', () => {
    const bundle = [
      chunk('a', 'revenue grew this quarter', 2),
      chunk('b', 'growth outlook remains strong', 3),
    ];
    const first = scoreEvidence(bundle, 'annual revenue growth');
    const second = scoreEvidence(bundle, 'annual revenue growth');
    expect(first).toEqual(second);

    const shuffled = scoreEvidence([...bundle].reverse(), 'annual revenue growth');
    expect(shuffled.score).toBe(first.score);
    expect(shuffled.rankScore).toBe(first.rankScore);
    expect(shuffled.coverageScore).toBe(first.coverageScore);

    expect(rankScores(bundle)).toEqual([1 / 3, 1 / 4]);
    expect(decideCalibrated(bundle, 'annual revenue growth')).toBe('answered');
  });

  it('coverage is token-overlap of the stopword-stripped query against the bundle text union', () => {
    expect(tokenize('Annual revenue growth')).toEqual(['annual', 'revenue', 'growth']);
    expect(tokenize('the growth of revenue')).toEqual(['growth', 'revenue']);
    expect(coverageScore('annual revenue growth', [chunk('a', 'revenue grew', 1), chunk('b', 'growth outlook', 1)])).toBeCloseTo(2 / 3, 9);
    expect(coverageScore('annual revenue growth', [chunk('a', 'team sync notes', 1)])).toBe(0);
    expect(coverageScore('', [chunk('a', 'revenue grew', 1)])).toBe(0);
  });

  it('rank term is the saturating 1/(1+rank) transform, higher ranks score higher', () => {
    expect(rankScores([chunk('a', 'x', 1)])).toEqual([0.5]);
    expect(rankScores([chunk('a', 'x', 5)])).toEqual([1 / 6]);
    expect(rankScores([chunk('a', 'x', -1)])).toEqual([1]);
  });
});
