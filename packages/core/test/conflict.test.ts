import { describe, expect, it } from 'vitest';
import { detectConflicts, hasConflicts, type ConflictIssue } from '../src/conflict.js';
import type { EvidenceChunk } from '../src/types.js';

function chunk(id: string, text: string, rank = 1): EvidenceChunk {
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
  };
}

describe('deterministic conflicting-evidence detector (S7, ADR-0009)', () => {
  it('numeric disagreement on the same entity across chunks -> CONFLICTING_EVIDENCE material', () => {
    const issues = detectConflicts([
      chunk('a', 'The response rate was 5% in the last survey.', 1),
      chunk('b', 'The response rate was 12% in the last survey.', 2),
    ]);
    expect(issues).toHaveLength(1);
    expect(issues[0]).toMatchObject({
      kind: 'numeric-disagreement',
      entity: 'response rate',
    });
    expect(hasConflicts([
      chunk('a', 'The response rate was 5% in the last survey.', 1),
      chunk('b', 'The response rate was 12% in the last survey.', 2),
    ])).toBe(true);
  });

  it('negation contradiction: one chunk negates, another asserts the same phrase', () => {
    const issues = detectConflicts([
      chunk('a', 'The policy does not allow refunds after 30 days.', 1),
      chunk('b', 'The policy allows refunds after 30 days.', 1),
    ]);
    expect(issues.some((i) => i.kind === 'negation-contradiction')).toBe(true);
    expect(issues[0]!.entity).toBe('refunds after 30 days');
  });

  it('numeric agreement (same value) is NOT a conflict', () => {
    expect(
      detectConflicts([
        chunk('a', 'The response rate was 5% in the last survey.', 1),
        chunk('b', 'The response rate was 5% in an earlier survey.', 2),
      ]),
    ).toEqual([]);
  });

  it('same number with different unit classes is NOT a conflict (5% vs 5 million)', () => {
    expect(
      detectConflicts([
        chunk('a', 'The budget reached 5 million dollars.', 1),
        chunk('b', 'The budget reached 5% of revenue.', 2),
      ]),
    ).toEqual([]);
  });

  it('different entities with different numbers are NOT conflicts', () => {
    expect(
      detectConflicts([
        chunk('a', 'The response rate was 5% and the market share was 12%.', 1),
        chunk('b', 'The headcount was 40 and the budget reached 60 million.', 2),
      ]),
    ).toEqual([]);
  });

  it('single-word entity with an assertion verb IS extracted ("headcount was 40")', () => {
    const issues = detectConflicts([
      chunk('a', 'The headcount was 40 in March.', 1),
      chunk('b', 'The headcount was 60 in March.', 2),
    ]);
    expect(issues).toHaveLength(1);
    expect(issues[0]).toMatchObject({ kind: 'numeric-disagreement', entity: 'headcount' });
  });

  it('single-word entities (figure/milestone/reference) are intentionally not extracted', () => {
    // Operational texts with 1-word labels + numbers must never trip the gate.
    expect(
      detectConflicts([
        chunk('a', 'Operational notes with reference xyz and figure 42 for the quarterly report.', 1),
        chunk('b', 'Operational notes with reference abc and figure 17 for the quarterly report.', 2),
        chunk('c', 'Project plan with milestone 42 and milestone 17 in Q3.', 3),
      ]),
    ).toEqual([]);
  });

  it('a single chunk (even with internal disagreement) is not a conflict', () => {
    expect(
      detectConflicts([chunk('a', 'The rate was 5% then the rate was 12%.', 1)]),
    ).toEqual([]);
  });

  it('empty and one-chunk bundles never conflict', () => {
    expect(detectConflicts([])).toEqual([]);
    expect(detectConflicts([chunk('a', 'The response rate was 5%.', 1)])).toEqual([]);
  });

  it('deterministic: same input -> same ordered issues; reversing bundle order swaps chunk order only', () => {
    const bundleA = [
      chunk('a', 'The response rate was 5% in the last survey.', 1),
      chunk('b', 'The response rate was 12% in the last survey.', 2),
    ];
    const first = detectConflicts(bundleA);
    const second = detectConflicts(bundleA);
    expect(first).toEqual(second);

    // Bundle order is retrieval order: pairwise (i<j); reversing the bundle
    // yields the same disagreement with the chunk roles swapped.
    const reversed = detectConflicts([...bundleA].reverse());
    expect(reversed).toHaveLength(first.length);
    if (first[0] !== undefined && reversed[0] !== undefined) {
      expect(reversed[0].kind).toBe(first[0].kind);
      expect(reversed[0].entity).toBe(first[0].entity);
      expect(reversed[0].chunkIds).toEqual([first[0].chunkIds[1], first[0].chunkIds[0]]);
    }

    const multiBundle = [
      chunk('a', 'The response rate was 5% and the headcount was 40.', 1),
      chunk('b', 'The response rate was 12% in the last survey.', 2),
      chunk('c', 'The headcount was 60.', 3),
    ];
    const multi = detectConflicts(multiBundle);
    // sorted deterministically by (entity, kind, chunkIds): headcount < response rate
    expect(multi.map((i: ConflictIssue) => i.entity)).toEqual(['headcount', 'response rate']);
    expect(multi.map((i: ConflictIssue) => i.kind)).toEqual([
      'numeric-disagreement',
      'numeric-disagreement',
    ]);
    expect(detectConflicts(multiBundle)).toEqual(multi);
  });
});
