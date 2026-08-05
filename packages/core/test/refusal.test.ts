import { describe, expect, it } from 'vitest';
import { decide, EVIDENCE_MIN_CHUNKS } from '../src/refusal.js';
import type { EvidenceChunk } from '../src/types.js';

function chunk(id: string, text = 'authorized evidence text'): EvidenceChunk {
  return {
    chunkId: id,
    chunkNo: 1,
    text,
    spanStart: 0,
    spanEnd: text.length,
    versionId: 'v',
    versionNo: 1,
    documentId: 'd',
    title: 't',
    rank: 1,
  };
}

describe('decide (evidence gate, ADR-0009)', () => {
  it('answers when the bundle meets the calibrated threshold', () => {
    expect(decide([chunk('a'), chunk('b')], 'question')).toBe('answered');
    expect(decide([chunk('a'), chunk('b'), chunk('c')], 'question')).toBe('answered');
  });

  it('refuses an empty bundle (no authorized evidence)', () => {
    expect(decide([], 'question')).toBe('INSUFFICIENT_EVIDENCE');
  });

  it('refuses a bundle below the threshold even when all chunks are authorized', () => {
    expect(decide([chunk('a')], 'question')).toBe('INSUFFICIENT_EVIDENCE');
  });

  it('refuses an empty or whitespace question regardless of bundle', () => {
    expect(decide([chunk('a'), chunk('b')], '')).toBe('INSUFFICIENT_EVIDENCE');
    expect(decide([chunk('a'), chunk('b')], '   ')).toBe('INSUFFICIENT_EVIDENCE');
  });

  it('documents the calibrated threshold constant', () => {
    expect(EVIDENCE_MIN_CHUNKS).toBe(2);
  });
});
