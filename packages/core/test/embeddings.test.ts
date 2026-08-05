import { describe, expect, it } from 'vitest';
import {
  DeterministicHashEmbedding,
  EMBEDDING_DIM,
  toVectorLiteral,
} from '../src/embeddings.js';

describe('DeterministicHashEmbedding (CI/demo provider fake)', () => {
  it('returns fixed-dimension, L2-normalized vectors for every input', async () => {
    const provider = new DeterministicHashEmbedding();
    const vectors = await provider.embed(['quantum coherence', '', 'vault key rotation']);
    expect(vectors).toHaveLength(3);
    for (const vec of vectors) {
      expect(vec).toHaveLength(EMBEDDING_DIM);
      const norm = Math.sqrt(vec.reduce((sum, v) => sum + v * v, 0));
      expect(norm).toBeCloseTo(1, 10);
    }
  });

  it('is stable across instances, batches, and processes (pure hash, no randomness)', async () => {
    const a = new DeterministicHashEmbedding();
    const b = new DeterministicHashEmbedding();
    const first = await a.embed(['secret formula review']);
    const second = await b.embed(['secret formula review', 'unrelated']);
    expect(second[0]).toEqual(first[0]);
  });

  it('maps lexically overlapping texts closer than unrelated texts (cosine)', async () => {
    const provider = new DeterministicHashEmbedding();
    const [nearA, nearB, far] = await provider.embed([
      'quantum coherence entanglement',
      'entanglement coherence quantum',
      'shipping invoice ledger',
    ]);
    const cos = (x: number[], y: number[]) => x.reduce((s, v, i) => s + v * y[i]!, 0);
    expect(nearA).toBeDefined();
    expect(nearB).toBeDefined();
    expect(far).toBeDefined();
    expect(cos(nearA!, nearB!)).toBeGreaterThan(cos(nearA!, far!));
    expect(cos(nearA!, nearB!)).toBeGreaterThan(0.8);
  });

  it('embed() is order-preserving and parallel-safe to call', async () => {
    const provider = new DeterministicHashEmbedding();
    const [single] = await provider.embed(['alpha']);
    const batch = await provider.embed(['alpha', 'beta']);
    expect(batch[0]).toEqual(single);
  });

  it('toVectorLiteral formats a pgvector literal for $n::vector parameters', () => {
    expect(toVectorLiteral([0.5, -0.25])).toBe('[0.5,-0.25]');
  });
});
