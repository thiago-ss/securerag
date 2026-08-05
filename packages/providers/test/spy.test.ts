import { describe, expect, it } from 'vitest';
import { SpyGenerator, type SpyRecord } from '../src/answer.js';

describe('SpyGenerator', () => {
  it('records every payload into the shared records array and cites only provided ids', async () => {
    const records: SpyRecord[] = [];
    const spy = new SpyGenerator(records);
    const citation = {
      documentId: 'doc-1',
      versionId: 'ver-1',
      chunkId: 'chunk-1',
      span: { start: 0, end: 21 },
      excerpt: 'Alpha secret formula one',
    };

    const first = await spy.generate({
      question: 'secret formula',
      bundle: [{ chunkId: 'chunk-1', text: 'Alpha secret formula one' }],
      citations: [citation],
    });
    const second = await spy.generate({
      question: 'other',
      bundle: [{ chunkId: 'chunk-2', text: 'unrelated' }],
      citations: [],
    });

    expect(records).toHaveLength(2);
    expect(records[0]).toEqual({
      question: 'secret formula',
      bundle: [{ chunkId: 'chunk-1', text: 'Alpha secret formula one' }],
      citations: [citation],
    });
    expect(records[1]?.bundle).toEqual([{ chunkId: 'chunk-2', text: 'unrelated' }]);
    expect(first.answer).toContain('chunk-1');
    expect(first.citations).toEqual([citation]);
    expect(second.answer).toContain('[]');
    expect(second.citations).toEqual([]);
  });

  it('is deterministic: same input yields the same output', async () => {
    const spy = new SpyGenerator();
    const request = {
      question: 'q',
      bundle: [{ chunkId: 'c1', text: 't1' }],
      citations: [
        {
          documentId: 'd',
          versionId: 'v',
          chunkId: 'c1',
          span: { start: 0, end: 2 },
          excerpt: 't1',
        },
      ],
    };
    const a = await spy.generate(request);
    const b = await spy.generate(request);
    expect(a.answer).toBe(b.answer);
  });
});
