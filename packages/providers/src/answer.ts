/**
 * Answer-generation seam (T3 contract §providers/answer.ts).
 *
 * The generation provider is the ONLY source of answers in T3 and it is always
 * the deterministic SpyGenerator: the model never decides authorization, never
 * answers from memory, and may reference only the citations it was handed.
 * Real adapters land behind this same interface (deferred; the seam is the
 * contract).
 */

export interface ProviderCitation {
  documentId: string;
  versionId: string;
  chunkId: string;
  span: { start: number; end: number };
  excerpt: string;
}

/** Minimal authorized evidence a provider may consume (redacted text only). */
export interface ProviderBundleChunk {
  chunkId: string;
  text: string;
}

export interface GenerationRequest {
  question: string;
  bundle: ProviderBundleChunk[];
  citations: ProviderCitation[];
}

export interface GenerationResult {
  answer: string;
  citations: ProviderCitation[];
}

export interface AnswerGenerator {
  generate(request: GenerationRequest): Promise<GenerationResult>;
}

/** What the SpyGenerator records per payload, for test assertions. */
export interface SpyRecord {
  question: string;
  bundle: ProviderBundleChunk[];
  citations: ProviderCitation[];
}

/**
 * Deterministic, in-memory generator used by every T3 test. Every payload
 * (question, bundle chunk texts+ids, citations) is appended to the SHARED
 * records array passed in, so tests observe exactly what the pipeline sent to
 * the model. The answer is a fixed template referencing ONLY the citation ids
 * it was provided — it never fabricates or pulls from memory.
 */
export class SpyGenerator implements AnswerGenerator {
  constructor(readonly records: SpyRecord[] = []) {}

  async generate(request: GenerationRequest): Promise<GenerationResult> {
    this.records.push({
      question: request.question,
      bundle: request.bundle.map((chunk) => ({
        chunkId: chunk.chunkId,
        text: chunk.text,
      })),
      citations: request.citations,
    });
    const ids = request.citations.map((c) => c.chunkId).join(',');
    return {
      answer: `Synthesis of authorized evidence [${ids}]`,
      citations: request.citations,
    };
  }
}
