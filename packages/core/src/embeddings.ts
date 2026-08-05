/**
 * Embedding provider seam (S6, ADR-0008): the vector arm of retrieval embeds
 * the question through this interface. Embeddings are DERIVED DATA: only
 * redacted derivatives may ever reach a provider payload (CONTEXT.md) — the
 * question redaction step lands in S4 and plugs in before embed().
 *
 * The seam contract, and the OpenAI-compatible adapter contract, are documented
 * in packages/core/README.md (section "Embedding provider"). The real OpenAI
 * adapter is out of scope for v1 CI; DeterministicHashEmbedding is the CI/demo
 * fake: stable pseudo-vectors from the text hash, so every test and demo run
 * is reproducible without network access.
 */

/** Fixed dimension of the chunks.embedding column (vector(384), migration 0002). */
export const EMBEDDING_DIM = 384;

export interface EmbeddingProvider {
  /** Embed a batch of texts; returns one L2-normalized vector per input. */
  embed(texts: string[]): Promise<number[][]>;
}

/** Format an embedding as a pgvector literal text ('[...]') for a $n::vector parameter. */
export function toVectorLiteral(values: readonly number[]): string {
  return `[${values.join(',')}]`;
}

/** djb2-style stable string hash (pure JS, no platform drift). */
function hashString(input: string): number {
  let h = 5381;
  for (let i = 0; i < input.length; i += 1) {
    h = ((h << 5) + h + input.charCodeAt(i)) | 0;
  }
  return h >>> 0;
}

/**
 * Deterministic, hash-based embedding fake for CI/demo (never for production
 * retrieval quality). Tokenizes on non-alphanumeric characters, folds case,
 * and spreads each token across `dimsPerToken` dimensions with deterministic
 * signs and magnitudes (LCG-mixed sub-hashes). The output is dense-ish and
 * L2-normalized — deliberately shaped like a real dense embedding model
 * (multi-qa-MiniLM class), because HNSW cosine graphs need dense enough
 * vectors to navigate; ultra-sparse hashing produced degenerate graphs in the
 * recall baseline (measured during S6). Lexically overlapping texts produce
 * similar (not identical) vectors; `<=>` cosine is the distance contract.
 * Stable across processes and runs (no Math.random, no platform-dependent
 * hash), so fixtures seeded with one instance are comparable to queries
 * embedded by another.
 */
export class DeterministicHashEmbedding implements EmbeddingProvider {
  constructor(
    readonly dim: number = EMBEDDING_DIM,
    private readonly dimsPerToken = 16,
  ) {}

  async embed(texts: string[]): Promise<number[][]> {
    return texts.map((text) => this.embedOne(text));
  }

  embedOne(text: string): number[] {
    const vec = new Array<number>(this.dim).fill(0);
    const tokens = text.toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length > 0);
    // Never return a zero vector (zero vectors are not indexed and break
    // cosine distance): an empty text embeds to a fixed deterministic token.
    if (tokens.length === 0) tokens.push('');
    for (const token of tokens) {
      let h = hashString(token);
      for (let i = 0; i < this.dimsPerToken; i += 1) {
        h = (Math.imul(h, 1103515245) + 12345) | 0;
        const dimIdx = (h >>> 1) % this.dim;
        const sign = ((h >>> 8) & 1) === 0 ? 1 : -1;
        const magnitude = 0.2 + ((h >>> 16) % 800) / 1000;
        vec[dimIdx] = (vec[dimIdx] ?? 0) + sign * magnitude;
      }
    }
    let norm = 0;
    for (const v of vec) norm += v * v;
    const inv = 1 / Math.sqrt(norm);
    return vec.map((v) => v * inv);
  }
}

/** Shared CI instance; the retrieval pipeline uses it when no provider is injected. */
export const DETERMINISTIC_EMBEDDING: EmbeddingProvider = new DeterministicHashEmbedding();
