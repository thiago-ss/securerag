import type { AnswerGenerator, GenerationRequest, GenerationResult } from '@securerag/providers';

/**
 * Answer-generation contract hardening (ADR-0009, S7):
 *
 * - The model has NO tools: the generation request carries ONLY
 *   {question, bundle (redacted), citations} (the GenerationRequest type IS
 *   that shape — nothing else can reach the provider seam).
 * - Bounded regeneration: at most MAX_GENERATION_ATTEMPTS generate+verify
 *   cycles. If verification fails after generation, generate once more; if it
 *   still fails, refuse with CITATION_UNSUPPORTED. Deterministic: the retry
 *   loop is a simple bounded loop, no randomness.
 * - The verifier is INJECTED so the pipeline can chain the pure deterministic
 *   verifier (verifier.ts) with the DB-backed citation-resolution recheck —
 *   the verifier never depends on the generating model.
 */

export const MAX_GENERATION_ATTEMPTS = 2;

export type VerifyOutcome = { ok: true } | { ok: false; issues: string[] };

export interface GenerationGuaranteeDeps {
  providers: AnswerGenerator;
  verify: (result: GenerationResult) => Promise<VerifyOutcome>;
}

export type GenerationGuaranteeOutcome =
  | { decision: 'answered'; result: GenerationResult; attempts: number }
  | { decision: 'refused'; code: 'CITATION_UNSUPPORTED'; issues: string[]; attempts: number };

export async function generateWithGuarantee(
  deps: GenerationGuaranteeDeps,
  request: GenerationRequest,
): Promise<GenerationGuaranteeOutcome> {
  let lastVerify: VerifyOutcome = { ok: false, issues: [] };
  for (let attempt = 1; attempt <= MAX_GENERATION_ATTEMPTS; attempt += 1) {
    const result = await deps.providers.generate(request);
    lastVerify = await deps.verify(result);
    if (lastVerify.ok) return { decision: 'answered', result, attempts: attempt };
    if (attempt === MAX_GENERATION_ATTEMPTS) {
      return { decision: 'refused', code: 'CITATION_UNSUPPORTED', issues: lastVerify.issues, attempts: attempt };
    }
  }
  // Unreachable: the loop is bounded by MAX_GENERATION_ATTEMPTS.
  throw new Error(`unreachable: generation bounded at ${MAX_GENERATION_ATTEMPTS}`);
}
