/**
 * Labeled answerability fixtures (S7, ADR-0009) — the calibration set for the
 * calibrated evidence gate (packages/core/src/calibration.ts).
 *
 * Design rules:
 *  - FIXED CONSTANTS, no RNG: the gate must be deterministic, so the labeled
 *    set is hand-curated rather than seeded-generated (a fixed seed is only
 *    needed when generating; constants are stronger). The calibration
 *    procedure in core/test/calibration.test.ts runs an exhaustive grid
 *    search over this set and MUST reproduce the committed threshold.
 *  - The bundle contains ONLY post-authorization chunks (RLS-filtered rows);
 *    'foreign-only' therefore manifests as an EMPTY bundle — foreign/revoked/
 *    expired rows never reach the gate (CONTEXT.md invariant). The fixture
 *    labels make the modeling explicit.
 *  - The compat contract case `compat-basic` (2 chunks, rank 1, zero query
 *    overlap — the shape of the original EVIDENCE_MIN_CHUNKS = 2 unit test)
 *    is IN the answerable set: the calibrated gate must keep answering it.
 *  - Boundary rationale is documented per fixture; the operational line is:
 *    coverage + rank separate answerable from unanswerable bundles of count
 *    >= 2; count < 2 and empty bundles are refused by the decide() floor.
 *
 * This file is intentionally import-free (structural FixtureChunk shape,
 * identical to core's EvidenceChunk) so packages/core tests can consume it
 * without pulling an @securerag/eval dependency into core's typecheck graph.
 */

export interface FixtureChunk {
  chunkId: string;
  chunkNo: number;
  text: string;
  spanStart: number;
  spanEnd: number;
  versionId: string;
  versionNo: number;
  documentId: string;
  title: string;
  rank: number;
}

export type FixtureLabel = 'answerable' | 'unanswerable' | 'foreign-only';

export interface LabeledCalibrationFixture {
  id: string;
  label: FixtureLabel;
  question: string;
  bundle: FixtureChunk[];
  /** Why this fixture is labeled as it is (the operational boundary). */
  note: string;
}

function chunk(id: string, text: string, rank: number): FixtureChunk {
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

export const CALIBRATION_FIXTURES: readonly LabeledCalibrationFixture[] = [
  // ---------------------------- answerable --------------------------------
  {
    id: 'compat-basic',
    label: 'answerable',
    question: 'question',
    bundle: [
      chunk('chunk-a', 'authorized evidence text', 1),
      chunk('chunk-b', 'authorized evidence text', 1),
    ],
    note: 'S7 compat contract: the original decide() unit shape (2 chunks, tied top rank, ZERO query overlap) must stay answered — the calibrated gate wraps, never tightens, the EVIDENCE_MIN_CHUNKS = 2 floor.',
  },
  {
    id: 'strong-multi',
    label: 'answerable',
    question: 'quantum teleportation fidelity',
    bundle: [
      chunk('q1', 'quantum teleportation achieved with high fidelity', 1),
      chunk('q2', 'teleportation fidelity measured across runs', 1),
      chunk('q3', 'quantum fidelity benchmarks', 2),
      chunk('q4', 'teleportation protocol notes', 3),
    ],
    note: 'Strong case: 4 chunks, top ranks, full query coverage.',
  },
  {
    id: 'moderate-pair',
    label: 'answerable',
    question: 'annual revenue growth',
    bundle: [
      chunk('r1', 'revenue grew this quarter', 2),
      chunk('r2', 'growth outlook remains strong', 3),
    ],
    note: 'Moderate: 2 chunks, mid ranks, 2/3 coverage ("annual" absent from texts).',
  },
  {
    id: 'weak-but-covered',
    label: 'answerable',
    question: 'merge deadline',
    bundle: [
      chunk('m1', 'merge deadline is next week', 4),
      chunk('m2', 'the merge deadline moved', 5),
    ],
    note: 'Weak ranks but FULL coverage: citable evidence exists for every query term.',
  },
  {
    id: 'multi-partial',
    label: 'answerable',
    question: 'customer retention policy',
    bundle: [
      chunk('p1', 'retention policy applies to customers', 1),
      chunk('p2', 'policy details for customer accounts', 2),
      chunk('p3', 'retention review board', 6),
    ],
    note: '3 chunks, mixed ranks, 2/3 coverage.',
  },
  {
    id: 'low-rank-partial',
    label: 'answerable',
    question: 'annual revenue growth',
    bundle: [
      chunk('l1', 'revenue trends summarized', 3),
      chunk('l2', 'growth figures available', 4),
    ],
    note: 'Low ranks + 2/3 coverage: the weakest still-answerable case (min answerable score).',
  },
  {
    id: 'top-ranked-partial',
    label: 'answerable',
    question: 'annual revenue growth',
    bundle: [
      chunk('t1', 'revenue outlook approved', 1),
      chunk('t2', 'revenue plan filed', 1),
    ],
    note: 'Top-ranked pair with only 1/3 coverage: top relevance compensates partial entity coverage.',
  },

  // ---------------------------- unanswerable ------------------------------
  {
    id: 'single-strong',
    label: 'unanswerable',
    question: 'merge deadline',
    bundle: [chunk('s1', 'merge deadline is next week', 1)],
    note: 'Single authorized chunk — refused by the decide() count floor regardless of rank/coverage.',
  },
  {
    id: 'single-weak',
    label: 'unanswerable',
    question: 'annual revenue growth',
    bundle: [chunk('s2', 'revenue table attached', 9)],
    note: 'Single authorized chunk, weak rank, partial coverage — count floor.',
  },
  {
    id: 'retrieved-unrelated',
    label: 'unanswerable',
    question: 'annual revenue growth',
    bundle: [
      chunk('u1', 'team sync notes for the sprint board', 2),
      chunk('u2', 'pipeline status for the ops review', 3),
    ],
    note: '2 authorized chunks, mid ranks, ZERO query-token overlap: retrieved but unrelated.',
  },
  {
    id: 'retrieved-unrelated-low',
    label: 'unanswerable',
    question: 'annual revenue growth',
    bundle: [
      chunk('u3', 'vacation calendar for the design team', 5),
      chunk('u4', 'office catering menu draft', 6),
    ],
    note: '2 authorized chunks, low ranks, zero overlap.',
  },
  {
    id: 'retrieved-unrelated-deep',
    label: 'unanswerable',
    question: 'annual revenue growth',
    bundle: [
      chunk('u9', 'warehouse inventory log', 8),
      chunk('u10', 'shipping manifest archive', 9),
    ],
    note: '2 authorized chunks, deep ranks, zero overlap.',
  },
  {
    id: 'low-rank-partial-refused',
    label: 'unanswerable',
    question: 'annual revenue growth',
    bundle: [
      chunk('u7', 'revenue appendix archived', 8),
      chunk('u8', 'legal filing index', 9),
    ],
    note: '2 chunks, deep ranks, only 1/3 coverage: partial coverage without relevant ranking.',
  },

  // ---------------------------- foreign-only ------------------------------
  {
    id: 'foreign-only-empty',
    label: 'foreign-only',
    question: 'quantum teleportation fidelity',
    bundle: [],
    note: 'Foreign/revoked/expired evidence never reaches the gate (RLS filters in SQL) — it manifests as an empty bundle. Score 0, refused.',
  },
];
