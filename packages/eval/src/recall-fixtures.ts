import type pg from 'pg';
import { randomUUID } from 'node:crypto';
import {
  DETERMINISTIC_EMBEDDING,
  EMBEDDING_DIM,
  type EmbeddingProvider,
} from '@securerag/core';
import { seedGrant } from '@securerag/db/src/testkit.js';

/**
 * Labeled hybrid-recall corpus (S6, ADR-0008 "Recall baseline").
 *
 * One tenant; three principals exercising grant selectivity against the SAME
 * corpus through the production grant predicate:
 *  - `full`    — grant on every document (100% chunk selectivity)
 *  - `narrow10` — grant on ~10% of documents (~10% of chunks)
 *  - `narrow1`  — grant on ~1% of documents (~1% of chunks; still sized so
 *    min(k, allowed) = allowed <= k exercises full-coverage recall)
 *
 * `narrowMode` controls WHERE the narrow grants sit:
 *  - 'spread' (recall baseline default): every 10th / every 100th document,
 *    so allowed chunks are uniformly spread across topics — the honest 1%
 *    selectivity scenario in which the HNSW filtering-after-scan footgun
 *    (research r4 §2.1) manifests without strict_order, and strict_order is
 *    the thing the gate proves.
 *  - 'prefix' (authorization tests): the FIRST 10% / 1% of documents, so a
 *    topic-aligned query lexically matches every allowed chunk — the narrow
 *    principals' no-starvation property is exercised on chunks they are
 *    allowed to see.
 *
 * ~200 documents x 1-3 chunks (default docCount 200, chunkCount 3) grouped
 * into 40 topics of 5 documents each; every topic shares a distinctive word
 * set, so the topic's chunks form a known semantic/lexical overlap group.
 * Neighboring documents rotate the topic word window, creating near-duplicates
 * ACROSS documents (the future unauthorized-order test corpus), and document
 * markers keep chunk texts distinct.
 *
 * Every chunk carries a deterministic embedding from the SAME provider used by
 * the retrieval pipeline for question embedding (DeterministicHashEmbedding),
 * so query vectors live in the same space as the corpus and the whole
 * baseline is reproducible with zero network.
 *
 * Selectivity is measured on chunks (granted documents' chunks / all chunks);
 * ground truth is computed in SQL by the exact paths (enable_indexscan/off),
 * never approximated in fixtures.
 */

const TOPIC_WORDS: string[][] = [
  ['quantum', 'coherence', 'entangled', 'superposition', 'photon', 'interference'],
  ['cipher', 'redaction', 'vault', 'keyrotation', 'plaintext', 'cleartext'],
  ['plasma', 'flux', 'toroidal', 'confinement', 'ignition', 'heating'],
  ['ledger', 'reconciliation', 'settlement', 'clearing', 'remittance', 'float'],
  ['biopsy', 'histology', 'cytology', 'lesion', 'necrosis', 'staining'],
  ['refinery', 'catalyst', 'cracking', 'distillation', 'feedstock', 'octane'],
  ['telemetry', 'attitude', 'thruster', 'perigee', 'apogee', 'eclipse'],
  ['mortgage', 'underwriting', 'escrow', 'appraisal', 'amortization', 'default'],
  ['pipeline', 'hydraulic', 'pigging', 'corrosion', 'flange', 'pressure'],
  ['quarantine', 'inoculum', 'serotype', 'antigen', 'virulence', 'isolation'],
  ['fuselage', 'aileron', 'cowl', 'nacelle', 'empennage', 'deice'],
  ['escrow', 'settlement', 'title', 'deed', 'encumbrance', 'lien'],
  ['electrolyte', 'anode', 'cathode', 'cell', 'dendrite', 'capacity'],
  ['herbicide', 'germination', 'photoperiod', 'allelopathy', 'tillage', 'mulch'],
  ['orbital', 'kepler', 'perigee', 'inclination', 'node', 'apsis'],
  ['impeachment', 'quorum', 'subpoena', 'hearing', 'caucus', 'committee'],
  ['turbine', 'pitch', 'yaw', 'nacelle', 'gear', 'blade'],
  ['anomaly', 'gradient', 'isotherm', 'adiabatic', 'cyclone', 'jetstream'],
  ['bloom', 'chlorophyll', 'eutrophication', 'algal', 'turbidity', 'nitrate'],
  ['arbitrage', 'volatility', 'hedge', 'spread', 'delta', 'gamma'],
  ['solder', 'reflow', 'stencil', 'flux', 'paste', 'interconnect'],
  ['denature', 'foldon', 'chaperone', 'misfold', 'proteostasis', 'aggregate'],
  ['combustion', 'stoichiometry', 'octane', 'knock', 'detonation', 'flame'],
  ['fiduciary', 'custodian', 'depository', 'rehypothecation', 'segregation', 'pledge'],
  ['photon', 'waveguide', 'coupling', 'evanescent', 'modulator', 'detector'],
  ['basalt', 'magma', 'vesicle', 'xenolith', 'tuff', 'breccia'],
  ['pollinator', 'nectar', 'forage', 'brood', 'hive', 'swarm'],
  ['stenography', 'shorthand', 'transcription', 'diplomatic', 'paleography', 'manuscript'],
  ['sinter', 'ceramic', 'greenware', 'kiln', 'glaze', 'frit'],
  ['effluent', 'denitrification', 'anammox', 'clarifier', 'activated', 'sludge'],
  ['cartography', 'projection', 'geodesy', 'datum', 'contour', 'relief'],
  ['ionosphere', 'scintillation', 'troposphere', 'ducting', 'absorption', 'refraction'],
  ['deuterium', 'tritium', 'blanket', 'plasma', 'neutron', 'breeding'],
  ['aquifer', 'recharge', 'drawdown', 'confining', 'porosity', 'saline'],
  ['bronchitis', 'spirometry', 'obstruction', 'ventilation', 'airflow', 'peak'],
  ['hemoglobin', 'oxygen', 'erythrocyte', 'hemolysis', 'transfusion', 'ferritin'],
  ['quaternion', 'rotation', 'gimbal', 'attitude', 'inertial', 'integration'],
  ['cartel', 'collusion', 'antitrust', 'predation', 'monopsony', 'dominance'],
  ['turboprop', 'propeller', 'feathering', 'governor', 'torque', 'alpha'],
  ['synapse', 'neurotransmitter', 'potentiation', 'plasticity', 'myelin', 'axon'],
];

export interface RecallQueryLabel {
  topicIndex: number;
  text: string;
  /** Expected chunk ids in the topic's overlap group (labeled; exact ground truth is SQL-computed). */
  topicChunkIds: string[];
}

export interface RecallCorpus {
  tenantId: string;
  full: string;
  narrow10: string;
  narrow1: string;
  docs: number;
  chunkCount: number;
  /** chunk_id -> topic index (labeling for reports and sanity checks). */
  chunkTopic: Map<string, number>;
  queries: RecallQueryLabel[];
  /** Every chunk id in the corpus (full-grant scope). */
  allChunkIds: string[];
  narrow10ChunkIds: string[];
  narrow1ChunkIds: string[];
}

/** Deterministic PRNG (mulberry32) so corpus content is reproducible. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function windowOf(words: string[], start: number, count: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < count; i += 1) out.push(words[(start + i) % words.length]!);
  return out;
}

export interface RecallCorpusOptions {
  /** Number of documents; must be >= 10 and divisible by 5 (5 docs per topic). Default 200. */
  docCount?: number;
  /** Chunks per document; default 3. */
  chunkCount?: number;
  /** Embedding provider for chunk embeddings; defaults to the deterministic CI fake. */
  embeddings?: EmbeddingProvider;
  /** Where the narrow-ACL grants sit: 'spread' (baseline) or 'prefix' (authz tests). */
  narrowMode?: 'spread' | 'prefix';
}

export async function buildRecallCorpus(
  pool: pg.Pool,
  options: RecallCorpusOptions = {},
): Promise<RecallCorpus> {
  const docCount = options.docCount ?? 200;
  const chunkCount = options.chunkCount ?? 3;
  const narrowMode = options.narrowMode ?? 'spread';
  if (docCount < 10 || docCount % 5 !== 0) {
    throw new Error(`recall corpus docCount must be >= 10 and a multiple of 5, got ${docCount}`);
  }
  const embeddings = options.embeddings ?? DETERMINISTIC_EMBEDDING;
  const rand = mulberry32(0x5ec2_2ea9);
  const tenantId = randomUUID();
  const topics = Math.floor(docCount / 5);

  await pool.query(
    `INSERT INTO securerag.tenants (tenant_id, name) VALUES ($1, 'Recall Tenant')`,
    [tenantId],
  );

  const principals = await pool.query<{ principal_id: string }>(
    `INSERT INTO securerag.principals (principal_id, provider, external_subject, display_name) VALUES
       (gen_random_uuid(), 'test-issuer', 'recall-full-sub', 'Recall Full'),
       (gen_random_uuid(), 'test-issuer', 'recall-narrow10-sub', 'Recall Narrow10'),
       (gen_random_uuid(), 'test-issuer', 'recall-narrow1-sub', 'Recall Narrow1')
     RETURNING principal_id`,
  );
  const [full, narrow10, narrow1] = principals.rows;
  if (!full || !narrow10 || !narrow1) throw new Error('recall corpus principal insert failed');

  await pool.query(
    `INSERT INTO securerag.tenant_memberships (tenant_id, principal_id, role) VALUES
       ($1, $2, 'member'),
       ($1, $3, 'member'),
       ($1, $4, 'member')`,
    [tenantId, full.principal_id, narrow10.principal_id, narrow1.principal_id],
  );

  // spread: every 10th / every 100th doc (uniform selectivity across topics);
  // prefix: the first ceil(10%) / max(1, floor(1%)) docs (clustered grants).
  const narrow10Granted = (docIdx: number): boolean =>
    narrowMode === 'spread' ? docIdx % 10 === 0 : docIdx < Math.max(1, Math.ceil(docCount * 0.1));
  const narrow1Granted = (docIdx: number): boolean =>
    narrowMode === 'spread' ? docIdx % 100 === 0 : docIdx < Math.max(1, Math.floor(docCount * 0.01));

  const docInsert = async (title: string): Promise<string> => {
    const { rows } = await pool.query<{ document_id: string }>(
      `INSERT INTO securerag.documents (tenant_id, title) VALUES ($1, $2) RETURNING document_id`,
      [tenantId, title],
    );
    const id = rows[0]?.document_id;
    if (!id) throw new Error('recall corpus document insert failed');
    return id;
  };

  const chunkTopic = new Map<string, number>();
  const allChunkIds: string[] = [];
  const narrow10ChunkIds: string[] = [];
  const narrow1ChunkIds: string[] = [];

  for (let docIdx = 0; docIdx < docCount; docIdx += 1) {
    const topicIndex = Math.floor(docIdx / 5);
    const words = TOPIC_WORDS[topicIndex] ?? TOPIC_WORDS[0]!;
    const topic = words[0]!;
    const documentId = await docInsert(`${topic} recall doc ${docIdx}`);
    const { rows } = await pool.query<{ version_id: string }>(
      `INSERT INTO securerag.document_versions
         (tenant_id, document_id, version_no, source_object_key, content_hash, status, is_current)
       VALUES ($1, $2, 1, $3, decode('aabb', 'hex'), 'valid', true) RETURNING version_id`,
      [tenantId, documentId, `recall/${topic}-${docIdx}.txt`],
    );
    const versionId = rows[0]?.version_id;
    if (!versionId) throw new Error('recall corpus version insert failed');

    const texts: string[] = [];
    for (let chunkIdx = 0; chunkIdx < chunkCount; chunkIdx += 1) {
      const windowStart = (docIdx + chunkIdx + Math.floor(rand() * 2)) % 5;
      const window = windowOf(words.slice(1), windowStart, 2);
      // Topic word opens and closes every chunk; a rotating window of two
      // distinctive words; a unique doc marker keeps chunks distinct while
      // neighboring documents stay near-duplicates.
      texts.push(`${topic} ${window.join(' ')} ${topic} doc${docIdx} chunk${chunkIdx}`);
    }

    const vectors = await embeddings.embed(texts);
    const chunkValues: string[] = [];
    const chunkIds: string[] = [];
    for (let chunkIdx = 0; chunkIdx < texts.length; chunkIdx += 1) {
      const chunkId = randomUUID();
      chunkIds.push(chunkId);
      chunkValues.push(
        `(${quote(tenantId)}, ${quote(chunkId)}, ${quote(versionId)}, ${chunkIdx + 1}, ${quote(texts[chunkIdx]!)}, ` +
          `${chunkIdx * 10}, ${chunkIdx * 10 + texts[chunkIdx]!.length}, decode('aabb', 'hex'), ` +
          `'${toPgVector(vectors[chunkIdx]!)}'::vector)`,
      );
      chunkTopic.set(chunkId, topicIndex);
      allChunkIds.push(chunkId);
      if (narrow10Granted(docIdx)) narrow10ChunkIds.push(chunkId);
      if (narrow1Granted(docIdx)) narrow1ChunkIds.push(chunkId);
    }
    await pool.query(
      `INSERT INTO securerag.chunks
         (tenant_id, chunk_id, version_id, chunk_no, text_redacted, span_start, span_end, content_hash, embedding)
       VALUES ${chunkValues.join(', ')}`,
    );

    // full principal: grant on every document
    await seedGrant(pool, {
      tenantId,
      documentId,
      subjectType: 'principal',
      subjectId: full.principal_id,
      capability: 'read',
    });
    if (narrow10Granted(docIdx)) {
      await seedGrant(pool, {
        tenantId,
        documentId,
        subjectType: 'principal',
        subjectId: narrow10.principal_id,
        capability: 'read',
      });
    }
    if (narrow1Granted(docIdx)) {
      await seedGrant(pool, {
        tenantId,
        documentId,
        subjectType: 'principal',
        subjectId: narrow1.principal_id,
        capability: 'read',
      });
    }
  }

  // One labeled query per topic: topic word + a rotating pair of topic words.
  const queries: RecallQueryLabel[] = TOPIC_WORDS.slice(0, topics).map((words, topicIndex) => {
    const q = `${words[0]} ${words[1]} ${words[2]}`;
    const topicChunkIds = allChunkIds.filter((id) => chunkTopic.get(id) === topicIndex);
    return { topicIndex, text: q, topicChunkIds };
  });

  return {
    tenantId,
    full: full.principal_id,
    narrow10: narrow10.principal_id,
    narrow1: narrow1.principal_id,
    docs: docCount,
    chunkCount,
    chunkTopic,
    queries,
    allChunkIds,
    narrow10ChunkIds,
    narrow1ChunkIds,
  };
}

/** SQL string literal (corpus text is generated, but never trust it raw). */
function quote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function toPgVector(values: number[]): string {
  if (values.length !== EMBEDDING_DIM) {
    throw new Error(`recall corpus embedding dim ${values.length} != ${EMBEDDING_DIM}`);
  }
  return `[${values.map((v) => v.toFixed(6)).join(',')}]`;
}
