/**
 * Source object storage seam (S9/S2; ADR-0010, ADR-0007).
 *
 * The purge worker removes SOURCE objects through `deleteSources` (S9);
 * the ingestion pipeline writes/reads them through `put`/`get`/`has` (S2).
 *
 * Object contract (ADR-0007):
 *  - one S3-compatible bucket; keys are tenant-prefixed and
 *    CONTENT-ADDRESSED: `tenant/{tenantId}/{sha256}/{filename}` — immutable
 *    (any byte change → new key), automatically deduplicated, unguessable.
 *  - SSE-S3 automatic at-rest encryption (bucket-default in MinIO/KMS; the
 *    S3 adapter also passes `ServerSideEncryption: AES256` per put).
 *  - NO presigned or permanent public URLs ever: object reads stream through
 *    the authorized API route that re-checks RLS/grants per request.
 *
 * Adapters: InMemorySourceObjectStore (CI/local fake, bytes in memory) and
 * S3SourceObjectStore (S3/MinIO via @aws-sdk/client-s3, config from env —
 * never secrets in code; not exercised in CI without a container).
 */
import {
  DeleteObjectsCommand,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
  type S3ClientConfig,
} from '@aws-sdk/client-s3';

export interface SourceObjectStore {
  /** Store `bytes` at `key` (content-addressed; idempotent overwrite). */
  put(key: string, bytes: Buffer): Promise<void>;
  /** Read the object bytes; null when the key does not exist. */
  get(key: string): Promise<Buffer | null>;
  /** True when the key exists. */
  has(key: string): Promise<boolean>;
  /** Delete the given object keys; returns how many actually existed. */
  deleteSources(keys: readonly string[]): Promise<number>;
}

/**
 * In-memory fake for CI/local: content-addressed keys; `deleteSources` counts
 * only keys that exist, so the purge flow's counts are honest and idempotent
 * re-runs report zero without an error. `put` with one argument (the S9
 * purge tests' convenience shape) stores an empty buffer.
 */
export class InMemorySourceObjectStore implements SourceObjectStore {
  private readonly objects = new Map<string, Buffer>();

  /** Record an uploaded source object (fixture/seed helper). */
  async put(key: string, bytes: Buffer = Buffer.alloc(0)): Promise<void> {
    this.objects.set(key, bytes);
  }

  async get(key: string): Promise<Buffer | null> {
    return this.objects.get(key) ?? null;
  }

  async has(key: string): Promise<boolean> {
    return this.objects.has(key);
  }

  get size(): number {
    return this.objects.size;
  }

  async deleteSources(keys: readonly string[]): Promise<number> {
    let deleted = 0;
    for (const key of keys) {
      if (this.objects.delete(key)) deleted += 1;
    }
    return deleted;
  }
}

/** Content-addressed key shape (ADR-0007): tenant prefix first, sha256, safe filename. */
export function sourceObjectKey(tenantId: string, sha256Hex: string, filename: string): string {
  return `tenant/${tenantId}/${sha256Hex}/${sanitizeFilename(filename)}`;
}

/** Strip path components and control characters from an untrusted filename. */
export function sanitizeFilename(filename: string): string {
  const base = filename.split('/').pop()?.split('\\').pop() ?? '';
  const cleaned = base.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 200).trim();
  return cleaned.length > 0 ? cleaned : 'document';
}

export interface S3SourceObjectStoreConfig {
  bucket: string;
  /** S3-compatible endpoint (MinIO/AIStor); omit for AWS S3. */
  endpoint?: string;
  region?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  /** Path-style addressing for MinIO/AIStor (AWS S3 uses virtual-host). */
  forcePathStyle?: boolean;
}

/**
 * S3-compatible adapter (ADR-0007; MinIO pinned in ops, AIStor successor
 * noted). Keys are opaque to S3 (flat namespace → no path traversal);
 * SSE-S3 is requested per put (`AES256`) AND expected bucket-default. The
 * worker/API service credentials hold NO ListBucket grant — tenant
 * separation is enforced in PostgreSQL before any key leaves the DB.
 */
export class S3SourceObjectStore implements SourceObjectStore {
  private readonly client: S3Client;
  private readonly bucket: string;

  constructor(config: S3SourceObjectStoreConfig) {
    this.bucket = config.bucket;
    const clientConfig: S3ClientConfig = {
      region: config.region ?? 'us-east-1',
      ...(config.endpoint !== undefined ? { endpoint: config.endpoint } : {}),
      ...(config.forcePathStyle !== undefined ? { forcePathStyle: config.forcePathStyle } : {}),
    };
    if (config.accessKeyId !== undefined && config.secretAccessKey !== undefined) {
      clientConfig.credentials = {
        accessKeyId: config.accessKeyId,
        secretAccessKey: config.secretAccessKey,
      };
    }
    this.client = new S3Client(clientConfig);
  }

  async put(key: string, bytes: Buffer): Promise<void> {
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: bytes,
        ServerSideEncryption: 'AES256',
      }),
    );
  }

  async get(key: string): Promise<Buffer | null> {
    try {
      const response = await this.client.send(
        new GetObjectCommand({ Bucket: this.bucket, Key: key }),
      );
      const body = response.Body;
      if (body === undefined) return null;
      return Buffer.from(await body.transformToByteArray());
    } catch (err) {
      if (isNoSuchKey(err)) return null;
      throw err;
    }
  }

  async has(key: string): Promise<boolean> {
    try {
      await this.client.send(new HeadObjectCommand({ Bucket: this.bucket, Key: key }));
      return true;
    } catch (err) {
      if (isNoSuchKey(err)) return false;
      throw err;
    }
  }

  async deleteSources(keys: readonly string[]): Promise<number> {
    if (keys.length === 0) return 0;
    // Batch deletes: deleteSources' count contract = keys that existed.
    let deleted = 0;
    for (let i = 0; i < keys.length; i += 1000) {
      const batch = keys.slice(i, i + 1000).map((Key) => ({ Key }));
      const response = await this.client.send(
        new DeleteObjectsCommand({ Bucket: this.bucket, Delete: { Objects: batch } }),
      );
      deleted += response.Deleted?.length ?? 0;
    }
    return deleted;
  }
}

function isNoSuchKey(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    ((err as { name?: string }).name === 'NoSuchKey' ||
      (err as { name?: string }).name === 'NotFound')
  );
}
