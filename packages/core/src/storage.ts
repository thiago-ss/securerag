/**
 * Source object storage seam (S9, ADR-0010 / r8 §4): the purge worker removes
 * SOURCE objects through this interface. Object storage itself is S2's scope;
 * v1 ships the in-memory fake so verified deletion can prove the source
 * storage class end to end. A real S3/MinIO adapter plugs in later without
 * touching the purge pipeline.
 */
export interface SourceObjectStore {
  /** Delete the given object keys; returns how many actually existed. */
  deleteSources(keys: readonly string[]): Promise<number>;
}

/**
 * In-memory fake for CI/local: content-addressed keys; `deleteSources` counts
 * only keys that exist, so the purge flow's counts are honest and idempotent
 * re-runs report zero without an error.
 */
export class InMemorySourceObjectStore implements SourceObjectStore {
  private readonly objects = new Set<string>();

  /** Record an uploaded source object (fixture/seed helper). */
  put(key: string): void {
    this.objects.add(key);
  }

  has(key: string): boolean {
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
