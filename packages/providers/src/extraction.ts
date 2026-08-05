/**
 * Extraction seam + adapters (S2; ADR-0007, research r8 §1).
 *
 * Contract: `ExtractionProvider.extract(buffer, contentType)` returns the
 * UTF-8 text layer of the document plus a page count when the format has one.
 * v1 adapters:
 *   - PdfExtractor  — pdfjs-dist 6.2.x (Apache-2.0), legacy build; page cap.
 *   - DocxExtractor — mammoth 1.12.x (BSD-2-Clause), raw text.
 *   - TextExtractor — stdlib UTF-8 decode (fatal: true), BOM stripped.
 *
 * OCR is NOT in v1 (ADR-0007): scanned/image-only PDFs (empty text layer) and
 * every other unsupported type produce a typed UnsupportedTypeError that names
 * the reason — never a silent empty ingestion. Limits are declared constants
 * enforced here and in the pipeline (research r8 §1 "Limits"): 50 MB input,
 * 1 000 pages, 10 MB extracted text, 60 s parse timeout. Violations are typed
 * errors (SizeLimitError / PageLimitError / TextSizeLimitError /
 * ExtractionTimeoutError) so callers can classify deterministically.
 *
 * Extracted text is UNTRUSTED input to everything downstream (injection
 * detection, embeddings) — parse defensively, never crash the worker.
 */

/** v1 input cap (ADR-0007): 50 MB per uploaded source object. */
export const MAX_SOURCE_BYTES = 50 * 1024 * 1024;
/** v1 page cap (r8 §1): 1 000 pages per PDF. */
export const MAX_PAGES = 1000;
/** v1 extracted-text cap (r8 §1): 10 MB of UTF-8 text. */
export const MAX_EXTRACTED_TEXT_BYTES = 10 * 1024 * 1024;
/** v1 parse timeout (r8 §1): 60 s wall-clock per extraction. */
export const EXTRACTION_TIMEOUT_MS = 60_000;

/** MIME types the v1 pipeline accepts (server-detected, never client-supplied). */
export const SUPPORTED_CONTENT_TYPES = [
  'application/pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'text/plain',
  'text/markdown',
] as const;

export type SupportedContentType = (typeof SUPPORTED_CONTENT_TYPES)[number];

/** The pipeline seam: extract the text layer of a source buffer. */
export interface ExtractionProvider {
  extract(buffer: Buffer, contentType: string): Promise<ExtractedText>;
}

export interface ExtractedText {
  /** UTF-8 text layer; empty only when the parser produced nothing. */
  text: string;
  /** Page count for paged formats (PDF); null for non-paged formats. */
  pages: number | null;
}

/** Base class for every extraction failure (typed, never a crash). */
export class ExtractionError extends Error {
  constructor(
    message: string,
    /** Machine-stable reason string for audit filters (never content). */
    readonly reason: string,
  ) {
    super(message);
    this.name = 'ExtractionError';
  }
}

/** The type is recognized but unsupported in v1 (scanned PDFs, images, zip, …). */
export class UnsupportedTypeError extends ExtractionError {
  constructor(reason: string) {
    super(`unsupported document type: ${reason}`, reason);
    this.name = 'UnsupportedTypeError';
  }
}

/** Input exceeds the 50 MB source cap. */
export class SizeLimitError extends ExtractionError {
  constructor(sizeBytes: number) {
    super(`source exceeds 50 MB (${sizeBytes} bytes)`, 'size-limit');
    this.name = 'SizeLimitError';
  }
}

/** PDF exceeds the 1 000 page cap. */
export class PageLimitError extends ExtractionError {
  constructor(pages: number) {
    super(`pdf exceeds 1 000 pages (${pages})`, 'page-limit');
    this.name = 'PageLimitError';
  }
}

/** Extracted text exceeds the 10 MB cap. */
export class TextSizeLimitError extends ExtractionError {
  constructor(sizeBytes: number) {
    super(`extracted text exceeds 10 MB (${sizeBytes} bytes)`, 'text-size-limit');
    this.name = 'TextSizeLimitError';
  }
}

/** The parser did not finish within the 60 s budget. */
export class ExtractionTimeoutError extends ExtractionError {
  constructor() {
    super('extraction exceeded the 60 s timeout', 'timeout');
    this.name = 'ExtractionTimeoutError';
  }
}

/**
 * Run `fn` under a wall-clock budget. The worker subprocess isolation
 * (r8 §1) is the resource backstop; this timeout is the deterministic
 * job-level bound.
 */
async function withTimeout<T>(ms: number, fn: () => Promise<T>): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      fn(),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new ExtractionTimeoutError()), ms);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** Zip-bomb guard for DOCX (a zip container): cap entries and the ratio of
 * uncompressed to compressed size before mammoth inflates anything (S2
 * review 3). */
function assertSafeZip(buffer: Buffer): void {
  const ZIP_MAX_ENTRIES = 2_000;
  const ZIP_MAX_RATIO = 100;
  let entries = 0;
  let compressed = 0;
  let uncompressed = 0;
  // Parse the central directory records: EOCD at the end, entries before it.
  const eocd = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (eocd < 0) throw new UnsupportedTypeError('docx-zip-malformed');
  const count = buffer.readUInt16LE(eocd + 10);
  const offset = buffer.readUInt32LE(eocd + 16);
  if (count > ZIP_MAX_ENTRIES) throw new TextSizeLimitError(0);
  for (let i = 0; i < count; i += 1) {
    const pos = offset + i * 46;
    if (pos + 46 > buffer.length) break;
    const method = buffer.readUInt16LE(pos + 10);
    const comp = buffer.readUInt32LE(pos + 20);
    const uncomp = buffer.readUInt32LE(pos + 24);
    compressed += comp;
    uncompressed += uncomp;
    void method;
  }
  if (compressed > 0 && uncompressed / compressed > ZIP_MAX_RATIO) {
    throw new TextSizeLimitError(0);
  }
  entries = count;
  void entries;
}

/** Enforce the extracted-text cap (post-parse, all adapters). */
function enforceTextCap(text: string): string {
  const bytes = Buffer.byteLength(text, 'utf8');
  if (bytes > MAX_EXTRACTED_TEXT_BYTES) throw new TextSizeLimitError(bytes);
  return text;
}

/**
 * PDF text extraction via pdfjs-dist (legacy build, r8 §1): the legacy entry
 * runs in Node without worker/DOMMatrix gymnastics. Page cap checked from
 * `numPages` before any page is loaded; empty text layer = scanned/image-only
 * PDF = typed UnsupportedTypeError (OCR is not in v1).
 */
export class PdfExtractor {
  /** Lazy import keeps pdfjs-dist out of other bundles until used. */
  async extract(buffer: Buffer): Promise<ExtractedText> {
    if (buffer.length > MAX_SOURCE_BYTES) throw new SizeLimitError(buffer.length);
    const { getDocument } = await import('pdfjs-dist/legacy/build/pdf.mjs');
    const task = getDocument({
      data: new Uint8Array(buffer),
      useWorkerFetch: false,
      disableFontFace: true,
    });
    const timeout = new Promise<never>((_, reject) => {
      setTimeout(() => {
        // Cancel the underlying parse so a hostile 50MB PDF cannot pin CPU
        // after the timeout (S2 review 3). task.destroy aborts the worker.
        void task.destroy().catch(() => {});
        reject(new ExtractionTimeoutError());
      }, EXTRACTION_TIMEOUT_MS).unref?.();
    });
    try {
      const pdf = await Promise.race([task.promise, timeout]);
      const pages = pdf.numPages;
      if (pages > MAX_PAGES) throw new PageLimitError(pages);
      let text = '';
      for (let pageNo = 1; pageNo <= pages; pageNo += 1) {
        const page = await pdf.getPage(pageNo);
        const content = await page.getTextContent();
        for (const item of content.items) {
          const str = (item as { str?: unknown }).str;
          if (typeof str === 'string') text += str;
        }
        if (pageNo < pages) text += '\n';
      }
      text = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      if (text.trim().length === 0) {
        // No text layer: a scanned/image-only PDF. Explicit v1 rejection.
        throw new UnsupportedTypeError('no-extractable-text-layer-ocr-not-supported');
      }
      return { text: enforceTextCap(text), pages };
    } finally {
      // Best-effort: destroy the worker so hostile streams cannot pin it.
      void task.destroy().catch(() => {});
    }
  }
}

/**
 * DOCX raw-text extraction via mammoth (BSD-2-Clause, r8 §1). Legacy .doc is
 * not supported (mammoth is docx-only) and rejects as unsupported.
 */
export class DocxExtractor {
  async extract(buffer: Buffer, contentType: string): Promise<ExtractedText> {
    if (buffer.length > MAX_SOURCE_BYTES) throw new SizeLimitError(buffer.length);
    if (contentType !== 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
      throw new UnsupportedTypeError('docx-mime-required');
    }
    // Zip-bomb guard (S2 review 3): DOCX is a zip; cap entry count and the
    // decompressed ratio before mammoth inflates anything.
    assertSafeZip(buffer);
    const mammoth = await import('mammoth');
    const { value } = await mammoth.extractRawText({ buffer });
    const text = value.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    return { text: enforceTextCap(text), pages: null };
  }
}

/**
 * Plain text / Markdown (r8 §1): stdlib decode with `fatal: true` — invalid
 * UTF-8 rejects rather than silently replacing. BOM stripped. Markdown is
 * ingested as plain text in v1 (no markdown parsing).
 */
export class TextExtractor {
  async extract(buffer: Buffer, contentType: string): Promise<ExtractedText> {
    if (buffer.length > MAX_EXTRACTED_TEXT_BYTES) {
      throw new TextSizeLimitError(buffer.length);
    }
    if (contentType !== 'text/plain' && contentType !== 'text/markdown') {
      throw new UnsupportedTypeError('text-mime-required');
    }
    let text: string;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
    } catch {
      throw new UnsupportedTypeError('invalid-utf8');
    }
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    return { text: enforceTextCap(text), pages: null };
  }
}

/**
 * Content-type dispatch (the v1 pipeline adapter). Unknown/unsupported types
 * reject as UnsupportedTypeError with the type name (never a silent empty
 * ingestion); every supported path is bounded by size + timeout caps.
 */
export class StandardExtractionProvider implements ExtractionProvider {
  private readonly pdf = new PdfExtractor();
  private readonly docx = new DocxExtractor();
  private readonly text = new TextExtractor();

  async extract(buffer: Buffer, contentType: string): Promise<ExtractedText> {
    if (buffer.length > MAX_SOURCE_BYTES) throw new SizeLimitError(buffer.length);
    return withTimeout(EXTRACTION_TIMEOUT_MS, async () => {
      switch (contentType) {
        case 'application/pdf':
          return this.pdf.extract(buffer);
        case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
          return this.docx.extract(buffer, contentType);
        case 'text/plain':
        case 'text/markdown':
          return this.text.extract(buffer, contentType);
        default:
          throw new UnsupportedTypeError(`unsupported-content-type-${contentType}`);
      }
    });
  }
}

/** Shared CI/demo instance. */
export const STANDARD_EXTRACTION = new StandardExtractionProvider();
