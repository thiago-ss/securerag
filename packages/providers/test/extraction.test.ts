import { describe, expect, it } from 'vitest';
import {
  EXTRACTION_TIMEOUT_MS,
  MAX_EXTRACTED_TEXT_BYTES,
  MAX_SOURCE_BYTES,
  PageLimitError,
  PdfExtractor,
  SizeLimitError,
  StandardExtractionProvider,
  TextExtractor,
  TextSizeLimitError,
  UnsupportedTypeError,
} from '../src/index.js';
import { buildMinimalDocx, buildMultiPagePdf, buildScannedPdf, buildTextPdf } from '../src/test-fixtures.js';

const DOCX = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';

describe('S2 extraction: PDF via pdfjs-dist (legacy build, Node)', () => {
  it('extracts the text layer of a real PDF fixture (pdfjs-dist must parse it)', async () => {
    const pdf = buildTextPdf('Hello pdf world 123');
    const { text, pages } = await new PdfExtractor().extract(pdf);
    expect(pages).toBe(1);
    expect(text).toContain('Hello pdf world 123');
  });

  it('rejects scanned/image-only PDFs (no text layer) as unsupported — OCR is not in v1', async () => {
    const scanned = buildScannedPdf();
    await expect(new PdfExtractor().extract(scanned)).rejects.toBeInstanceOf(
      UnsupportedTypeError,
    );
    await expect(new PdfExtractor().extract(scanned)).rejects.toMatchObject({
      reason: 'no-extractable-text-layer-ocr-not-supported',
    });
  });

  it('rejects over-size input before parsing (50 MB cap)', async () => {
    const big = Buffer.alloc(MAX_SOURCE_BYTES + 1, 0x20);
    await expect(new PdfExtractor().extract(big)).rejects.toBeInstanceOf(SizeLimitError);
  });

  it('rejects over-page PDFs with a typed PageLimitError (1k cap)', async () => {
    // A real 1001-page PDF: the numPages gate fires before any page loads.
    await expect(
      new PdfExtractor().extract(buildMultiPagePdf(1001, 'x')),
    ).rejects.toBeInstanceOf(PageLimitError);
  });
});

describe('S2 extraction: DOCX via mammoth', () => {
  it('extracts raw text from a minimal docx fixture', async () => {
    const docx = buildMinimalDocx('Hello docx world 123');
    const { text, pages } = await new StandardExtractionProvider().extract(docx, DOCX);
    expect(pages).toBeNull();
    expect(text).toContain('Hello docx world 123');
  });

  it('rejects non-docx content types as unsupported', async () => {
    await expect(
      new StandardExtractionProvider().extract(buildMinimalDocx('x'), 'application/zip'),
    ).rejects.toBeInstanceOf(UnsupportedTypeError);
  });
});

describe('S2 extraction: plain text / markdown', () => {
  it('decodes UTF-8 text and strips the BOM', async () => {
    const withBom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('café', 'utf8')]);
    const { text, pages } = await new StandardExtractionProvider().extract(withBom, 'text/plain');
    expect(pages).toBeNull();
    expect(text).toBe('café');
  });

  it('accepts markdown as plain text', async () => {
    const md = Buffer.from('# Title\n\nbody text', 'utf8');
    const { text } = await new StandardExtractionProvider().extract(md, 'text/markdown');
    expect(text).toContain('# Title');
  });

  it('rejects invalid UTF-8 instead of silently replacing', async () => {
    const bad = Buffer.from([0xff, 0xfe, 0xfd]);
    await expect(new TextExtractor().extract(bad, 'text/plain')).rejects.toMatchObject({
      reason: 'invalid-utf8',
    });
  });

  it('caps text input at 10 MB', async () => {
    const big = Buffer.alloc(MAX_EXTRACTED_TEXT_BYTES + 1, 0x61);
    await expect(new TextExtractor().extract(big, 'text/plain')).rejects.toBeInstanceOf(
      TextSizeLimitError,
    );
  });
});

describe('S2 extraction: provider dispatch and limits', () => {
  it('rejects unsupported types with a typed UnsupportedTypeError naming the type', async () => {
    const provider = new StandardExtractionProvider();
    for (const contentType of ['application/zip', 'image/png', 'application/octet-stream', '']) {
      await expect(provider.extract(Buffer.from('x'), contentType)).rejects.toBeInstanceOf(
        UnsupportedTypeError,
      );
      await expect(provider.extract(Buffer.from('x'), contentType)).rejects.toMatchObject({
        reason: `unsupported-content-type-${contentType}`,
      });
    }
  });

  it('enforces the 50 MB input cap at the provider boundary', async () => {
    const provider = new StandardExtractionProvider();
    await expect(
      provider.extract(Buffer.alloc(MAX_SOURCE_BYTES + 1), 'text/plain'),
    ).rejects.toBeInstanceOf(SizeLimitError);
  });

  it('declares the 60 s timeout constant (enforced by withTimeout around dispatch)', () => {
    expect(EXTRACTION_TIMEOUT_MS).toBe(60_000);
    expect(MAX_EXTRACTED_TEXT_BYTES).toBe(10 * 1024 * 1024);
    expect(MAX_SOURCE_BYTES).toBe(50 * 1024 * 1024);
  });
});
