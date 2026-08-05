/**
 * Deterministic minimal-document fixtures (S2): a byte-exact PDF and a
 * stored (uncompressed) DOCX, both built in-process with correct offsets so
 * pdfjs-dist and mammoth parse them. No external binaries, no committed
 * blobs — identical bytes every run.
 */

// ---------- Minimal PDF (one page per text layer, correct xref) ----------

/**
 * Build a minimal valid PDF with one page per entry in `textLayers`
 * (raw content-stream operators; '' builds a page with NO text layer —
 * scanned-PDF simulation). Offsets are computed exactly; pdfjs-dist must
 * parse it.
 */
export function buildMinimalPdf(textLayers: readonly string[]): Buffer {
  const n = textLayers.length;
  if (n < 1) throw new Error('pdf fixture needs >= 1 page');
  const fontObjNo = 2 * n + 3; // catalog, pages, n pages, n contents, font
  const pageObj = (i: number): string => {
    const contentObj = n + 3 + i; // content streams come after all pages
    return `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents ${contentObj} 0 R `
      + `/Resources << /Font << /F1 ${fontObjNo} 0 R >> >> >>`;
  };
  const contentObj = (i: number): string => {
    const layer = textLayers[i] ?? '';
    return `<< /Length ${Buffer.byteLength(layer, 'ascii')} >>\nstream\n${layer}\nendstream`;
  };
  const fontObj = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';

  const kids = Array.from({ length: n }, (_, i) => `${i + 3} 0 R`).join(' ');
  const objects: string[] = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    `<< /Type /Pages /Kids [${kids}] /Count ${n} >>`,
    ...Array.from({ length: n }, (_, i) => pageObj(i)),
    ...Array.from({ length: n }, (_, i) => contentObj(i)),
    fontObj,
  ];
  let out = '%PDF-1.4\n';
  const offsets: number[] = [];
  for (let i = 0; i < objects.length; i += 1) {
    const body = objects[i] ?? '';
    offsets.push(Buffer.byteLength(out, 'latin1'));
    out += `${i + 1} 0 obj\n${body}\nendobj\n`;
  }
  const xrefStart = Buffer.byteLength(out, 'latin1');
  out += `xref\n0 ${objects.length + 1}\n`;
  out += '0000000000 65535 f \n';
  for (const offset of offsets) {
    out += `${String(offset).padStart(10, '0')} 00000 n \n`;
  }
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\n`;
  out += `startxref\n${xrefStart}\n%%EOF\n`;
  return Buffer.from(out, 'latin1');
}

/** A one-page PDF with an extractable text layer. */
export function buildTextPdf(text: string): Buffer {
  // Escape parens/backslashes inside the Tj string (fixture text is plain).
  const safe = text.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
  return buildMinimalPdf([`BT /F1 24 Tf 72 720 Td (${safe}) Tj ET`]);
}

/** A scanned-PDF simulation: one page, NO text layer. */
export function buildScannedPdf(): Buffer {
  return buildMinimalPdf(['q Q']); // no text operators
}

/** An N-page PDF where every page has a text layer. */
export function buildMultiPagePdf(pageCount: number, text: string): Buffer {
  const safe = text.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
  const layer = `BT /F1 24 Tf 72 720 Td (${safe}) Tj ET`;
  return buildMinimalPdf(Array.from({ length: pageCount }, () => layer));
}

// ---------- Minimal DOCX (stored ZIP with exact CRC32) ----------

const CRC_TABLE: number[] = (() => {
  const table = new Array<number>(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(data: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc = (crc >>> 8) ^ (CRC_TABLE[(crc ^ byte) & 0xff] ?? 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function zipEntry(name: string, data: Buffer): Buffer {
  const crc = crc32(data);
  const nameBuf = Buffer.from(name, 'utf8');
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4); // version needed
  local.writeUInt16LE(0x0800, 6); // UTF-8 name flag
  local.writeUInt16LE(0, 8); // stored
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(nameBuf.length, 26);
  return Buffer.concat([local, nameBuf, data]);
}

function zipCentral(name: string, data: Buffer, localOffset: number): Buffer {
  const crc = crc32(data);
  const nameBuf = Buffer.from(name, 'utf8');
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0x0800, 8);
  central.writeUInt16LE(0, 10);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(nameBuf.length, 28);
  central.writeUInt32LE(localOffset, 42);
  return Buffer.concat([central, nameBuf]);
}

/** Build a valid minimal DOCX whose body is one paragraph of `text`. */
export function buildMinimalDocx(text: string): Buffer {
  const safe = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const contentTypes = Buffer.from(
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
      + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
      + '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
      + '<Default Extension="xml" ContentType="application/xml"/>'
      + '<Override PartName="/word/document.xml" '
      + 'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
      + '</Types>',
    'utf8',
  );
  const rels = Buffer.from(
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
      + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
      + '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
      + 'Target="word/document.xml"/>'
      + '</Relationships>',
    'utf8',
  );
  const documentXml = Buffer.from(
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
      + '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
      + '<w:body><w:p><w:r><w:t>'
      + safe
      + '</w:t></w:r></w:p></w:body></w:document>',
    'utf8',
  );
  const names: [string, Buffer][] = [
    ['[Content_Types].xml', contentTypes],
    ['_rels/.rels', rels],
    ['word/document.xml', documentXml],
  ];
  const locals: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const [name, data] of names) {
    const local = zipEntry(name, data);
    locals.push(local);
    central.push(zipCentral(name, data, offset));
    offset += local.length;
  }
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(names.length, 8);
  eocd.writeUInt16LE(names.length, 10);
  eocd.writeUInt32LE(Buffer.concat(central).length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, ...central, eocd]);
}
