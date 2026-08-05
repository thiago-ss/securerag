/**
 * Injection-detection seam (ADR-0006 layer 7, research r6 §Detector options).
 *
 * Detection is DEFENSE-IN-DEPTH ONLY: it is a *signal* that feeds quarantine
 * and audit policy, never a gate on authorization. Turning detection off (or a
 * detector outage) changes nothing about RLS/ACL enforcement, refusal, or
 * egress. This contract has two adapters:
 *
 *  1. HeuristicInjectionDetector — deterministic, in-process, model-free.
 *     NFKC + zero-width/whitespace stripping + casefolding + a small
 *     confusable fold, then pattern sets (instruction-like phrases,
 *     markup/script, exfil markers, base64/percent/unicode encoding tricks,
 *     control markers) with decode-and-rescan. Used in CI, tests, and demo.
 *  2. A real classifier adapter (self-hosted Llama Guard / llm-guard) behind
 *     the SAME interface — documented in docs/research/r6-injection-detection.md
 *     and docs/adr/0006-injection-policy.md; kept OUT of CI because it is
 *     probabilistic and model-dependent. It must implement scan(): Promise<{
 *     risk: 'none'|'high'; reasons: string[] }> and never throw on input.
 *
 * `reasons` carries pattern ids only (never query/doc text), so reports and
 * audit events cannot leak content by construction.
 */

export interface InjectionScanResult {
  /** 'high' for any deterministic high-risk signal; 'none' otherwise. */
  risk: 'none' | 'high';
  /** Deterministic, deduplicated pattern ids (stable order). */
  reasons: string[];
}

export interface InjectionDetector {
  scan(text: string): Promise<InjectionScanResult>;
}

/** Lower-case confusable fold for the most common homoglyph families
 * (Cyrillic + Greek vs Latin). NOT full Unicode confusables data; the fold is
 * intentionally small and deterministic (research r6: confusable folding is
 * pattern-layer hardening, not a security boundary). */
const CONFUSABLES: Record<string, string> = {
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', х: 'x', у: 'y', н: 'h', т: 't',
  к: 'k', м: 'm', в: 'b', г: 'r', з: '3', ѕ: 's', і: 'i', ій: 'i',
  Α: 'a', Ε: 'e', Ο: 'o', Ρ: 'p', С: 'c', Х: 'x', Υ: 'y', Н: 'h', Т: 't',
  Κ: 'k', Μ: 'm', Β: 'b',
};

function foldConfusables(value: string): string {
  let out = '';
  for (const ch of value) {
    out += CONFUSABLES[ch] ?? ch;
  }
  return out;
}

const ZERO_WIDTH_RE = /[\u200b-\u200f\u2060\ufeff]/g;
const BIDI_RE = /[\u202a-\u202e]/;

/** Long contiguous base64-ish run (>= 16 chars, padding optional) — a flag for
 * encoded instruction blobs (research r6 §Encoding-attack notes). */
const BASE64_RUN_RE = /[A-Za-z0-9+/]{16,}={0,2}/g;
const PERCENT_ESCAPE_RE = /%[0-9a-fA-F]{2}/g;

/** Instruction-like phrases, matched AFTER normalization (NFKC, casefold,
 * confusable fold, zero-width/whitespace collapse). Whitespace-tolerant: any
 * run of whitespace inside the phrase matches. Deterministic order of this
 * list defines the `reasons` order. */
const INSTRUCTION_PATTERNS: { id: string; re: RegExp }[] = [
  { id: 'instruction:ignore-previous', re: /ignore\s+(?:all\s+)?previous\s+instructions?/ },
  { id: 'instruction:ignore-above', re: /ignore\s+the\s+instructions?\s+(?:above|aforementioned|previous)/ },
  { id: 'instruction:system-prompt', re: /system\s*prompt\s*:/ },
  { id: 'instruction:unconstrained', re: /you\s+are\s+now\s+(?:unconstrained|without\s+(?:restrictions?|constraints))/ },
  { id: 'instruction:reveal-documents', re: /reveal\s+(?:every|all(?:\s+the)?)\s*documents?/ },
  { id: 'instruction:print-secrets', re: /print\s+(?:all\s+)?secrets?/ },
  { id: 'instruction:list-every-document', re: /list\s+every\s+document/ },
  { id: 'instruction:output-contents', re: /output\s+the\s+contents?\s+of/ },
  { id: 'instruction:exfil-path', re: /(?:etc\/passwd|etc\/shadow|\.ssh\/|\.aws\/|\.env)/ },
  { id: 'instruction:printf', re: /\bprintf\b/ },
];

/** Markup / script-embedding markers (OWASP LLM08 hidden-text class). */
const MARKUP_PATTERNS: { id: string; re: RegExp }[] = [
  { id: 'markup:script', re: /<\/?script/ },
  { id: 'markup:fetch', re: /fetch\s*\(/ },
  { id: 'markup:eval', re: /\beval\s*\(/ },
  { id: 'markup:document-access', re: /document\.(?:cookie|title|body|location|querySelector|getElementById)/ },
  { id: 'markup:innerhtml', re: /innerhtml\s*=/ },
  { id: 'markup:onerror', re: /\bonerror\s*=/ },
  { id: 'markup:javascript-url', re: /javascript\s*:/ },
];

/** Scheme / exfiltration markers. */
const SCHEME_PATTERNS: { id: string; re: RegExp }[] = [
  { id: 'scheme:base64-url', re: /base64:\/\// },
  { id: 'scheme:data-url', re: /data:(?:text|application|image)\// },
  { id: 'exfil:keyword', re: /exfil(?:trat\w*)?/ },
  { id: 'exfil:paste-service', re: /(?:pastebin|dpaste|webhook\.site|requestbin\.com|interact\.sh|oast\.)/ },
];

/** Control / encoding markers on the RAW text (before normalization): their
 * PRESENCE is itself the signal. */
const RAW_PATTERNS: { id: string; re: RegExp }[] = [
  { id: 'encoding:zero-width', re: ZERO_WIDTH_RE },
  { id: 'encoding:bidi-override', re: BIDI_RE },
];

/** Whitespace collapse: every run of whitespace (incl. non-breaking/unicode
 * spaces after NFKC) becomes a single ASCII space. */
const WHITESPACE_COLLAPSE_RE = /\s+/g;

const BASE64_RUN = /^[A-Za-z0-9+/]+={0,2}$/;

function stripAndCollapse(value: string): string {
  return value.replace(ZERO_WIDTH_RE, '').replace(WHITESPACE_COLLAPSE_RE, ' ').trim();
}

function normalize(value: string): string {
  const nfkc = value.normalize('NFKC');
  return foldConfusables(nfkc).toLowerCase();
}

function scanPatterns(normalized: string, patterns: { id: string; re: RegExp }[]): string[] {
  const found: string[] = [];
  for (const p of patterns) {
    if (p.re.test(normalized)) found.push(p.id);
  }
  return found;
}

/**
 * Deterministic heuristic injection detector (ADR-0006 detector seam (a);
 * research r6 recommended core). Fully synchronous logic behind the async
 * interface so a real classifier adapter can be dropped in without changing
 * callers. Deterministic for CI: no randomness, no time, stable reason order.
 */
export class HeuristicInjectionDetector implements InjectionDetector {
  async scan(text: string): Promise<InjectionScanResult> {
    const reasons = scanPatterns(text, RAW_PATTERNS);

    // Encoding tricks run on the NFKC form BEFORE casefolding: base64 is
    // case-sensitive, so decoding must not see the lowercased text.
    const nfkc = text.normalize('NFKC');
    const base64Runs = nfkc.match(BASE64_RUN_RE) ?? [];
    for (const run of base64Runs) {
      if (BASE64_RUN.test(run)) {
        reasons.push('encoding:base64-run');
        const decoded = decodeBase64OrNull(run);
        if (decoded !== null) {
          const decodedNorm = stripAndCollapse(normalize(decoded));
          reasons.push(...scanPatterns(decodedNorm, INSTRUCTION_PATTERNS));
          reasons.push(...scanPatterns(decodedNorm, MARKUP_PATTERNS));
          reasons.push(...scanPatterns(decodedNorm, SCHEME_PATTERNS));
        }
      }
    }

    const percentEscapes = nfkc.match(PERCENT_ESCAPE_RE) ?? [];
    if (percentEscapes.length >= 3) reasons.push('encoding:percent-encoded');
    const percentDecoded = percentDecodeOrNull(nfkc);
    if (percentDecoded !== null) {
      const decodedNorm = stripAndCollapse(normalize(percentDecoded));
      reasons.push(...scanPatterns(decodedNorm, INSTRUCTION_PATTERNS));
    }

    // Instruction/markup/scheme patterns on the folded, casefolded,
    // whitespace-collapsed text (whitespace/zero-width-split phrases).
    const normalized = stripAndCollapse(normalize(nfkc));
    reasons.push(...scanPatterns(normalized, INSTRUCTION_PATTERNS));
    reasons.push(...scanPatterns(normalized, MARKUP_PATTERNS));
    reasons.push(...scanPatterns(normalized, SCHEME_PATTERNS));

    const unique = [...new Set(reasons)];
    return {
      risk: unique.length > 0 ? 'high' : 'none',
      reasons: unique,
    };
  }
}

function decodeBase64OrNull(value: string): string | null {
  try {
    const normalizedPadding = value.replace(/=+$/, '').padEnd(Math.ceil(value.replace(/=+$/, '').length / 4) * 4, '=');
    const decoded = Buffer.from(normalizedPadding, 'base64').toString('utf8');
    if (decoded.length === 0 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(decoded)) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

function percentDecodeOrNull(value: string): string | null {
  if (!/%.{2}/.test(value)) return null;
  try {
    const decoded = decodeURIComponent(value);
    return decoded === value ? null : decoded;
  } catch {
    return null;
  }
}

/** Stateless singleton for CI/demo wiring (ADR-0006: heuristic adapter used in
 * CI and demo; the classifier adapter stays out of CI). */
export const HEURISTIC_INJECTION_DETECTOR = new HeuristicInjectionDetector();
