/**
 * PII detector + redactor unit tests (S4, ADR-0005). The patterns are the
 * byte-level contract with the ST canary corpus: email regex, `+1-555-\d{8}`
 * phone, dashed SSN, spaced Luhn-verified card.
 */
import { describe, expect, it } from 'vitest';
import {
  DeterministicPiiDetector,
  PII_TOKENS,
  luhnValid,
  redactText,
  type PiiMatch,
} from '../src/pii.js';

const detector = new DeterministicPiiDetector();

function spans(matches: PiiMatch[]): [string, number, number][] {
  return matches.map((m) => [m.type, m.start, m.end]);
}

describe('DeterministicPiiDetector', () => {
  it('detects EMAIL with exact corpus alignment', () => {
    const text = 'Client contact: ops.ab12cd34@synthetic.example phone';
    expect(spans(detector.detect(text))).toEqual([['EMAIL', 16, 46]]);
  });

  it('does not flag lookalike non-email strings', () => {
    expect(detector.detect('no at-symbol ops.ab12cd34 synthetic.example')).toEqual([]);
    expect(detector.detect('mailto with space ops.ab12cd34 @ synthetic.example')).toEqual([]);
    expect(detector.detect('ops.ab12cd34@example.c')).toEqual([]);
  });

  it('detects PHONE in the +1-555-<8 digits> corpus format', () => {
    expect(spans(detector.detect('call +1-555-12345678 now'))).toEqual([['PHONE', 5, 20]]);
  });

  it('does not flag phone lookalikes (short runs, other prefixes)', () => {
    expect(detector.detect('+1-555-1234')).toEqual([]);
    expect(detector.detect('+1-555-123456789')).toEqual([]);
    expect(detector.detect('+1-999-12345678')).toEqual([]);
    expect(detector.detect('555-1234')).toEqual([]);
  });

  it('detects dashed SSN in the \d{3}-\d{2}-\d{4} corpus format', () => {
    expect(spans(detector.detect('SSN 700-05-1000 card'))).toEqual([['SSN', 4, 15]]);
  });

  it('does not flag non-dashed or boundary-crossing numbers', () => {
    expect(detector.detect('700051000')).toEqual([]);
    expect(detector.detect('12345-678')).toEqual([]);
    expect(detector.detect('0700-05-1000')).toEqual([]);
  });

  it('detects a spaced card only when the Luhn checksum verifies', () => {
    // 4111 1111 1111 1111 is the canonical Luhn-valid test card.
    expect(spans(detector.detect('card 4111 1111 1111 1111 end'))).toEqual([
      ['CREDIT_CARD', 5, 24],
    ]);
    // Same shape, invalid checksum: not a card (Luhn gate).
    expect(detector.detect('card 4111 1111 1111 1112 end')).toEqual([]);
    // Non-4 prefix is out of class even when Luhn-valid.
    expect(detector.detect('card 5500 0000 0000 0004 end')).toEqual([]);
    // Runs of the right length but wrong grouping are not cards.
    expect(detector.detect('4111 1111 1111 111')).toEqual([]);
  });

  it('reports one match per distinct span, sorted by start', () => {
    const text = 'SSN 700-05-1000 then 123-45-6789';
    const matches = detector.detect(text);
    expect(matches).toHaveLength(2);
    expect(matches[0]!.start).toBeLessThan(matches[1]!.start);
  });

  it('detects all four classes in the canary corpus line in one pass', () => {
    const line =
      'Client contact: ops.ab12cd34@synthetic.example phone +1-555-12345678 ' +
      'SSN 700-05-1000 card 4111 1111 1111 1111 reference CANARY-c-deadbeef';
    const matches = detector.detect(line);
    const types = matches.map((m) => m.type).sort();
    expect(types).toEqual(['CREDIT_CARD', 'EMAIL', 'PHONE', 'SSN']);
    // spans are contiguous and non-overlapping
    for (let i = 1; i < matches.length; i += 1) {
      expect(matches[i]!.start).toBeGreaterThanOrEqual(matches[i - 1]!.end);
    }
  });
});

describe('redactText (one-way class-token replacement)', () => {
  it('replaces every match span with its canonical class token', () => {
    const text = 'Client contact: ops.ab12cd34@synthetic.example SSN 700-05-1000 card 4111 1111 1111 1111';
    const redacted = redactText(text, detector.detect(text));
    expect(redacted).toBe(
      'Client contact: [EMAIL] SSN [SSN] card [CREDIT_CARD]',
    );
  });

  it('leaves non-PII text byte-identical (no-op redaction)', () => {
    expect(redactText('operational notes reference CANARY-c-abc', detector.detect('operational notes reference CANARY-c-abc'))).toBe(
      'operational notes reference CANARY-c-abc',
    );
  });

  it('is one-way: the original value is not recoverable from the output', () => {
    const text = 'email ops.ab12cd34@synthetic.example';
    const redacted = redactText(text, detector.detect(text));
    expect(redacted).not.toContain('ops.ab12cd34@synthetic.example');
    expect(redacted).toContain('[EMAIL]');
  });

  it('maps every class to its reserved token', () => {
    expect(PII_TOKENS).toEqual({
      EMAIL: '[EMAIL]',
      PHONE: '[PHONE]',
      SSN: '[SSN]',
      CREDIT_CARD: '[CREDIT_CARD]',
    });
  });

  it('handles matches passed out of order and zero matches', () => {
    const text = 'a ops.x@synthetic.example b 700-05-1000 c';
    const outOfOrder: PiiMatch[] = [
      { type: 'SSN', start: 28, end: 39, value: '700-05-1000' },
      { type: 'EMAIL', start: 2, end: 25, value: 'ops.x@synthetic.example' },
    ];
    expect(redactText(text, outOfOrder)).toBe('a [EMAIL] b [SSN] c');
    expect(redactText(text, [])).toBe(text);
  });
});

describe('luhnValid', () => {
  it('accepts valid checksums and rejects invalid ones', () => {
    expect(luhnValid('4111111111111111')).toBe(true);
    expect(luhnValid('4111111111111112')).toBe(false);
    expect(luhnValid('5500000000000004')).toBe(true);
    expect(luhnValid('')).toBe(false);
    expect(luhnValid('4111x111111111111')).toBe(false);
  });
});
