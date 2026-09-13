import { describe, expect, it } from 'vitest';
import {
  CRYPTO_KEY_PURPOSES,
  CRYPTO_PROTOCOL_VECTORS,
  canonicalEventMetadata,
  isClientCiphertext,
  isE2eeEnvelope,
  mediaChunkAad,
  metadataIntegrityAad,
  notificationAad,
  parseE2eeEnvelope,
  parseNotificationEnvelope,
  publicLinkCalendarKeyAad,
  recordAad,
  serializeE2ee2Envelope,
  serializeNotificationEnvelope,
  webauthnPrfEvalSalt,
} from '../src/protocol.js';

const IV = 'AAECAwQFBgcICQoL';
const CIPHERTEXT = 'AAECAwQFBgcICQoLDA0ODw==';

describe('crypto protocol contexts', () => {
  it('matches shared known-answer vectors', () => {
    expect(recordAad(CRYPTO_PROTOCOL_VECTORS.recordContext.input)).toBe(
      CRYPTO_PROTOCOL_VECTORS.recordContext.aad,
    );
    expect(mediaChunkAad(CRYPTO_PROTOCOL_VECTORS.mediaChunkContext.input)).toBe(
      CRYPTO_PROTOCOL_VECTORS.mediaChunkContext.aad,
    );
    expect(notificationAad(CRYPTO_PROTOCOL_VECTORS.notificationContext.input)).toBe(
      CRYPTO_PROTOCOL_VECTORS.notificationContext.aad,
    );
  });

  it('prevents delimiter ambiguity and cross-record substitution', () => {
    const base = {
      resource: 'calendar-event' as const,
      scopeId: 'calendar',
      recordId: 'event',
      field: 'title',
      keyVersion: 1,
    };
    expect(recordAad({ ...base, scopeId: 'calendar|event' })).not.toBe(
      recordAad({ ...base, recordId: 'event|event' }),
    );
    expect(recordAad(base)).not.toBe(recordAad({ ...base, recordId: 'other' }));
    const meta = CRYPTO_PROTOCOL_VECTORS.metadataContext.input;
    expect(canonicalEventMetadata(meta)).not.toBe(
      canonicalEventMetadata({ ...meta, start: '2026-09-12T18:01:00.000Z' }),
    );
    expect(
      metadataIntegrityAad(
        { resource: 'calendar-event', scopeId: 'cal', recordId: 'evt', field: 'metadata', keyVersion: 1 },
        canonicalEventMetadata(meta),
      ),
    ).toContain('whenary.e2ee.metadata-integrity.v1');
  });

  it('rejects invalid context components and counters', () => {
    expect(() =>
      recordAad({
        resource: 'calendar-event',
        scopeId: 'calendar',
        recordId: '',
        field: 'title',
        keyVersion: 1,
      }),
    ).toThrow();
    expect(() =>
      mediaChunkAad({
        scopeId: 'calendar',
        fileId: 'file',
        kind: 'photo',
        keyVersion: 1,
        chunkIndex: -1,
      }),
    ).toThrow();
  });
});

describe('crypto protocol envelopes', () => {
  it('parses legacy and v2 envelopes without accepting prefixes alone', () => {
    expect(parseE2eeEnvelope(`e2ee1.e1.${IV}.${CIPHERTEXT}`)).toEqual({
      version: 1,
      keyVersion: null,
      iv: IV,
      ciphertext: CIPHERTEXT,
    });
    expect(parseE2eeEnvelope(`e2ee2.4.${IV}.${CIPHERTEXT}`)).toEqual({
      version: 2,
      keyVersion: 4,
      iv: IV,
      ciphertext: CIPHERTEXT,
    });
    expect(isE2eeEnvelope('e2ee1.')).toBe(false);
    expect(isE2eeEnvelope('e2ee2.')).toBe(false);
  });

  it('treats notification envelopes as client ciphertext', () => {
    const record = `e2ee2.4.${IV}.${CIPHERTEXT}`;
    const notification = serializeNotificationEnvelope(3, IV, CIPHERTEXT);
    expect(isE2eeEnvelope(record)).toBe(true);
    expect(isE2eeEnvelope(notification)).toBe(false);
    expect(isClientCiphertext(record)).toBe(true);
    expect(isClientCiphertext(notification)).toBe(true);
    expect(isClientCiphertext('Team Lunch')).toBe(false);
  });

  it('round-trips validated v2 envelopes', () => {
    const serialized = serializeE2ee2Envelope(8, IV, CIPHERTEXT);
    expect(parseE2eeEnvelope(serialized)?.keyVersion).toBe(8);
    const notification = serializeNotificationEnvelope(3, IV, CIPHERTEXT);
    expect(parseNotificationEnvelope(notification)?.keyVersion).toBe(3);
    expect(parseE2eeEnvelope(notification)).toBeNull();
  });

  it('fails safely for malformed and adversarial envelopes', () => {
    const malformed = [
      null,
      undefined,
      1,
      {},
      '',
      'e2ee1.e1.short.bad',
      `e2ee2.0.${IV}.${CIPHERTEXT}`,
      `e2ee2.01.${IV}.${CIPHERTEXT}`,
      `e2ee2.1.${IV}!.${CIPHERTEXT}`,
      `e2ee2.999999999999999999999.${IV}.${CIPHERTEXT}`,
      `e2ee2.1.${IV}.${CIPHERTEXT}.extra`,
      `e2ee2.1.${'A'.repeat(16 * 1024 * 1024)}.${CIPHERTEXT}`,
    ];
    for (const value of malformed) {
      expect(() => parseE2eeEnvelope(value)).not.toThrow();
      expect(parseE2eeEnvelope(value)).toBeNull();
    }
  });

  it('does not classify deterministic fuzz input as an envelope', () => {
    let state = 0x9e3779b9;
    for (let sample = 0; sample < 2_000; sample += 1) {
      let candidate = '';
      const length = sample % 80;
      for (let i = 0; i < length; i += 1) {
        state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
        candidate += String.fromCharCode(32 + (state % 95));
      }
      expect(parseE2eeEnvelope(candidate)).toBeNull();
    }
  });
});

describe('public-link calendar key AAD', () => {
  it('binds the wrap to the link, calendar, and key version', () => {
    const a = publicLinkCalendarKeyAad(
      '11111111-1111-4111-8111-111111111111',
      '22222222-2222-4222-8222-222222222222',
      1,
    );
    const otherLink = publicLinkCalendarKeyAad(
      '33333333-3333-4333-8333-333333333333',
      '22222222-2222-4222-8222-222222222222',
      1,
    );
    const otherVersion = publicLinkCalendarKeyAad(
      '11111111-1111-4111-8111-111111111111',
      '22222222-2222-4222-8222-222222222222',
      2,
    );
    expect(a).toContain(CRYPTO_KEY_PURPOSES.publicLinkKek);
    expect(a).not.toEqual(otherLink);
    expect(a).not.toEqual(otherVersion);
  });
});

describe('WebAuthn PRF salt', () => {
  it('is deterministic per user and bound to the PRF KEK purpose', () => {
    const a = webauthnPrfEvalSalt('user-1');
    const b = webauthnPrfEvalSalt('user-1');
    const other = webauthnPrfEvalSalt('user-2');
    expect(Buffer.from(a)).toEqual(Buffer.from(b));
    expect(Buffer.from(a)).not.toEqual(Buffer.from(other));
    expect(new TextDecoder().decode(a).startsWith(CRYPTO_KEY_PURPOSES.prfKek)).toBe(true);
  });
});
