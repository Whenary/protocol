import { describe, expect, it } from 'vitest';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import {
  IDENTITY_XEDDSA_DOMAIN,
  aesGcmDecrypt,
  aesGcmEncrypt,
  derivePasswordKek,
  deriveRecoveryKek,
  derivePurposeKey,
  exportPurposeKey,
  fromBase64,
  generateIdentityKeyPair,
  hexToBytes,
  identityPublicKey,
  identitySigningPublicKey,
  importRawAesKey,
  openFromSender,
  randomBytes,
  sealForRecipient,
  signBytes,
  toBase64,
  verifyBytes,
  wrapKey,
  unwrapKey,
} from '../src/primitives.js';
import vectors from '../test-vectors/protocol-v2.json' with { type: 'json' };

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map((n) => n.toString(16).padStart(2, '0')).join('');
}

const RFC7748_ALICE_PRIV = hexToBytes(
  '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
);
const RFC7748_BOB_PRIV = hexToBytes(
  '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
);

async function keysMatch(a: CryptoKey, b: CryptoKey): Promise<boolean> {
  const plain = new Uint8Array(16).fill(0x42);
  const iv = new Uint8Array(12).fill(0x07);
  const aad = new TextEncoder().encode('kat-proof');
  const params: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad as BufferSource };
  const ctA = new Uint8Array(await crypto.subtle.encrypt(params, a, plain as BufferSource));
  const ctB = new Uint8Array(await crypto.subtle.encrypt(params, b, plain as BufferSource));
  return bytesToHex(ctA) === bytesToHex(ctB);
}

describe('HKDF-SHA-256 known-answer vectors', () => {
  it('password KEK derivation is equivalent to importing the known OKM', async () => {
    const vec = vectors.primitives.hkdf_sha256.find((v) => v.id === 'password-kek')!;
    const derived = await derivePasswordKek(hexToBytes(vec.ikm), hexToBytes(vec.salt));
    const expected = await importRawAesKey(hexToBytes(vec.okm));
    expect(await keysMatch(derived, expected)).toBe(true);
  });

  it('recovery KEK derivation is equivalent to importing the known OKM', async () => {
    const vec = vectors.primitives.hkdf_sha256.find((v) => v.id === 'recovery-kek')!;
    const derived = await deriveRecoveryKek(hexToBytes(vec.ikm), hexToBytes(vec.salt));
    const expected = await importRawAesKey(hexToBytes(vec.okm));
    expect(await keysMatch(derived, expected)).toBe(true);
  });

  it('exportPurposeKey produces the frozen record-purpose-key OKM', async () => {
    const vec = vectors.primitives.hkdf_sha256.find((v) => v.id === 'record-purpose-key')!;
    const parent = await importRawAesKey(hexToBytes(vec.ikm), true);
    const raw = await exportPurposeKey(parent, vec.info);
    expect(bytesToHex(raw)).toBe(vec.okm);
  });

  it('derivePurposeKey produces a key equivalent to the frozen record-purpose-key OKM', async () => {
    const vec = vectors.primitives.hkdf_sha256.find((v) => v.id === 'record-purpose-key')!;
    const parent = await importRawAesKey(hexToBytes(vec.ikm), true);
    const derived = await derivePurposeKey(parent, vec.info);
    const expected = await importRawAesKey(hexToBytes(vec.okm));
    expect(await keysMatch(derived, expected)).toBe(true);
  });
});

describe('AES-256-GCM known-answer vectors', () => {
  it('decrypts the protocol-v2.json ciphertext to the expected plaintext', async () => {
    const vec = vectors.primitives.aes_256_gcm[0]!;
    const key = await importRawAesKey(hexToBytes(vec.key));
    const envelope = `e1.${toBase64(hexToBytes(vec.iv))}.${toBase64(hexToBytes(vec.ciphertext))}`;
    const plaintext = await aesGcmDecrypt(key, envelope, vec.aad);
    expect(bytesToHex(plaintext)).toBe(vec.plaintext);
  });

  it('round-trips plaintext through encrypt/decrypt', async () => {
    const rawKey = randomBytes(32);
    const key = await importRawAesKey(rawKey);
    const plain = new TextEncoder().encode('round-trip test');
    const aad = '22:whenary.e2ee.record.v2|1:2|14:calendar-event|6:scope|8:record-1|5:title|1:1';
    const envelope = await aesGcmEncrypt(key, plain, aad);
    const decrypted = await aesGcmDecrypt(key, envelope, aad);
    expect(bytesEqual(decrypted, plain)).toBe(true);
  });

  it('fails decryption when AAD is wrong', async () => {
    const key = await importRawAesKey(randomBytes(32));
    const plain = new TextEncoder().encode('test');
    const envelope = await aesGcmEncrypt(key, plain, 'aad-1');
    await expect(aesGcmDecrypt(key, envelope, 'aad-2')).rejects.toThrow();
  });

  it('fails decryption when key is wrong', async () => {
    const key = await importRawAesKey(randomBytes(32));
    const plain = new TextEncoder().encode('test');
    const envelope = await aesGcmEncrypt(key, plain, 'aad');
    const wrongKey = await importRawAesKey(randomBytes(32));
    await expect(aesGcmDecrypt(wrongKey, envelope, 'aad')).rejects.toThrow();
  });
});

describe('X25519 ECDH known-answer vectors (RFC 7748)', () => {
  it('Alice and Bob derive the same shared secret', () => {
    const vec = vectors.primitives.x25519_ecdh[0]!;
    const alicePub = x25519.getPublicKey(hexToBytes(vec.alice_private));
    const bobPub = x25519.getPublicKey(hexToBytes(vec.bob_private));
    expect(bytesToHex(alicePub)).toBe(vec.alice_public);
    expect(bytesToHex(bobPub)).toBe(vec.bob_public);
    const sharedAB = x25519.getSharedSecret(hexToBytes(vec.alice_private), bobPub);
    const sharedBA = x25519.getSharedSecret(hexToBytes(vec.bob_private), alicePub);
    expect(bytesToHex(sharedAB)).toBe(vec.shared_secret);
    expect(bytesToHex(sharedAB)).toBe(bytesToHex(sharedBA));
  });

  it('sealForRecipient / openFromSender round-trip', async () => {
    const recipient = generateIdentityKeyPair();
    const rawKey = randomBytes(32);
    const aad = 'test-ecdh-seal';
    const { sealed, ephemeralPublicKey, salt } = await sealForRecipient(
      rawKey,
      recipient.publicKey,
      aad,
    );
    const opened = await openFromSender(sealed, ephemeralPublicKey, salt, recipient.privateKey, aad);
    expect(bytesEqual(opened, rawKey)).toBe(true);
  });

  it('sealForRecipient fails to open with wrong private key', async () => {
    const recipient = generateIdentityKeyPair();
    const other = generateIdentityKeyPair();
    const rawKey = randomBytes(32);
    const { sealed, ephemeralPublicKey, salt } = await sealForRecipient(
      rawKey,
      recipient.publicKey,
      'seal-aad',
    );
    await expect(
      openFromSender(sealed, ephemeralPublicKey, salt, other.privateKey, 'seal-aad'),
    ).rejects.toThrow();
  });

  it('sealForRecipient fails to open with wrong AAD', async () => {
    const recipient = generateIdentityKeyPair();
    const rawKey = randomBytes(32);
    const { sealed, ephemeralPublicKey, salt } = await sealForRecipient(
      rawKey,
      recipient.publicKey,
      'aad-original',
    );
    await expect(
      openFromSender(sealed, ephemeralPublicKey, salt, recipient.privateKey, 'aad-tampered'),
    ).rejects.toThrow();
  });
});

describe('Whenary XEdDSA signing: known-answer vector', () => {
  it('identitySigningPublicKey always has sign bit 0', () => {
    const vec = vectors.primitives.xeddsa[0]!;
    const signingPub = identitySigningPublicKey(hexToBytes(vec.private_key));
    expect(signingPub[31]! & 0x80).toBe(0);
    expect(bytesToHex(signingPub)).toBe(vec.signing_pub_key);
  });

  it('signBytes produces the frozen known-answer signature', () => {
    const vec = vectors.primitives.xeddsa[0]!;
    const sig = signBytes(hexToBytes(vec.message), hexToBytes(vec.private_key));
    expect(bytesToHex(sig)).toBe(vec.signature);
  });

  it('verifyBytes confirms the known-answer signature', () => {
    const vec = vectors.primitives.xeddsa[0]!;
    const ok = verifyBytes(
      hexToBytes(vec.message),
      hexToBytes(vec.signature),
      hexToBytes(vec.signing_pub_key),
    );
    expect(ok).toBe(true);
  });

  it('sign + verify round-trip for all key/message combinations', () => {
    const messages = [
      new Uint8Array(0),
      new TextEncoder().encode('a'),
      new TextEncoder().encode('identity rotation payload with unicode: αβγ'),
      randomBytes(1024),
    ];
    for (const msg of messages) {
      const key = generateIdentityKeyPair();
      const signingPub = identitySigningPublicKey(key.privateKey);
      expect(signingPub[31]! & 0x80).toBe(0);
      const sig = signBytes(msg, key.privateKey);
      expect(sig).toHaveLength(64);
      expect(verifyBytes(msg, sig, signingPub)).toBe(true);
    }
  });

  it('verifyBytes rejects tampered message', () => {
    const vec = vectors.primitives.xeddsa[0]!;
    const tampered = hexToBytes(vec.message);
    tampered[0] ^= 0xff;
    expect(verifyBytes(tampered, hexToBytes(vec.signature), hexToBytes(vec.signing_pub_key))).toBe(false);
  });

  it('verifyBytes rejects tampered signature', () => {
    const vec = vectors.primitives.xeddsa[0]!;
    const sig = hexToBytes(vec.signature);
    sig[0] ^= 0xff;
    expect(verifyBytes(hexToBytes(vec.message), sig, hexToBytes(vec.signing_pub_key))).toBe(false);
  });

  it('verifyBytes rejects signature under a different key', () => {
    const vec = vectors.primitives.xeddsa[0]!;
    const otherPub = identitySigningPublicKey(RFC7748_BOB_PRIV);
    expect(verifyBytes(hexToBytes(vec.message), hexToBytes(vec.signature), otherPub)).toBe(false);
  });

  it('ed25519.verify accepts the Whenary XEdDSA signature (standard verifier compatibility)', () => {
    const vec = vectors.primitives.xeddsa[0]!;
    const ok = ed25519.verify(
      hexToBytes(vec.signature),
      hexToBytes(vec.message),
      hexToBytes(vec.signing_pub_key),
    );
    expect(ok).toBe(true);
  });

  it('identitySigningPublicKey round-trips through toMontgomery to the X25519 public key', () => {
    const keys = [
      RFC7748_ALICE_PRIV,
      RFC7748_BOB_PRIV,
      generateIdentityKeyPair().privateKey,
    ];
    for (const priv of keys) {
      const signingPub = identitySigningPublicKey(priv);
      const x25519Pub = identityPublicKey(priv);
      const montgomery = ed25519.utils.toMontgomery(signingPub);
      expect(bytesEqual(montgomery, x25519Pub)).toBe(true);
    }
  });

  it('signBytes is deterministic', () => {
    const msg = new TextEncoder().encode('determinism check');
    const key = generateIdentityKeyPair();
    const sig1 = signBytes(msg, key.privateKey);
    const sig2 = signBytes(msg, key.privateKey);
    expect(bytesEqual(sig1, sig2)).toBe(true);
  });

  it('IDENTITY_XEDDSA_DOMAIN matches the frozen vector domain separator', () => {
    const vec = vectors.primitives.xeddsa[0]!;
    expect(IDENTITY_XEDDSA_DOMAIN).toBe(vec.domain_separator);
  });
});

describe('key wrapping round-trip', () => {
  it('wrapKey / unwrapKey restores the original bytes', async () => {
    const kekRaw = randomBytes(32);
    const kek = await importRawAesKey(kekRaw);
    const secret = randomBytes(32);
    const aad = 'test-wrap-aad';
    const wrapped = await wrapKey(kek, secret, aad);
    const unwrapped = await unwrapKey(kek, wrapped, aad);
    expect(bytesEqual(unwrapped, secret)).toBe(true);
  });

  it('unwrapKey fails with wrong AAD', async () => {
    const kek = await importRawAesKey(randomBytes(32));
    const wrapped = await wrapKey(kek, randomBytes(32), 'real-aad');
    await expect(unwrapKey(kek, wrapped, 'wrong-aad')).rejects.toThrow();
  });
});

describe('base64 encoding round-trip', () => {
  it('toBase64 / fromBase64 round-trip over arbitrary bytes', () => {
    const cases = [
      new Uint8Array(0),
      new Uint8Array(1),
      new Uint8Array([0xff, 0x00, 0xfe, 0x01]),
      randomBytes(256),
    ];
    for (const input of cases) {
      expect(bytesEqual(fromBase64(toBase64(input)), input)).toBe(true);
    }
  });
});
