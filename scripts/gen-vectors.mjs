#!/usr/bin/env node
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function bytesToNumberLE(bytes) {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

function clampX25519(key) {
  const c = new Uint8Array(key);
  c[0] &= 248; c[31] &= 127; c[31] |= 64;
  return c;
}

function utf8(s) { return new TextEncoder().encode(s); }

async function hkdfRaw(ikm, salt, info) {
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: utf8(info) },
    base, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'],
  );
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

async function aesGcmEncryptFixed(rawKey, iv, plaintext, aad) {
  const key = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const params = { name: 'AES-GCM', iv };
  if (aad) params.additionalData = utf8(aad);
  return new Uint8Array(await crypto.subtle.encrypt(params, key, plaintext));
}

async function aesGcmDecryptFixed(rawKey, iv, ciphertext, aad) {
  const key = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const params = { name: 'AES-GCM', iv };
  if (aad) params.additionalData = utf8(aad);
  return new Uint8Array(await crypto.subtle.decrypt(params, key, ciphertext));
}

const DOMAIN = 'whenary.identity.xeddsa.v1';

function xeddsaScalar(privateKey) {
  const { BASE, Fn } = ed25519.Point;
  const clamped = clampX25519(privateKey);
  const s0 = Fn.create(bytesToNumberLE(clamped));
  const pub0 = BASE.multiply(s0).toBytes();
  if (pub0[31] & 0x80) {
    const scalar = Fn.create(-bytesToNumberLE(clamped));
    return { scalar, signingPub: BASE.multiply(scalar).toBytes() };
  }
  return { scalar: s0, signingPub: pub0 };
}

function xeddsaSign(payload, privateKey) {
  const { BASE, Fn } = ed25519.Point;
  const { scalar, signingPub } = xeddsaScalar(privateKey);
  const prefix = sha512(concatBytes(utf8(DOMAIN), privateKey));
  const r = Fn.create(bytesToNumberLE(sha512(concatBytes(prefix, payload))));
  const R = BASE.multiply(r).toBytes();
  const k = Fn.create(bytesToNumberLE(sha512(concatBytes(R, signingPub, payload))));
  const s = Fn.create(r + k * scalar);
  return concatBytes(R, Fn.toBytes(s));
}

function xeddsaSigningPublicKey(privateKey) {
  return xeddsaScalar(privateKey).signingPub;
}

function xeddsaVerify(payload, signature, signingPublicKey) {
  if (signature.length !== 64) return false;
  const { BASE, Fn } = ed25519.Point;
  try {
    const R = ed25519.Point.fromHex(signature.subarray(0, 32));
    const s = Fn.create(bytesToNumberLE(signature.subarray(32, 64)));
    const A = ed25519.Point.fromHex(signingPublicKey);
    const h = Fn.create(bytesToNumberLE(sha512(concatBytes(signature.subarray(0, 32), signingPublicKey, payload))));
    return BASE.multiply(s).subtract(A.multiply(h)).equals(R);
  } catch {
    return false;
  }
}

const RFC7748_ALICE_PRIV = hexToBytes('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
const RFC7748_BOB_PRIV   = hexToBytes('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');

const FIXED_SALT_16 = hexToBytes('0102030405060708090a0b0c0d0e0f10');
const FIXED_IV_12   = hexToBytes('0102030405060708090a0b0c');
const PLAINTEXT     = utf8('hello from whenary protocol v2');
const AAD_STRING    = '22:whenary.e2ee.record.v2|1:2|14:calendar-event|6:cal|α|8:event:42|5:title|1:7';
const MESSAGE       = utf8('whenary xeddsa test message v2');

async function main() {
  const hkdfPasswordKek = await hkdfRaw(
    hexToBytes('0101010101010101010101010101010101010101010101010101010101010101'),
    FIXED_SALT_16,
    'whenary.e2ee.kek.password.v1',
  );
  const hkdfRecoveryKek = await hkdfRaw(
    hexToBytes('0202020202020202020202020202020202020202020202020202020202020202'),
    FIXED_SALT_16,
    'whenary.e2ee.kek.recovery.v1',
  );
  const hkdfRecordPurpose = await hkdfRaw(
    hexToBytes('0303030303030303030303030303030303030303030303030303030303030303'),
    new Uint8Array(32),
    'whenary.e2ee.record.v2',
  );

  const aesKey = hkdfPasswordKek;
  const aesCiphertext = await aesGcmEncryptFixed(aesKey, FIXED_IV_12, PLAINTEXT, AAD_STRING);
  const aesDecrypted = await aesGcmDecryptFixed(aesKey, FIXED_IV_12, aesCiphertext, AAD_STRING);
  if (bytesToHex(aesDecrypted) !== bytesToHex(PLAINTEXT)) throw new Error('AES round-trip failed');

  const alicePub = x25519.getPublicKey(RFC7748_ALICE_PRIV);
  const bobPub   = x25519.getPublicKey(RFC7748_BOB_PRIV);
  const sharedAtoB = x25519.getSharedSecret(RFC7748_ALICE_PRIV, bobPub);
  const sharedBtoA = x25519.getSharedSecret(RFC7748_BOB_PRIV, alicePub);
  if (bytesToHex(sharedAtoB) !== bytesToHex(sharedBtoA)) throw new Error('ECDH asymmetry');
  if (bytesToHex(sharedAtoB) !== '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742') {
    throw new Error('RFC 7748 X25519 mismatch: ' + bytesToHex(sharedAtoB));
  }

  const ecdhKek = await hkdfRaw(sharedAtoB, FIXED_SALT_16, 'whenary.e2ee.kek.ecdh.v1');

  const signingPub = xeddsaSigningPublicKey(RFC7748_ALICE_PRIV);
  const sig = xeddsaSign(MESSAGE, RFC7748_ALICE_PRIV);
  if (!xeddsaVerify(MESSAGE, sig, signingPub)) throw new Error('XEdDSA verify failed');
  if (xeddsaVerify(utf8('wrong'), sig, signingPub)) throw new Error('XEdDSA verify accepted wrong message');
  if (xeddsaVerify(MESSAGE, sig, xeddsaSigningPublicKey(RFC7748_BOB_PRIV))) {
    throw new Error('XEdDSA verify accepted wrong key');
  }

  const vectors = {
    version: '2',
    description: 'Whenary E2EE Protocol v2: known-answer test vectors',
    note: 'XEdDSA variant. Deterministic nonce via SHA-512(DOMAIN||key||msg). Sign-bit normalization per spec §3.',
    primitives: {
      hkdf_sha256: [
        {
          id: 'password-kek',
          description: 'HKDF-SHA-256 password KEK derivation',
          ikm:  bytesToHex(hexToBytes('0101010101010101010101010101010101010101010101010101010101010101')),
          salt: bytesToHex(FIXED_SALT_16),
          info: 'whenary.e2ee.kek.password.v1',
          length: 32,
          okm:  bytesToHex(hkdfPasswordKek),
        },
        {
          id: 'recovery-kek',
          description: 'HKDF-SHA-256 recovery KEK derivation',
          ikm:  bytesToHex(hexToBytes('0202020202020202020202020202020202020202020202020202020202020202')),
          salt: bytesToHex(FIXED_SALT_16),
          info: 'whenary.e2ee.kek.recovery.v1',
          length: 32,
          okm:  bytesToHex(hkdfRecoveryKek),
        },
        {
          id: 'record-purpose-key',
          description: 'HKDF-SHA-256 purpose key derivation with zero salt',
          ikm:  bytesToHex(hexToBytes('0303030303030303030303030303030303030303030303030303030303030303')),
          salt: bytesToHex(new Uint8Array(32)),
          info: 'whenary.e2ee.record.v2',
          length: 32,
          okm:  bytesToHex(hkdfRecordPurpose),
        },
      ],
      aes_256_gcm: [
        {
          id: 'record-encrypt',
          description: 'AES-256-GCM encryption with record AAD',
          key:        bytesToHex(aesKey),
          iv:         bytesToHex(FIXED_IV_12),
          plaintext:  bytesToHex(PLAINTEXT),
          aad:        AAD_STRING,
          ciphertext: bytesToHex(aesCiphertext),
          note: 'ciphertext includes 16-byte GCM authentication tag appended',
        },
      ],
      x25519_ecdh: [
        {
          id: 'rfc7748-alice-bob',
          description: 'X25519 ECDH from RFC 7748 Section 6.1',
          alice_private: bytesToHex(RFC7748_ALICE_PRIV),
          alice_public:  bytesToHex(alicePub),
          bob_private:   bytesToHex(RFC7748_BOB_PRIV),
          bob_public:    bytesToHex(bobPub),
          shared_secret: bytesToHex(sharedAtoB),
          ecdh_kek: {
            salt: bytesToHex(FIXED_SALT_16),
            info: 'whenary.e2ee.kek.ecdh.v1',
            okm:  bytesToHex(ecdhKek),
          },
        },
      ],
      xeddsa: [
        {
          id: 'alice-sign-message',
          description: 'Whenary XEdDSA: sign + verify using RFC 7748 Alice key',
          domain_separator: DOMAIN,
          private_key:     bytesToHex(RFC7748_ALICE_PRIV),
          signing_pub_key: bytesToHex(signingPub),
          message:         bytesToHex(MESSAGE),
          signature:       bytesToHex(sig),
          note: 'Deterministic nonce: r = LE(SHA-512(SHA-512(DOMAIN||key) || message)) mod l. Sign-bit normalized per spec.',
        },
      ],
    },
  };

  console.log(JSON.stringify(vectors, null, 2));
}

main().catch((err) => { console.error(err); process.exit(1); });
