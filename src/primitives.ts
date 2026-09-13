import { ed25519, x25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { CRYPTO_KEY_PURPOSES, E2EE_INNER_PREFIX } from './protocol.js';

export const IDENTITY_XEDDSA_DOMAIN = 'whenary.identity.xeddsa.v1';
export const MASTER_KEY_BYTES = 32;
export const SALT_BYTES = 16;
const IV_BYTES = 12;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function toBase64(bytes: Uint8Array): string {
  const CHUNK = 0x8000;
  let result = '';
  for (let i = 0; i < bytes.length; i += CHUNK) {
    result += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(result);
}

export function fromBase64(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length >> 1);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i << 1, (i << 1) + 2), 16);
  }
  return out;
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

export function stringToBytes(value: string): Uint8Array {
  return textEncoder.encode(value);
}

export function bytesToString(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

function utf8(value: string): Uint8Array {
  return textEncoder.encode(value);
}

async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
  extractable = false,
): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: utf8(info) as BufferSource },
    base,
    { name: 'AES-GCM', length: 256 },
    extractable,
    ['encrypt', 'decrypt'],
  );
}

export function derivePasswordKek(exportKey: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  return hkdf(exportKey, salt, CRYPTO_KEY_PURPOSES.passwordKek);
}

export function deriveRecoveryKek(seed: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  return hkdf(seed, salt, CRYPTO_KEY_PURPOSES.recoveryKek);
}

export function derivePrfKek(prfSecret: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  return hkdf(prfSecret, salt, CRYPTO_KEY_PURPOSES.prfKek);
}

export async function derivePurposeKey(parent: CryptoKey, purpose: string): Promise<CryptoKey> {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', parent));
  try {
    return await hkdf(raw, new Uint8Array(32), purpose);
  } finally {
    raw.fill(0);
  }
}

export async function exportPurposeKey(parent: CryptoKey, purpose: string): Promise<Uint8Array> {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', parent));
  try {
    const derived = await hkdf(raw, new Uint8Array(32), purpose, true);
    return new Uint8Array(await crypto.subtle.exportKey('raw', derived));
  } finally {
    raw.fill(0);
  }
}

export async function importRawAesKey(raw: Uint8Array, extractable = false): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    raw as BufferSource,
    { name: 'AES-GCM', length: 256 },
    extractable,
    ['encrypt', 'decrypt'],
  );
}

export async function aesGcmEncrypt(
  key: CryptoKey,
  plaintext: Uint8Array,
  aad?: string,
): Promise<string> {
  const iv = randomBytes(IV_BYTES);
  const params: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource };
  if (aad) params.additionalData = utf8(aad) as BufferSource;
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt(params, key, plaintext as BufferSource),
  );
  return `${E2EE_INNER_PREFIX}.${toBase64(iv)}.${toBase64(cipher)}`;
}

export async function aesGcmDecrypt(
  key: CryptoKey,
  payload: string,
  aad?: string,
): Promise<Uint8Array> {
  const parts = payload.split('.');
  if (parts.length !== 3 || parts[0] !== E2EE_INNER_PREFIX) {
    throw new Error('Malformed E2EE payload');
  }
  const iv = fromBase64(parts[1]!);
  const cipher = fromBase64(parts[2]!);
  const params: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource };
  if (aad) params.additionalData = utf8(aad) as BufferSource;
  return new Uint8Array(await crypto.subtle.decrypt(params, key, cipher as BufferSource));
}

export async function wrapKey(kek: CryptoKey, rawKey: Uint8Array, aad: string): Promise<string> {
  return aesGcmEncrypt(kek, rawKey, aad);
}

export async function unwrapKey(kek: CryptoKey, wrapped: string, aad: string): Promise<Uint8Array> {
  return aesGcmDecrypt(kek, wrapped, aad);
}

export interface IdentityKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function generateIdentityKeyPair(): IdentityKeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

export function identityPublicKey(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function bytesToNumberLE(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    value = (value << 8n) | BigInt(bytes[i]!);
  }
  return value;
}

function clampX25519(privateKey: Uint8Array): Uint8Array {
  const clamped = new Uint8Array(privateKey);
  clamped[0]! &= 248;
  clamped[31]! &= 127;
  clamped[31]! |= 64;
  return clamped;
}

function xeddsaScalar(privateKey: Uint8Array): { scalar: bigint; signingPub: Uint8Array } {
  const { BASE, Fn } = ed25519.Point;
  const clamped = clampX25519(privateKey);
  const s0 = Fn.create(bytesToNumberLE(clamped));
  const pub0 = BASE.multiply(s0).toBytes();
  if (pub0[31]! & 0x80) {
    const scalar = Fn.create(-bytesToNumberLE(clamped));
    return { scalar, signingPub: BASE.multiply(scalar).toBytes() };
  }
  return { scalar: s0, signingPub: pub0 };
}

export function identitySigningPublicKey(privateKey: Uint8Array): Uint8Array {
  return xeddsaScalar(privateKey).signingPub;
}

export function signBytes(payload: Uint8Array, privateKey: Uint8Array): Uint8Array {
  const { BASE, Fn } = ed25519.Point;
  const { scalar, signingPub } = xeddsaScalar(privateKey);
  const prefix = sha512(concatBytes(new TextEncoder().encode(IDENTITY_XEDDSA_DOMAIN), privateKey));
  const r = Fn.create(bytesToNumberLE(sha512(concatBytes(prefix, payload))));
  const R = BASE.multiply(r).toBytes();
  const k = Fn.create(bytesToNumberLE(sha512(concatBytes(R, signingPub, payload))));
  const s = Fn.create(r + k * scalar);
  return concatBytes(R, Fn.toBytes(s));
}

export function verifyBytes(payload: Uint8Array, signature: Uint8Array, signingPublicKey: Uint8Array): boolean {
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

async function ecdhKek(
  ourPrivate: Uint8Array,
  theirPublic: Uint8Array,
  salt: Uint8Array,
): Promise<CryptoKey> {
  const shared = x25519.getSharedSecret(ourPrivate, theirPublic);
  const kek = await hkdf(shared, salt, CRYPTO_KEY_PURPOSES.ecdhKek);
  shared.fill(0);
  return kek;
}

export async function sealForRecipient(
  rawKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  aad: string,
): Promise<{ sealed: string; ephemeralPublicKey: string; salt: string }> {
  const ephemeral = generateIdentityKeyPair();
  const salt = randomBytes(SALT_BYTES);
  const kek = await ecdhKek(ephemeral.privateKey, recipientPublicKey, salt);
  ephemeral.privateKey.fill(0);
  const sealed = await aesGcmEncrypt(kek, rawKey, aad);
  return {
    sealed,
    ephemeralPublicKey: toBase64(ephemeral.publicKey),
    salt: toBase64(salt),
  };
}

export async function openFromSender(
  sealed: string,
  ephemeralPublicKey: string,
  salt: string,
  ourPrivateKey: Uint8Array,
  aad: string,
): Promise<Uint8Array> {
  const kek = await ecdhKek(ourPrivateKey, fromBase64(ephemeralPublicKey), fromBase64(salt));
  return aesGcmDecrypt(kek, sealed, aad);
}

export function zero(bytes: Uint8Array): void {
  bytes.fill(0);
}
