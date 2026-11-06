# @whenary/protocol

The Whenary E2EE Protocol v2: cryptographic primitives, key derivation paths, envelope formats, and AAD constructors used by Whenary.

Apache-2.0. Runtime dependencies are `@noble/curves`, `@noble/hashes`, and the browser/Node.js WebCrypto API.

## What this package is

Whenary uses end-to-end encryption for calendar events, chat messages, and file attachments. This package contains everything that defines the protocol boundary: the key derivation paths and their info strings, the ciphertext envelope formats, and the AAD constructors that bind a ciphertext to a specific record so it cannot be moved. Publishing it separately means the protocol can be independently implemented, verified, and audited without pulling in the Whenary application stack.

## Installation

```
npm install @whenary/protocol
```

Requires WebCrypto with HKDF and AES-GCM support. Whenary development and verification use Node.js 22.

## Primitives (`@whenary/protocol/primitives`)

```ts
import {
  derivePasswordKek,
  deriveRecoveryKek,
  aesGcmEncrypt,
  aesGcmDecrypt,
  generateIdentityKeyPair,
  identityPublicKey,
  identitySigningPublicKey,
  signBytes,
  verifyBytes,
  sealForRecipient,
  openFromSender,
} from '@whenary/protocol/primitives';
```

[`PROTOCOL.md`](PROTOCOL.md) describes the envelopes, associated data, and key derivation in this package.

## Protocol constants and AAD constructors (`@whenary/protocol/protocol`)

```ts
import {
  identityEpochPayload,
  recordAad,
  notificationAad,
  mediaChunkAad,
  parseE2eeEnvelope,
  CRYPTO_KEY_PURPOSES,
  CRYPTO_PROTOCOL_VECTORS,
} from '@whenary/protocol/protocol';
```

## Conformance test vectors

`test-vectors/protocol-v2.json` contains known-answer vectors. `scripts/gen-vectors.mjs` writes the HKDF, AES-GCM, X25519, and XEdDSA rows. `test/primitives.test.ts` checks the HKDF and AES-GCM rows through this package and recomputes the X25519 row with `@noble/curves`. The X25519 vector uses the Alice/Bob example from RFC 7748 §6.1.

To regenerate vectors from source:

```
node scripts/gen-vectors.mjs > test-vectors/protocol-v2.json
```

## XEdDSA signing

`signBytes` and `identitySigningPublicKey` implement a deterministic variant of the Signal XEdDSA scheme. A Whenary identity key is an X25519 key pair. XEdDSA derives an Ed25519 signing key from the X25519 scalar, allowing a single key pair to serve both functions. Key characteristics of the Whenary variant:

- Deterministic nonce: `r = LE(SHA-512(SHA-512(DOMAIN || privateKey) || message)) mod l`. No random input.
- Sign-bit normalization per XEdDSA spec §3 `calculate_key_pair`: the scalar is negated when `scalar * B` has odd x-coordinate, ensuring the signing public key always has sign bit 0.
- Domain separator: `whenary.identity.xeddsa.v1`
- Signatures are compatible with standard Ed25519 verifiers given the normalized signing public key. `verifyBytes` exposes this as a standalone function.

`identityEpochPayload` is the identity-rotation statement. Sign its UTF-8 bytes with `signBytes`.

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability disclosure policy and the full cryptographic scope.

## License

Apache-2.0. See [`LICENSE`](LICENSE) for the full text (includes patent grant).
