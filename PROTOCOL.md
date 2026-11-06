# Whenary protocol package

This directory is the `@whenary/protocol` package in the Whenary monorepo. A `protocol-v*` tag copies this directory to the public protocol repository. The description below is the behavior of `src/protocol.ts` and `src/primitives.ts` in this package.

The package exports key-derivation helpers, AES-256-GCM envelopes, X25519 identity keys, an XEdDSA signing variant, recipient key sealing, and associated-data constructors. It does not describe account records, server storage, or which process holds a key.

Runtime dependencies in `package.json` are `@noble/curves` and `@noble/hashes`. AES-GCM and HKDF calls use WebCrypto.

## Key purposes

`CRYPTO_KEY_PURPOSES` is the set of HKDF info strings:

| Export                   | Info string                          |
| ------------------------ | ------------------------------------ |
| `passwordKek`            | `whenary.e2ee.kek.password.v1`       |
| `recoveryKek`            | `whenary.e2ee.kek.recovery.v1`       |
| `prfKek`                 | `whenary.e2ee.kek.prf.v1`            |
| `publicLinkKek`          | `whenary.e2ee.kek.public-link.v1`    |
| `ecdhKek`                | `whenary.e2ee.kek.ecdh.v1`           |
| `recordEncryption`       | `whenary.e2ee.record.v2`             |
| `metadataIntegrity`      | `whenary.e2ee.metadata-integrity.v1` |
| `notificationEncryption` | `whenary.e2ee.notification.v1`       |
| `fileEncryption`         | `whenary.e2ee.file.v2`               |
| `aleFieldEncryption`     | `whenary.ale.field.v2`               |
| `blindIndex`             | `whenary.ale.blind-index.v2`         |

`E2EE_PROTOCOL_VERSION` is `2`.

`ALE_LEGACY_PREFIX` is `ale1.` and `ALE_KEYRING_PREFIX` is `ale2.`. This package exports those strings and the two ALE info strings. It does not export an ALE envelope parser.

`MEDIA_BLOB_MAGIC` is `WME2`. `MEDIA_CHUNK_BYTES` is `65536`. This package exports those values. It does not export a media-blob parser.

## HKDF

`hkdf` in `src/primitives.ts` imports the input keying material as WebCrypto HKDF, hash SHA-256, and derives an AES-GCM 256-bit key. The info argument is the purpose string encoded as UTF-8.

`derivePasswordKek(exportKey, salt)` uses info `whenary.e2ee.kek.password.v1`. `deriveRecoveryKek(seed, salt)` uses `whenary.e2ee.kek.recovery.v1`. `derivePrfKek(prfSecret, salt)` uses `whenary.e2ee.kek.prf.v1`. Those three return a non-extractable `CryptoKey`. `SALT_BYTES` is `16`. The functions do not check the salt length.

`derivePurposeKey(parent, purpose)` exports the parent raw key, derives HKDF with a 32-byte zero salt and `purpose` as info, then zeroes the exported parent bytes. The result is non-extractable. `exportPurposeKey` is the same derivation with an extractable key and returns the raw 32 bytes. `MASTER_KEY_BYTES` is `32`.

`importRawAesKey(raw, extractable)` imports a raw AES-GCM 256-bit key. The default `extractable` is false.

`test/primitives.test.ts` checks `derivePasswordKek` and `deriveRecoveryKek` against the `password-kek` and `recovery-kek` rows in `test-vectors/protocol-v2.json` by comparing encryption under the derived key with encryption under the imported OKM. It checks `derivePurposeKey` and `exportPurposeKey` against the `record-purpose-key` row, whose salt in that file is 32 zero bytes and whose info is `whenary.e2ee.record.v2`.

## Inner AES-GCM envelope

`aesGcmEncrypt` draws a 12-byte IV with `crypto.getRandomValues`, encrypts with AES-GCM, and returns:

```text
e1.<base64 iv>.<base64 ciphertext>
```

The ciphertext includes the 16-byte GCM tag. Additional data is the UTF-8 encoding of the string argument when the caller passes one. `aesGcmDecrypt` splits that string on `.`, requires three parts, requires the first part to be `e1`, and decrypts. `wrapKey` and `unwrapKey` call those two functions.

`E2EE_INNER_PREFIX` is `e1` with no trailing dot.

`parseInnerE2eeEnvelope` accepts the same three-part form. The IV segment must be standard base64 that decodes to at least 12 bytes. The ciphertext segment must decode to at least 16 bytes. A value longer than `16 * 1024 * 1024` characters is rejected.

`aesGcmEncrypt` chooses a fresh IV, so it does not reproduce a fixed test-vector IV. `test/primitives.test.ts` decrypts the `aes_256_gcm` row by building `e1.<iv>.<ciphertext>` from that row.

## Record envelopes

`parseE2eeEnvelope` accepts two shapes.

Legacy, version 1, `keyVersion` null:

```text
e2ee1.e1.<base64 iv>.<base64 ciphertext>
```

`E2EE_LEGACY_PREFIX` is `e2ee1.`.

Version 2:

```text
e2ee2.<keyVersion>.<base64 iv>.<base64 ciphertext>
```

`E2EE_RECORD_PREFIX` is `e2ee2.`. `keyVersion` matches `[1-9]` followed by at most nine more digits, and `Number` of that text must be a safe integer. IV and ciphertext use the same base64 minimums as the inner envelope. `serializeE2ee2Envelope` builds the version 2 string and throws if `parseE2eeEnvelope` does not return version 2.

`isE2eeEnvelope` is true when `parseE2eeEnvelope` returns a value. That parser does not accept `e2ee2n.` or `e2ee2meta.`.

## Notification and integrity envelopes

Notification:

```text
e2ee2n.<keyVersion>.<base64 iv>.<base64 ciphertext>
```

`E2EE_NOTIFICATION_PREFIX` is `e2ee2n.`. `parseNotificationEnvelope` rewrites that prefix to `e2ee2.` and uses `parseE2eeEnvelope`. `serializeNotificationEnvelope` throws when that parse fails. `isClientCiphertext` is true for an `isE2eeEnvelope` value or a notification envelope.

Integrity:

```text
e2ee2meta.<keyVersion>.<base64 iv>.<base64 ciphertext>
```

`E2EE_INTEGRITY_PREFIX` is `e2ee2meta.`. `parseIntegrityEnvelope` rewrites that prefix to `e2ee2.` and uses `parseE2eeEnvelope`. `serializeIntegrityEnvelope` concatenates the prefix, key version, IV, and ciphertext. It does not call the parser.

## Associated data

Context parts are joined as `byteLength:text` separated by `|`. `byteLength` is the UTF-8 length of that part. `assertContextPart` rejects an empty part, a part longer than 1024 characters, and a part that contains a code point from U+0000 through U+001F or U+007F.

`recordAad` parts, in order: `whenary.e2ee.record.v2`, `2`, `resource`, `scopeId`, `recordId`, `field`, decimal `keyVersion`. `keyVersion` must be a safe integer greater than or equal to 1. `resource` is one of the `E2eeResourceType` names: `calendar`, `calendar-event`, `event-message`, `checklist-item`, `event-poll`, `availability-poll`, `poll-response`, `space`, `space-message`, `space-list`, `space-list-item`, `space-storage`, `media`.

`CRYPTO_PROTOCOL_VECTORS.recordContext` is:

```text
22:whenary.e2ee.record.v2|1:2|14:calendar-event|6:cal|α|8:event:42|5:title|1:7
```

`cal|α` is length 6 because `α` is two UTF-8 bytes.

`notificationAad` parts: `whenary.e2ee.notification.v1`, `2`, `scopeId`, `recordId`, decimal `keyVersion`. The vector string is:

```text
28:whenary.e2ee.notification.v1|1:2|5:cal-1|7:event-9|1:4
```

`mediaChunkAad` parts: `whenary.e2ee.file.v2`, `2`, `scopeId`, `fileId`, `kind`, decimal `keyVersion`, decimal `chunkIndex`. `kind` is `photo`, `attachment`, `cover`, or `memory`. `chunkIndex` must be a safe integer greater than or equal to 0. The vector string is:

```text
20:whenary.e2ee.file.v2|1:2|5:cal-1|6:file-9|10:attachment|1:3|2:12
```

`metadataIntegrityAad` parts: `whenary.e2ee.metadata-integrity.v1`, `2`, `resource`, `scopeId`, `recordId`, decimal `keyVersion`, then the canonical metadata string. The canonical string must be non-empty and at most `64 * 1024` characters.

`canonicalEventMetadata` builds that string with `encodeContext` over: `start`, `end`, `1` or `0` for `allDay`, `timezone` or an empty string, `rrule` or an empty string, `exdates` sorted and joined with commas, reminders sorted and joined with commas, attendee ids sorted and joined with commas. Each reminder is `method:minutesBefore:intensity`, and a missing intensity is `medium`.

`publicLinkCalendarKeyAad` parts: `whenary.e2ee.kek.public-link.v1`, `2`, `linkId`, `calendarId`, decimal `keyVersion`.

`webauthnPrfEvalSalt(userId)` returns the UTF-8 bytes of `whenary.e2ee.kek.prf.v1:` followed by `userId`. It does not run `assertContextPart`.

## Identity keys and XEdDSA

`generateIdentityKeyPair` uses `x25519.utils.randomPrivateKey` and `x25519.getPublicKey`. `identityPublicKey` is `x25519.getPublicKey`.

`IDENTITY_XEDDSA_DOMAIN` is `whenary.identity.xeddsa.v1`.

`identitySigningPublicKey` and `signBytes` clamp the X25519 private key (`byte0 &= 248`, `byte31 &= 127`, `byte31 |= 64`), interpret it as a little-endian scalar, and multiply the Ed25519 base point. When byte 31 of that point has bit `0x80` set, the scalar is negated and the point is recomputed. `signBytes` then sets:

```text
prefix = SHA-512(domain || privateKey)
r = SHA-512(prefix || message) as a scalar
R = r * B
k = SHA-512(R || signingPublicKey || message) as a scalar
s = r + k * scalar
```

The signature is `R || s`, 64 bytes. `privateKey` in the prefix is the function argument before clamping. `verifyBytes` returns false when the signature length is not 64. Otherwise it checks `s*B - h*A = R` with `h = SHA-512(R || signingPublicKey || message)`, using the signing public key passed in.

`IDENTITY_EPOCH_LABEL` is `whenary:identity-epoch:v1`. `identityEpochPayload` joins six lines with `\n`, in this order: `IDENTITY_EPOCH_LABEL`, `userId`, decimal `previousEpoch`, `previousPublicKey`, `nextPublicKey`, decimal `nextEpoch`. The public-key lines are the strings passed in. The function does not sign. Callers sign `TextEncoder` bytes of that string with `signBytes`. `CRYPTO_PROTOCOL_VECTORS.identityEpoch` is:

```text
whenary:identity-epoch:v1
user-1
3
old-pub
new-pub
4
```

`test/primitives.test.ts` recomputes the `x25519_ecdh` vector. Those private keys are the RFC 7748 section 6.1 values, and the test checks both public keys and both directions of `x25519.getSharedSecret` against `shared_secret` in the file. The `xeddsa` vector is produced by `scripts/gen-vectors.mjs` with the same domain string and the RFC 7748 Alice private key.

## Sealing a key to a recipient

`sealForRecipient(rawKey, recipientPublicKey, aad)` generates an ephemeral X25519 key pair, draws `SALT_BYTES` of salt, derives `whenary.e2ee.kek.ecdh.v1` from `x25519.getSharedSecret(ephemeralPrivate, recipientPublicKey)` and that salt, zeroes the ephemeral private key, and AES-GCM-encrypts `rawKey` under that KEK and `aad`. The result is `{ sealed, ephemeralPublicKey, salt }` with the public key and salt in base64. `sealed` is an `e1` envelope.

`openFromSender` derives the same KEK from the recipient private key and the ephemeral public key, then decrypts.

`zero(bytes)` fills the array with `0`.

## Byte helpers

`randomBytes(length)` fills a new array with `crypto.getRandomValues`. `toBase64` encodes with `btoa` in chunks of `0x8000`. `fromBase64` decodes with `atob`. `hexToBytes` accepts an optional `0x` prefix and parses hex pairs. `stringToBytes` and `bytesToString` are UTF-8 encode and decode.
