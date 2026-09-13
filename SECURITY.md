# Security Policy

## Supported Versions

`@whenary/protocol` is currently pre-release (`0.x`). All published versions receive
security updates until the first stable release, at which point only the latest
minor will be supported.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email: **security@whenary.com**

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- Affected versions (if known)

We aim to acknowledge reports within 48 hours and provide a fix or workaround
within 14 days for critical issues.

## Cryptographic Scope

This package implements the Whenary E2EE Protocol v2, which uses:

| Primitive | Construction |
|-----------|-------------|
| Key derivation | HKDF-SHA-256 (RFC 5869) |
| Symmetric encryption | AES-256-GCM (NIST SP 800-38D) |
| Key exchange | X25519 (RFC 7748) |
| Signing | Whenary XEdDSA-SHA-512 (XEdDSA §3 variant) |
| Randomness | WebCrypto `crypto.getRandomValues` |

The XEdDSA signing variant is deterministic (no random nonce) and applies
sign-bit normalization per the Signal XEdDSA specification §3. Signatures are
compatible with standard Ed25519 verifiers given the normalized signing public
key.

## Out of Scope

- Vulnerabilities in dependencies (`@noble/curves`, `@noble/hashes`): report
  those to their respective maintainers.
- Side-channel attacks requiring physical access to the device.
- Vulnerabilities that require a compromised Whenary server (the protocol
  assumes a malicious server can observe ciphertext).

## Acknowledgements

We follow responsible disclosure and will credit reporters in the changelog
unless they prefer to remain anonymous.
