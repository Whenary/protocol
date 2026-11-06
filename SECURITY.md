# Security Policy

## Supported Versions

`@whenary/protocol` is pre-release (`0.x`). Use the latest published release.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email: **security@whenary.com**

Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- Affected versions (if known)

Report handling depends on severity and the work required to investigate and fix the issue. There is no guaranteed response or resolution time.

## Cryptographic Scope

This package implements the Whenary E2EE Protocol v2, which uses:

| Primitive            | Construction                               |
| -------------------- | ------------------------------------------ |
| Key derivation       | HKDF-SHA-256 (RFC 5869)                    |
| Symmetric encryption | AES-256-GCM (NIST SP 800-38D)              |
| Key exchange         | X25519 (RFC 7748)                          |
| Signing              | Whenary XEdDSA-SHA-512 (XEdDSA §3 variant) |
| Randomness           | WebCrypto `crypto.getRandomValues`         |

The XEdDSA signing variant is deterministic (no random nonce) and applies
sign-bit normalization per the Signal XEdDSA specification §3. Signatures are
compatible with standard Ed25519 verifiers given the normalized signing public
key.

The server can observe ciphertext and unencrypted scheduling metadata. Reports of access to protected plaintext, key substitution, or broken record binding are in scope.

## Dependency and Device Reports

- Report dependency-only vulnerabilities to the dependency maintainer; include any Whenary-specific impact in a report to security@whenary.com.
- For device-side attacks, include the device access and operating-system privileges required.

## Acknowledgements

Disclosure and attribution are coordinated with the reporter.
