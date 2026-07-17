# Security Policy

## Overview

The `multi-hash` crate provides self-describing cryptographic hash digests
following the [Multihash](https://github.com/multiformats/multihash)
specification. This document outlines the security properties, threat model,
and guarantees of this crate.

## std-only Status

This crate is **std-only**. It depends on the `digest` crate's `DynDigest`
trait (which requires `Box<dyn DynDigest>` and thus `std::alloc` + `std`'s
box support), and `unsigned-varint` with the `std` feature. A `no_std`
conversion is not planned for this crate.

## Security Properties

### Memory Safety

- **No unsafe code**: `#![deny(unsafe_code)]` is enforced at compile time.
- **Input validation**: All decode paths validate lengths and codec
  identifiers before allocation.
- **DoS protection**: `Varbytes` decode (used for the hash digest length)
  enforces `MAX_DECODED_SIZE` (16 MiB) and buffer-length checks, mitigating
  CWE-400 (Uncontrolled Resource Consumption) and CWE-125 (Out-of-bounds
  Read).

### Constant-Time Comparison

`Multihash` derives `PartialEq`, which uses a short-circuiting byte
comparison. This is **not** constant-time and is unsuitable for
timing-sensitive comparisons (e.g. verifying a hash received from an
untrusted party).

The crate provides `impl subtle::ConstantTimeEq for Multihash`, which
compares the `codec`, hash length, and hash bytes in constant time. Use
`mh.ct_eq(&other)` in any context where timing leaks could be exploited.

### Supported Algorithms

See `SAFE_HASH_CODECS` for cryptographically recommended algorithms.
Legacy algorithms (SHA1, MD5, RIPEMD) are provided for compatibility only
and should not be used in new cryptographic constructions.

## Reporting Vulnerabilities

Report security issues via the project's GitHub issue tracker or privately
to the maintainers.