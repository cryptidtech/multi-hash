# Security Policy

## Overview

The `multi-hash` crate gives self-describing cryptographic hash digests. It follows the [Multihash](https://github.com/multiformats/multihash) specification. This document describes the security properties of the crate.

## std-only Status

The crate is std-only. The hash path holds each hasher as a concrete type in a private `Hasher` enum. The enum dispatches between the hashers without a trait object. The BLAKE3 arm holds a boxed `blake3::Hasher`. The boxed hasher and the digest buffers need the allocator in `std`. A `no_std` conversion is not planned for this crate.

## Security Properties

### Memory Safety

- No unsafe code. `#![deny(unsafe_code)]` is set at the crate root.
- Input validation. All decode paths check lengths and codec identifiers before they allocate.
- Builder validation. The builder checks an XOF output length against `1..=MAX_HASH_LENGTH` (16 MiB) before it allocates or squeezes. A missing length for streamed data returns `Error::OutputLenRequired`. A length of 0 or above `MAX_HASH_LENGTH` returns `Error::OutputLenInvalid`.
- Digest validation. `try_build` validates the digest against the codec output policy at build time. A fixed-output codec requires its exact policy length.
- DoS protection. The `Varbytes` decode path sets the hash digest length. It enforces a decoded-size cap (16 MiB) and buffer-length checks. This mitigates CWE-400 and CWE-125.

### Constant-Time Comparison

`Multihash` derives `PartialEq`. The derived `PartialEq` uses a short-circuiting byte comparison. It is not constant-time. Do not use it for timing-sensitive comparisons, such as verification of a hash from an untrusted party.

The crate gives `impl subtle::ConstantTimeEq for Multihash`. It compares the `codec`, the hash length, and the hash bytes in constant time. Use `mh.ct_eq(&other)` when timing leaks are a risk.

### Supported Algorithms

`SAFE_HASH_CODECS` lists 10 recommended codecs. They include the BLAKE2 and BLAKE3 algorithms, the SHA-3 family, and the `Shake128` and `Shake256` extendable-output functions (XOF). An XOF accepts a caller-chosen digest length from 1 to `MAX_HASH_LENGTH` bytes. `MAX_HASH_LENGTH` is 16 MiB. The check runs in `try_build` before any allocation or squeeze.

The sponge capacity fixes the security strength of an XOF. The chosen output length bounds collision resistance. Use at least 32 bytes for `Blake3` and `Shake128`, and at least 64 bytes for `Shake256`. Longer BLAKE3 outputs give no additional security. A different digest length encodes as a distinct multihash. A built `Multihash` digest cannot extend. A different length needs a rehash through a fresh builder.

The legacy algorithms (SHA1, MD5, RIPEMD) are for compatibility only. Do not use them in new cryptographic constructions.

With the `fips` feature, the crate exports `FIPS_CODECS` (13 codecs) and `SAFE_FIPS_CODECS` (8 codecs). They list the NIST FIPS approved hash algorithms. BLAKE2, BLAKE3, MD5, and RIPEMD are not FIPS approved. SHA-1 is verification-only under NIST SP 800-131A Rev. 2. The SP 800-131A Rev. 3 draft deprecates SHA-1 and the 224-bit hashes through 2030 and disallows them after 2030. `SAFE_FIPS_CODECS` omits SHA-1 and the restricted 224-bit algorithms, and it also omits SHA-512/256, for the same reason as `SAFE_HASH_CODECS`.

## Reporting Vulnerabilities

Report security issues through the GitHub issue tracker. You can also report them privately to the maintainers.

## CI

The CI workflow runs these jobs. `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`, an MSRV job (1.85), `cargo audit`, and a `coverage` job. The coverage job uses `cargo-llvm-cov` and uploads the result to Codecov. There is no `no_std` job. The crate is std-only (see [std-only Status](#std-only-status)).