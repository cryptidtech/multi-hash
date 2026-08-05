# Security Policy

## Overview

The `multi-hash` crate gives self-describing cryptographic hash digests. It follows the [Multihash](https://github.com/multiformats/multihash) specification. This document describes the security properties of the crate.

## std-only Status

The crate is std-only. It depends on the `DynDigest` trait from the `digest` crate. `DynDigest` needs `Box<dyn DynDigest>`, which needs `std::alloc` and `std` box support. The crate also uses `unsigned-varint` with the `std` feature. A `no_std` conversion is not planned for this crate.

## Security Properties

### Memory Safety

- No unsafe code. `#![deny(unsafe_code)]` is set at the crate root.
- Input validation. All decode paths check lengths and codec identifiers before they allocate.
- DoS protection. The `Varbytes` decode path sets the hash digest length. It enforces a decoded-size cap (16 MiB) and buffer-length checks. This mitigates CWE-400 and CWE-125.

### Constant-Time Comparison

`Multihash` derives `PartialEq`. The derived `PartialEq` uses a short-circuiting byte comparison. It is not constant-time. Do not use it for timing-sensitive comparisons, such as verification of a hash from an untrusted party.

The crate gives `impl subtle::ConstantTimeEq for Multihash`. It compares the `codec`, the hash length, and the hash bytes in constant time. Use `mh.ct_eq(&other)` when timing leaks are a risk.

### Supported Algorithms

See `SAFE_HASH_CODECS` for the recommended algorithms. The legacy algorithms (SHA1, MD5, RIPEMD) are for compatibility only. Do not use them in new cryptographic constructions.

## Reporting Vulnerabilities

Report security issues through the GitHub issue tracker. You can also report them privately to the maintainers.

## CI

The CI workflow runs these jobs. `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`, an MSRV job (1.85), `cargo audit`, and a `coverage` job. The coverage job uses `cargo-llvm-cov` and uploads the result to Codecov.