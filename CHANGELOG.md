# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-08-13

### Changed

- Upgraded the digest stack from digest 0.10 to digest 0.11. This is an internal upgrade with no public API change. The `DynDigest` trait API is the same in both versions. `multi-hash` does not re-export any digest traits in its public API; the public surface (`Multihash`, `Builder`, `EncodedMultihash`, `Error`, `AlgorithmId`, `HashDigest`, `HASH_CODECS`, `SAFE_HASH_CODECS`) is unchanged.
- `sha2` upgraded from `0.10` to `0.11`.
- `sha3` upgraded from `0.10` to `0.12`.
- `blake2` upgraded from `0.10` to `0.11.0-rc.6`.
- `blake3` upgraded from `1.5.1` to `1.8`.
- `md-5` upgraded from `0.10` to `0.11`.
- `ripemd` upgraded from `0.1.3` to `0.2`.
- `sha1` upgraded from `0.10` to `0.11`.
- `digest` upgraded from `0.10` to `0.11`.
- Fixed the `Blake3DynDigest` impl to use `blake3::Hasher::finalize(&self.0)` (fully-qualified call) instead of `self.0.finalize()`, because the `traits-preview` feature makes `blake3::Hasher` implement the `Digest` trait from `digest 0.11`, and the `Digest::finalize()` method shadows the inherent `blake3::Hasher::finalize()` method when `Digest` is in scope. The qualified call returns `blake3::Hash` (which has `as_bytes()`), while the trait method returns `Array` (which does not).

### Notes

- This upgrade unblocks `lamport_signature_plus` support in `multi-key` (Phases 8-9 of the crate extraction plan). `lamport_signature_plus` requires digest 0.11 hash crates (sha3 0.12, sha2 0.11, blake2 0.11, shake 0.1, blake3 1.8).
- `blake2 0.11.0-rc.6` is a release candidate. When the stable `blake2 0.11` is published, the version requirement can be loosened to `"0.11"`.
- `blake3 1.8` still bundles its own copy of `digest 0.11` internally (via the `traits-preview` feature). The `multiple_crate_versions` clippy allow is retained until blake3 publishes a release that depends on the RustCrypto `digest 0.11` crate directly.

## [1.0.7] - 2026-07-29

### Added

- Coverage CI job. The `coverage` job in `.github/workflows/rust.yml` uses `cargo-llvm-cov` and uploads the result to Codecov. The crate had fmt, clippy, MSRV, and audit jobs before. It had no coverage collection.

### Changed

- Bumped the `multi-codec` pin from `1.0` to `1.1` and the `multi-util` pin from `1.0` to `1.1` for traceability. The `multi-codec 1.1.0` release rejects trailing bytes in `TryFrom<&[u8]>`. This crate does not call `Codec::try_from(&[u8])`. It uses `Codec::try_decode_from` and `Codec::try_from(&str)`. No source change was required.
- Rewrote `README.md`, `SECURITY.md`, and `CHANGELOG.md` in ASD-STE100 strict mode. Removed marketing language, passive voice, and long sentences.

## [1.0.6] - 2026-07-16

### Security

- Removed the unmaintained `serde_cbor` dev-dependency (RUSTSEC-2021-0127). Replaced it with `ciborium` (a maintained CBOR library) in all test code.

### Changed

- `Multihash` non-human-readable `Deserialize` path now uses `deserialize_byte_buf` with a `ByteBufVisitor`. The visitor accepts borrowed bytes, owned bytes, and byte buffers. It is compatible with `serde_test`, `serde_cbor`, and `ciborium`. The previous `&'de [u8]` bound only worked with deserializers that lend borrowed slices.
- Added `cbor_to_vec` helper functions in test modules. They wrap `ciborium::into_writer` to replace `serde_cbor::to_vec`.
- Replaced `serde_cbor::from_slice` with `ciborium::from_reader`.
- Changed `test_serde_cbor` from exact-byte comparison to round-trip verification. `ciborium` may encode differently than `serde_cbor`.

### Dependencies

- Removed the `serde_cbor = "0.11"` dev-dependency.
- Added the `ciborium = "0.2"` dev-dependency.
- The dependency count went from 146 to 144 crates.

## [1.0.5] - 2026-07-16

### Security

- Added the `subtle = "2"` dependency and implemented `impl ConstantTimeEq for Multihash`. It compares `codec` (via `u64::from`), `hash.len()`, and `hash` bytes in constant time with `subtle::ConstantTimeEq`. Use `mh.ct_eq(&other)` in timing-sensitive contexts instead of `PartialEq`.
- Added a doc note on the `Multihash` struct. It explains that `PartialEq` is not constant-time and `ct_eq` should be used in timing-sensitive contexts.

### Documentation

- Added `SECURITY.md`. It documents std-only status, constant-time comparison, decoded-size caps, and supported algorithms.

### Tests

- Added 4 `ct_eq` unit tests. They are `test_ct_eq_equal`, `test_ct_eq_unequal_hash`, `test_ct_eq_unequal_codec`, and `test_ct_eq_unequal_length`.

## [1.0.4] - 2026-07-15

### Added

- `#![deny(unsafe_code)]` at the crate root.
- `#[must_use]` on `Builder::with_hash()` and `Builder::with_base_encoding()`. These methods return `Self`.
- `#[must_use]` on `Error::unsupported_hash()`, `Error::invalid_digest_length()`, `Error::hash_compute_failed()`, and `Error::kind()`.
- `# Errors` doc sections on `Builder::new_from_bytes()`, `Builder::try_build()`, and `Builder::try_build_encoded()`.
- MSRV declared. `rust-version = "1.85"` in `Cargo.toml`. CI verifies the MSRV with a dedicated job.
- `cargo audit` job in CI.
- `cargo fmt --check` and `clippy -D warnings` steps in CI.
- Clippy lint configuration. `[lints.clippy]` with `pedantic`, `nursery`, and `cargo` groups set to `warn`. `[lints.rust] unsafe_code = "deny"`. `multiple_crate_versions` is allowed. `blake3` pulls in `digest 0.11` while other RustCrypto crates use `0.10`.

### Changed

- Edition 2024. Updated from Rust 2021.
- `From<Multihash> for Vec<u8>` now pre-calculates the total size. It uses a single `with_capacity` + `extend_from_slice` instead of two `append` calls that each allocate intermediate `Vec<u8>` buffers.
- `Multihash` now derives `Hash`. This enables use in `HashMap` and `HashSet`.
- Resolved all clippy pedantic, nursery, and cargo warnings across source, tests, and benchmarks.
- Updated `README.md` with comprehensive documentation.

## [1.0.3] - 2026-07-14

### Changed

- Bumped the version and updated documentation.

## [1.0.2] - 2026-07-14

### Changed

- Updated dependencies to published crates.io versions.

## [1.0.1] - 2026-07-13

### Fixed

- Fixed codec name references after the multicodec table sync. The affected files are `error.rs`, `mh.rs`, `serde/de.rs`, and `types.rs`.

## [1.0.0] - 2026-07-13

### Changed

- Synced from the bettersign workspace (`bs-multihash` 0.7.0).
- Renamed the crate from `bs-multihash` to `multi-hash`.
- Added the `types.rs` module with type-safe wrappers.
- Added a test suite for edge cases, integration, proptests, and security.
- Initial published release on crates.io as `multi-hash`.

[1.1.0]: https://github.com/cryptidtech/multi-hash/compare/v1.0.7...v1.1.0
[1.0.7]: https://github.com/cryptidtech/multi-hash/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/cryptidtech/multi-hash/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/cryptidtech/multi-hash/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/cryptidtech/multi-hash/compare/v1.0.0...v1.0.4
[1.0.3]: https://github.com/cryptidtech/multi-hash/releases/tag/v1.0.3
[1.0.2]: https://github.com/cryptidtech/multi-hash/releases/tag/v1.0.2
[1.0.1]: https://github.com/cryptidtech/multi-hash/releases/tag/v1.0.1
[1.0.0]: https://github.com/cryptidtech/multi-hash/releases/tag/v1.0.0