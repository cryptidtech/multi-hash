# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.6] - 2026-07-16

### Security
- Removed unmaintained `serde_cbor` dev-dependency (RUSTSEC-2021-0127). Replaced
  with `ciborium` (a maintained CBOR library) in all test code.

### Changed
- `Multihash` non-human-readable `Deserialize` path now uses
  `deserialize_byte_buf` with a `ByteBufVisitor` that accepts borrowed bytes,
  owned bytes, and byte buffers — compatible with `serde_test`, `serde_cbor`,
  and `ciborium` (the previous `&'de [u8]` bound only worked with
  deserializers that lend borrowed slices).
- Added `cbor_to_vec` helper functions in test modules to wrap
  `ciborium::into_writer` (replacing `serde_cbor::to_vec`).
- Replaced `serde_cbor::from_slice` with `ciborium::from_reader`.
- Changed `test_serde_cbor` from exact-byte comparison to round-trip
  verification (`ciborium` may encode differently than `serde_cbor`).

### Dependencies
- Removed `serde_cbor = "0.11"` dev-dependency.
- Added `ciborium = "0.2"` dev-dependency.
- Dependency count reduced from 146 to 144 crates.

## [1.0.5] - 2026-07-16

### Security
- Added `subtle = "2"` dependency and implemented
  `impl ConstantTimeEq for Multihash` — compares `codec` (via `u64::from`),
  `hash.len()`, and `hash` bytes in constant time using `subtle::ConstantTimeEq`.
  Use `mh.ct_eq(&other)` in timing-sensitive contexts instead of `PartialEq`.
- Added doc note on `Multihash` struct explaining that `PartialEq` is **not**
  constant-time and `ct_eq` should be used in timing-sensitive contexts.

### Documentation
- Added `SECURITY.md` documenting std-only status, constant-time comparison,
  decoded-size caps, and supported algorithms.

### Tests
- Added 4 `ct_eq` unit tests: `test_ct_eq_equal`, `test_ct_eq_unequal_hash`,
  `test_ct_eq_unequal_codec`, `test_ct_eq_unequal_length`.

## [1.0.4] - 2026-07-15

### Added

- **`#![deny(unsafe_code)]`** at the crate root.
- **`#[must_use]`** on `Builder::with_hash()` and `Builder::with_base_encoding()`
  (methods returning `Self`).
- **`#[must_use]`** on `Error::unsupported_hash()`,
  `Error::invalid_digest_length()`, `Error::hash_compute_failed()`, and
  `Error::kind()`.
- **`# Errors`** doc sections on `Builder::new_from_bytes()`,
  `Builder::try_build()`, and `Builder::try_build_encoded()`.
- **MSRV declared**: `rust-version = "1.85"` in `Cargo.toml`. CI verifies the
  MSRV with a dedicated job.
- **`cargo audit`** job in CI.
- **`cargo fmt --check`** and **`clippy -D warnings`** steps in CI.
- **Clippy lint configuration**: `[lints.clippy]` with `pedantic`, `nursery`,
  and `cargo` groups (all `warn`), plus `[lints.rust] unsafe_code = "deny"`.
  `multiple_crate_versions` allowed (blake3 pulls in digest 0.11 while other
  RustCrypto crates use 0.10).

### Changed

- **Edition 2024**: Updated from Rust 2021.
- **`From<Multihash> for Vec<u8>`**: Pre-calculates total size and uses a single
  `with_capacity` + `extend_from_slice` instead of two `append` calls that each
  allocate intermediate `Vec<u8>` buffers.
- **`Multihash` derives `Hash`** (for use in `HashMap`/`HashSet`).
- **Clippy pedantic/nursery/cargo warnings** resolved across all source, tests,
  and benchmarks.
- Updated `README.md` with comprehensive documentation.

## [1.0.3] - 2026-07-14

### Changed
- Bumped version and updated documentation.

## [1.0.2] - 2026-07-14

### Changed
- Updated dependencies to published crates.io versions.

## [1.0.1] - 2026-07-13

### Fixed
- Fixed codec name references after multicodec table sync (`error.rs`, `mh.rs`,
  `serde/de.rs`, `types.rs`).

## [1.0.0] - 2026-07-13

### Changed
- Synced from bettersign workspace (bs-multihash 0.7.0)
- Renamed crate from `bs-multihash` to `multi-hash`
- Added `types.rs` module with type-safe wrappers
- Added test suite (edge cases, integration, proptest, security)
- Initial published release on crates.io as `multi-hash`

[1.0.6]: https://github.com/cryptidtech/multi-hash/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/cryptidtech/multi-hash/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/cryptidtech/multi-hash/compare/v1.0.0...v1.0.4
[1.0.3]: https://github.com/cryptidtech/multi-hash/releases/tag/v1.0.3
[1.0.2]: https://github.com/cryptidtech/multi-hash/releases/tag/v1.0.2
[1.0.1]: https://github.com/cryptidtech/multi-hash/releases/tag/v1.0.1
[1.0.0]: https://github.com/cryptidtech/multi-hash/releases/tag/v1.0.0