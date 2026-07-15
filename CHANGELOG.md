# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

### Changed

- **Edition 2024**: Updated from Rust 2021.
- **`From<Multihash> for Vec<u8>`**: Pre-calculates total size and uses a single
  `with_capacity` + `extend_from_slice` instead of two `append` calls that each
  allocate intermediate `Vec<u8>` buffers.
- **Clippy pedantic/nursery/cargo warnings** resolved across all source, tests,
  and benchmarks.

## [1.0.0] - 2026-07-13

### Changed
- Synced from bettersign workspace (bs-multihash 0.7.0)
- Renamed crate from `bs-multihash` to `multi-hash`
- Added `types.rs` module with type-safe wrappers
- Added test suite (edge cases, integration, proptest, security)
- Initial published release on crates.io as `multi-hash`

[1.0.4]: https://github.com/cryptidtech/multi-hash/compare/v1.0.0...v1.0.4
[1.0.0]: https://github.com/cryptidtech/multi-hash/releases/tag/v1.0.0