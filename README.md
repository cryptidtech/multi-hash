[![](https://img.shields.io/badge/made%20by-Cryptid%20Technologies-gold.svg?style=flat-square)](https://cryptid.tech/)
[![](https://img.shields.io/badge/project-provenance-purple.svg?style=flat-square)](https://github.com/cryptidtech/provenance-specifications/)
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)](https://github.com/multiformats/multiformats/)

[![Build Status](https://github.com/cryptidtech/multi-hash/actions/workflows/rust.yml/badge.svg)](https://github.com/cryptidtech/multi-hash/actions)
[![License](https://img.shields.io/crates/l/multi-hash?style=flat-square)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/multi-hash?style=flat-square)](https://crates.io/crates/multi-hash)
[![Documentation](https://docs.rs/multi-hash/badge.svg?style=flat-square)](https://docs.rs/multi-hash)

# multi-hash

Rust implementation of the [Multihash](https://github.com/multiformats/multihash) specification for self-describing cryptographic hash digests.

Multihash is a self-describing format. It pairs a hash algorithm identifier (a multicodec tag) with the raw digest bytes. This lets systems switch hash algorithms without a break in compatibility. The crate gives 25 supported hash algorithms, type-safe wrappers, serde integration, and multibase encoding via the `multi-util` crate stack. The codec set includes three extendable-output functions (XOF): `Blake3`, `Shake128`, and `Shake256`. You choose the digest length of an XOF with the builder, from 1 to `MAX_HASH_LENGTH` bytes (16 MiB).

## Table of Contents

- [Features](#features)
- [Install](#install)
- [Supported Algorithms](#supported-algorithms)
- [Usage](#usage)
  - [Computing a Hash](#computing-a-hash)
  - [Building from an Existing Digest](#building-from-an-existing-digest)
  - [Extendable-Output Functions](#extendable-output-functions)
  - [Encoding and Decoding](#encoding-and-decoding)
  - [Base Encoding](#base-encoding)
  - [Converting to EncodedMultihash](#converting-to-encodedmultihash)
  - [Serde Integration](#serde-integration)
  - [Error Handling](#error-handling)
  - [Type-Safe Newtypes](#type-safe-newtypes)
- [Testing](#testing)
- [Feature Flags](#feature-flags)
- [Security](#security)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Features

- 25 hash algorithms. SHA1, SHA2 family, SHA3 family, Blake2, Blake3, MD5, RIPEMD. `Blake3`, `Shake128`, and `Shake256` are extendable-output functions (XOF) with a caller-chosen digest length.
- Builder pattern. A fluent API to create multihashes from raw data or existing digests.
- Multibase encoding. The `EncodedMultihash` smart pointer gives a base-encoded string representation via `BaseEncoded` from `multi-util`.
- Serde support. JSON gives the codec name string. Binary gives the varint bytes. The `serde` feature gates it.
- Binary round-trip. `Into<Vec<u8>>` and `TryFrom<&[u8]>` for the raw wire format.
- Type-safe newtypes. `HashDigest` and `AlgorithmId` wrappers.
- Zero unsafe code. `#![deny(unsafe_code)]` is set at the crate root.
- Thread-safe. All types are `Send + Sync`.

## Install

Add this to your `Cargo.toml`:

```toml
[dependencies]
multi-hash = "2.0"
```

To disable serde support:

```toml
[dependencies]
multi-hash = { version = "2.0", default-features = false }
```

MSRV: Rust 1.99 (Edition 2024).

## Supported Algorithms

### Secure algorithms (recommended for cryptographic use)

| Algorithm | Codec | Digest Size |
|-----------|-------|-------------|
| Blake2b-256 | `Blake2B256` | 32 bytes |
| Blake2b-384 | `Blake2B384` | 48 bytes |
| Blake2b-512 | `Blake2B512` | 64 bytes |
| Blake2s-256 | `Blake2S256` | 32 bytes |
| Blake3 | `Blake3` | Caller-chosen, 1 to `MAX_HASH_LENGTH` bytes (recommended 32) |
| SHA3-256 | `Sha3256` | 32 bytes |
| SHA3-384 | `Sha3384` | 48 bytes |
| SHA3-512 | `Sha3512` | 64 bytes |
| Shake128 | `Shake128` | Caller-chosen, 1 to `MAX_HASH_LENGTH` bytes (recommended 32) |
| Shake256 | `Shake256` | Caller-chosen, 1 to `MAX_HASH_LENGTH` bytes (recommended 64) |

See [`SAFE_HASH_CODECS`](https://docs.rs/multi-hash/latest/multi_hash/constant.SAFE_HASH_CODECS.html) for the constant array.

### Legacy algorithms (for compatibility)

| Algorithm | Codec | Digest Size |
|-----------|-------|-------------|
| SHA1 | `Sha1` | 20 bytes |
| SHA2-224 | `Sha2224` | 28 bytes |
| SHA2-256 | `Sha2256` | 32 bytes |
| SHA2-384 | `Sha2384` | 48 bytes |
| SHA2-512 | `Sha2512` | 64 bytes |
| SHA2-512/224 | `Sha2512224` | 28 bytes |
| SHA2-512/256 | `Sha2512256` | 32 bytes |
| Blake2b-224 | `Blake2B224` | 28 bytes |
| Blake2s-224 | `Blake2S224` | 28 bytes |
| MD5 | `Md5` | 16 bytes |
| RIPEMD-128 | `Ripemd128` | 16 bytes |
| RIPEMD-160 | `Ripemd160` | 20 bytes |
| RIPEMD-256 | `Ripemd256` | 32 bytes |
| RIPEMD-320 | `Ripemd320` | 40 bytes |
| SHA3-224 | `Sha3224` | 28 bytes |

See [`HASH_CODECS`](https://docs.rs/multi-hash/latest/multi_hash/constant.HASH_CODECS.html) for the constant array of all 25 supported codecs.

The extendable-output functions (`Blake3`, `Shake128`, and `Shake256`) accept a caller-chosen digest length from 1 to `MAX_HASH_LENGTH` bytes (16 MiB), which you set with `Builder::output_len()`.

## Usage

### Computing a Hash

```rust
use multi_hash::Builder;
use multi_codec::Codec;

// Compute a SHA2-256 hash over data fed in chunks
let mut builder = Builder::new(Codec::Sha2256).unwrap();
builder.update(b"hello world");
let multihash = builder.try_build().unwrap();

assert_eq!(multihash.codec(), Codec::Sha2256);
assert_eq!(multihash.as_ref().len(), 32); // SHA2-256 outputs 32 bytes
```

### Building from an Existing Digest

If you already have a hash digest, for example from an external hashing library:

```rust
use multi_hash::Builder;
use multi_codec::Codec;

let digest = vec![0u8; 32]; // pre-computed SHA2-256 digest
let multihash = Builder::new(Codec::Sha2256)
    .unwrap()
    .with_hash(digest)
    .try_build()
    .unwrap();
```

### Extendable-Output Functions

`Blake3`, `Shake128`, and `Shake256` are extendable-output functions (XOF). They produce a digest of any length from 1 to `MAX_HASH_LENGTH` bytes. Set the length with `output_len()`. A streamed build of an XOF codec fails with `Error::OutputLenRequired` without a length:

```rust
use multi_hash::{Builder, Error};
use multi_codec::Codec;

// Stream data through SHAKE128 and squeeze 64 digest bytes
let mut shake = Builder::new(Codec::Shake128).unwrap();
shake.update(b"hello world");
shake.output_len(64);
let shake_digest = shake.try_build().unwrap();
assert_eq!(shake_digest.as_ref().len(), 64);

// BLAKE3 uses the same length policy. A 32-byte digest equals the classic BLAKE3 digest.
let mut blake = Builder::new(Codec::Blake3).unwrap();
blake.update(b"hello world");
blake.output_len(32);
let blake_digest = blake.try_build().unwrap();
assert_eq!(blake_digest.as_ref().len(), 32);

// A streamed build of an XOF codec fails without an output length
let mut builder = Builder::new(Codec::Shake256).unwrap();
builder.update(b"hello world");
match builder.try_build() {
    Err(Error::OutputLenRequired { codec }) => {
        eprintln!("Set output_len() for {:?} with a length from 1 to MAX_HASH_LENGTH", codec);
    }
    Err(e) => eprintln!("Other error: {}", e),
    Ok(_) => unreachable!(),
}
```

You can also wrap an existing XOF digest. `with_hash()` accepts any digest length from 1 to `MAX_HASH_LENGTH` bytes for an XOF codec. Notes on XOF digests:

- Prefix consistency. For the same input, the first N bytes of a long digest equal the shorter digest. Two different lengths still encode as distinct multihashes, because the encoded length prefix differs.
- No extension of a built digest. A built `Multihash` digest cannot extend to a longer digest. A different length needs a rehash through a fresh builder.
- Different algorithms. A 32-byte `Shake256` digest is not a `Sha3256` digest. A 32-byte `Blake3` digest is not a BLAKE2b-256 digest. The codecs name different algorithms.
- Length and security. The sponge capacity fixes the security strength of the XOF. The chosen output length bounds collision resistance. Use at least 32 bytes for `Blake3` and `Shake128`, and at least 64 bytes for `Shake256`. Longer BLAKE3 outputs give no additional security.

### Encoding and Decoding

Multihashes encode as `codec || length || hash` (varint-prefixed):

```rust
use multi_hash::{Builder, Multihash};
use multi_codec::Codec;

let mut builder = Builder::new(Codec::Sha2256).unwrap();
builder.update(b"data");
let mh1 = builder.try_build().unwrap();

// Encode to binary (varint wire format)
let bytes: Vec<u8> = mh1.clone().into();

// Decode from binary
let mh2 = Multihash::try_from(bytes.as_ref()).unwrap();
assert_eq!(mh1, mh2);
```

### Base Encoding

Use `try_build_encoded()` with a specific base. It gives an `EncodedMultihash` that supports `Display` and `TryFrom<&str>`:

```rust
use multi_hash::Builder;
use multi_codec::Codec;
use multi_base::Base;

let mut builder = Builder::new(Codec::Sha2256).unwrap();
builder.update(b"data");
let encoded = builder
    .with_base_encoding(Base::Base58Btc)
    .try_build_encoded()
    .unwrap();

// Display as a base58-encoded multihash string
let base58_string = encoded.to_string();
println!("Multihash: {}", base58_string);

// Parse back from string
use multi_hash::EncodedMultihash;
let decoded: EncodedMultihash = EncodedMultihash::try_from(base58_string.as_str()).unwrap();
assert_eq!(encoded, decoded);
```

### Converting to EncodedMultihash

You can convert a `Multihash` to an `EncodedMultihash` with `.into()`. The default base is `Base16Lower`. You can also use `EncodedMultihash::new()` with a base of your choice:

```rust
use multi_hash::{Builder, EncodedMultihash};
use multi_base::Base;
use multi_codec::Codec;

let mut builder = Builder::new(Codec::Sha3384).unwrap();
builder.update(b"for great justice, move every zig!");
let mh = builder.try_build().unwrap();

// Uses the preferred encoding for multihash objects: Base16Lower
let encoded_mh1: EncodedMultihash = mh.clone().into();

// Or choose a specific base encoding
let encoded_mh2: EncodedMultihash = EncodedMultihash::new(Base::Base32Upper, mh);
```

### Serde Integration

With the `serde` feature on by default, `Multihash` implements `Serialize` and `Deserialize`. Human-readable formats give the codec name and the hex digest. Binary formats give the varint bytes:

```rust
use multi_hash::Builder;
use multi_codec::Codec;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct DocumentHash {
    hash: multi_hash::Multihash,
    timestamp: u64,
}

let mut builder = Builder::new(Codec::Sha2256).unwrap();
builder.update(b"document content");
let doc = DocumentHash {
    hash: builder.try_build().unwrap(),
    timestamp: 1234567890,
};

// Serialize to JSON (human-readable - codec name + hex digest)
let json = serde_json::to_string(&doc).unwrap();
println!("{}", json);

// Deserialize from JSON
let deserialized: DocumentHash = serde_json::from_str(&json).unwrap();
assert_eq!(doc, deserialized);
```

### Error Handling

All conversion and builder errors return `Result` with a structured `Error` enum. `Builder::new()` is fallible and returns `Error::UnsupportedHash` for an unknown codec:

```rust
use multi_hash::{Builder, Error};
use multi_codec::Codec;

// Handle unsupported algorithms
match Builder::new(Codec::Identity) {
    Err(Error::UnsupportedHash { codec }) => {
        eprintln!("Algorithm {:?} not supported", codec);
    }
    Err(e) => eprintln!("Other error: {}", e),
    Ok(_) => unreachable!(),
}

// Handle missing hash data
match Builder::new(Codec::Sha2256).unwrap().try_build() {
    Err(Error::MissingHash) => {
        eprintln!("Must call with_hash() or update() before try_build()");
    }
    Err(e) => eprintln!("Other error: {}", e),
    Ok(_) => unreachable!(),
}
```

A streamed build of an XOF codec needs an output length:

```rust
use multi_hash::{Builder, Error};
use multi_codec::Codec;

// Handle a streamed build of an XOF codec without an output length
let mut builder = Builder::new(Codec::Shake128).unwrap();
builder.update(b"some data");
match builder.try_build() {
    Err(Error::OutputLenRequired { codec }) => {
        eprintln!("Set output_len() from 1 to MAX_HASH_LENGTH for {:?}", codec);
    }
    Err(e) => eprintln!("Other error: {}", e),
    Ok(_) => unreachable!(),
}

// Handle an XOF output length outside the 1..=MAX_HASH_LENGTH policy
let mut builder = Builder::new(Codec::Shake256).unwrap();
builder.update(b"some data");
builder.output_len(0);
match builder.try_build() {
    Err(Error::OutputLenInvalid { codec, output_len, max }) => {
        eprintln!(
            "Algorithm {:?} rejects a length of {}. Use a length from 1 to {}",
            codec, output_len, max
        );
    }
    Err(e) => eprintln!("Other error: {}", e),
    Ok(_) => unreachable!(),
}
```

The length check runs before any allocation or squeeze.

### Type-Safe Newtypes

For more type safety, use the newtype wrappers:

```rust
use multi_hash::types::{HashDigest, AlgorithmId};
use multi_codec::Codec;

// Type-safe hash digest
let digest = HashDigest::new(vec![0u8; 32]);
assert_eq!(digest.len(), 32);
assert_eq!(digest.as_bytes().len(), 32);

// Type-safe algorithm identifier
let algo = AlgorithmId::new(Codec::Sha2256);
assert_eq!(algo.codec(), Codec::Sha2256);
assert_eq!(algo.name(), "sha2-256");
assert_eq!(algo.code(), 0x12);
```

## Testing

The crate has 171 tests: 130 test functions and 41 doc examples. The suites cover unit, integration, property-based, security, XOF, FIPS, and doc-test paths:

```bash
# Run all tests
cargo test --all-features

# Run specific test suites
cargo test --test edge_case_tests
cargo test --test integration_tests
cargo test --test proptest_tests
cargo test --test security_tests
cargo test --test xof_tests

# Run the FIPS tests, which need the `fips` feature
cargo test --test fips_tests --features fips

# Run benchmarks
cargo bench
```

Linting and formatting:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

CI collects coverage with `cargo-llvm-cov` and uploads the result to Codecov.

## Feature Flags

- `serde` (default). Enables serde serialization and deserialization. When on, `Multihash` implements `Serialize` and `Deserialize`. Human-readable formats give the codec name and the hex digest. Binary formats give the varint bytes.
- `fips` (additive, off by default). Exports `FIPS_CODECS` (13 codecs) and `SAFE_FIPS_CODECS` (8 codecs). They list the NIST FIPS approved hash algorithms. `SAFE_FIPS_CODECS` omits SHA-1 and the 224-bit algorithms that SP 800-131A restricts. `Blake2`, `Blake3`, `Md5`, and the RIPEMD codecs are not FIPS approved. SHA-1 is verification-only under NIST SP 800-131A Rev. 2. The SP 800-131A Rev. 3 draft deprecates SHA-1 and the 224-bit hashes through 2030 and disallows them after 2030.

The `fips` feature composes with the default `serde` feature:

```toml
[dependencies]
multi-hash = { version = "2.0", features = ["fips"] }
```

### Disabling Default Features

```toml
[dependencies]
multi-hash = { version = "2.0", default-features = false }
```

## Security

- `#![deny(unsafe_code)]` is set at the crate root.
- All errors return `Result`. No path panics on invalid input.
- All types are `Send + Sync` with no shared mutable state.
- Hash computation uses vetted cryptographic libraries from the RustCrypto ecosystem.
- `impl subtle::ConstantTimeEq for Multihash` is available for timing-sensitive comparisons.
- The `Varbytes` decode path enforces a decoded-size cap (16 MiB) and buffer-length checks. This mitigates CWE-400 and CWE-125.
- The builder enforces the same 16 MiB cap through `MAX_HASH_LENGTH`. It checks an XOF output length against `1..=MAX_HASH_LENGTH` before it allocates or squeezes. The builder validates the digest length at `try_build()` time.

See [SECURITY.md](SECURITY.md) for the full security policy.

## Maintainers

This repo: [@dgrantham](https://github.com/dgrantham).

## Contribute

Contributions are welcome. Please check out [the issues](https://github.com/cryptidtech/multi-hash/issues).

### Development Guidelines

- Run `cargo fmt` before you commit.
- Run `cargo clippy -- -D warnings` to check for issues.
- Add tests for new features.
- Update documentation for API changes.
- Run the full test suite: `cargo test --all-features`.

## License

[Apache-2.0](LICENSE) (c) Cryptid Technologies