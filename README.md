[![](https://img.shields.io/badge/made%20by-Cryptid%20Technologies-gold.svg?style=flat-square)](https://cryptid.tech/)
[![](https://img.shields.io/badge/project-provenance-purple.svg?style=flat-square)](https://github.com/cryptidtech/provenance-specifications/)
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)](https://github.com/multiformats/multiformats/)

[![Build Status](https://github.com/cryptidtech/multi-hash/actions/workflows/rust.yml/badge.svg)](https://github.com/cryptidtech/multi-hash/actions)
[![License](https://img.shields.io/crates/l/multi-hash?style=flat-square)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/multi-hash?style=flat-square)](https://crates.io/crates/multi-hash)
[![Documentation](https://docs.rs/multi-hash/badge.svg?style=flat-square)](https://docs.rs/multi-hash)

# multi-hash

Rust implementation of the [Multihash](https://github.com/multiformats/multihash)
specification for self-describing cryptographic hash digests.

Multihash is a self-describing format that pairs a hash algorithm identifier
(multicodec tag) with the raw digest bytes, enabling systems to switch hash
algorithms without breaking compatibility. This crate provides 23 supported hash
algorithms, type-safe wrappers, serde integration, and multibase encoding via
the `multi-util` crate stack.

## Table of Contents

- [Features](#features)
- [Install](#install)
- [Supported Algorithms](#supported-algorithms)
- [Usage](#usage)
  - [Computing a Hash](#computing-a-hash)
  - [Building from an Existing Digest](#building-from-an-existing-digest)
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

- **23 Hash Algorithms**: SHA1, SHA2 family, SHA3 family, Blake2, Blake3,
  MD5, RIPEMD
- **Builder Pattern**: Fluent API for creating multihashes from raw data or
  existing digests
- **Multibase Encoding**: `EncodedMultihash` smart pointer for base-encoded
  string representation via `multi-util`'s `BaseEncoded`
- **Serde Support**: JSON (human-readable → codec name string) and binary
  (varint bytes) serialization (feature-gated)
- **Binary Round-Trip**: `Into<Vec<u8>>` and `TryFrom<&[u8]>` for raw wire format
- **Type-Safe Newtypes**: `HashDigest` and `AlgorithmId` wrappers
- **Zero Unsafe Code**: `#![deny(unsafe_code)]` enforced at compile time
- **Thread-Safe**: All types are `Send + Sync`

## Install

Add this to your `Cargo.toml`:

```toml
[dependencies]
multi-hash = "1.0"
```

To disable serde support:

```toml
[dependencies]
multi-hash = { version = "1.0", default-features = false }
```

**MSRV**: Rust 1.85 (Edition 2024)

## Supported Algorithms

### Secure algorithms (recommended for cryptographic use)

| Algorithm | Codec | Digest Size |
|-----------|-------|-------------|
| Blake2b-256 | `Blake2B256` | 32 bytes |
| Blake2b-384 | `Blake2B384` | 48 bytes |
| Blake2b-512 | `Blake2B512` | 64 bytes |
| Blake2s-256 | `Blake2S256` | 32 bytes |
| Blake3 | `Blake3` | 32 bytes |
| SHA3-256 | `Sha3256` | 32 bytes |
| SHA3-384 | `Sha3384` | 48 bytes |
| SHA3-512 | `Sha3512` | 64 bytes |

See [`SAFE_HASH_CODECS`](https://docs.rs/multi-hash/latest/multi_hash/constant.SAFE_HASH_CODECS.html)
for the constant array.

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

See [`HASH_CODECS`](https://docs.rs/multi-hash/latest/multi_hash/constant.HASH_CODECS.html)
for the constant array of all 23 supported codecs.

## Usage

### Computing a Hash

```rust
use multi_hash::Builder;
use multi_codec::Codec;

// Compute a SHA2-256 hash
let multihash = Builder::new_from_bytes(Codec::Sha2256, b"hello world")
    .unwrap()
    .try_build()
    .unwrap();

assert_eq!(multihash.codec(), Codec::Sha2256);
assert_eq!(multihash.as_ref().len(), 32); // SHA2-256 outputs 32 bytes
```

### Building from an Existing Digest

If you already have a hash digest (e.g. from an external hashing library):

```rust
use multi_hash::Builder;
use multi_codec::Codec;

let digest = vec![0u8; 32]; // pre-computed SHA2-256 digest
let multihash = Builder::new(Codec::Sha2256)
    .with_hash(digest)
    .try_build()
    .unwrap();
```

### Encoding and Decoding

Multihashes encode as `codec || length || hash` (varint-prefixed):

```rust
use multi_hash::{Builder, Multihash};
use multi_codec::Codec;

let mh1 = Builder::new_from_bytes(Codec::Sha2256, b"data")
    .unwrap()
    .try_build()
    .unwrap();

// Encode to binary (varint wire format)
let bytes: Vec<u8> = mh1.clone().into();

// Decode from binary
let mh2 = Multihash::try_from(bytes.as_ref()).unwrap();
assert_eq!(mh1, mh2);
```

### Base Encoding

Use `try_build_encoded()` with a specific base to get an `EncodedMultihash` that
supports `Display` and `TryFrom<&str>`:

```rust
use multi_hash::Builder;
use multi_codec::Codec;
use multi_base::Base;

let encoded = Builder::new_from_bytes(Codec::Sha2256, b"data")
    .unwrap()
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

Existing `Multihash` objects can be converted to `EncodedMultihash` using `.into()`
(defaults to `Base16Lower`) or `EncodedMultihash::new()` with a chosen base:

```rust
use multi_hash::{Builder, EncodedMultihash};
use multi_base::Base;
use multi_codec::Codec;

let mh = Builder::new_from_bytes(Codec::Sha3384, b"for great justice, move every zig!")
    .unwrap()
    .try_build()
    .unwrap();

// Uses the preferred encoding for multihash objects: Base16Lower
let encoded_mh1: EncodedMultihash = mh.clone().into();

// Or choose a specific base encoding
let encoded_mh2: EncodedMultihash = EncodedMultihash::new(Base::Base32Upper, mh);
```

### Serde Integration

With the `serde` feature (enabled by default), `Multihash` implements
`Serialize` and `Deserialize` — strings in human-readable formats, varint bytes
in binary formats:

```rust
use multi_hash::Builder;
use multi_codec::Codec;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct DocumentHash {
    hash: multi_hash::Multihash,
    timestamp: u64,
}

let doc = DocumentHash {
    hash: Builder::new_from_bytes(Codec::Sha2256, b"document content")
        .unwrap()
        .try_build()
        .unwrap(),
    timestamp: 1234567890,
};

// Serialize to JSON (human-readable → codec name + hex digest)
let json = serde_json::to_string(&doc).unwrap();
println!("{}", json);

// Deserialize from JSON
let deserialized: DocumentHash = serde_json::from_str(&json).unwrap();
assert_eq!(doc, deserialized);
```

### Error Handling

All conversion and builder errors return `Result` with a structured `Error` enum:

```rust
use multi_hash::{Builder, Error};
use multi_codec::Codec;

// Handle unsupported algorithms
match Builder::new_from_bytes(Codec::Identity, b"data") {
    Err(Error::UnsupportedHash { codec }) => {
        eprintln!("Algorithm {:?} not supported", codec);
    }
    Err(e) => eprintln!("Other error: {}", e),
    Ok(_) => unreachable!(),
}

// Handle missing hash data
match Builder::new(Codec::Sha2256).try_build() {
    Err(Error::MissingHash) => {
        eprintln!("Must call with_hash() before build()");
    }
    Err(e) => eprintln!("Other error: {}", e),
    Ok(_) => unreachable!(),
}
```

### Type-Safe Newtypes

For additional type safety, use the newtype wrappers:

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

The crate has 110 tests across unit, integration, property-based, security, and
doc-test suites:

```bash
# Run all tests
cargo test --all-features

# Run specific test suites
cargo test --test edge_case_tests
cargo test --test integration_tests
cargo test --test proptest_tests
cargo test --test security_tests

# Run benchmarks
cargo bench
```

Linting and formatting:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

## Feature Flags

- **`serde`** (default): Enables serde serialization/deserialization. When
  enabled, `Multihash` implements `Serialize` and `Deserialize` — codec name
  and hex digest in human-readable formats, varint bytes in binary formats.

### Disabling Default Features

```toml
[dependencies]
multi-hash = { version = "1.0", default-features = false }
```

## Security

- `#![deny(unsafe_code)]` enforced at compile time
- All errors return `Result` types — no panics on invalid input
- All types are `Send + Sync` with no shared mutable state
- Hash computation uses vetted cryptographic libraries from the RustCrypto
  ecosystem

## Maintainers

This repo: [@dgrantham](https://github.com/dgrantham).

## Contribute

Contributions welcome! Please check out [the issues](https://github.com/cryptidtech/multi-hash/issues).

### Development Guidelines

- Run `cargo fmt` before committing
- Run `cargo clippy -- -D warnings` to check for issues
- Add tests for new features
- Update documentation for API changes
- Run the full test suite: `cargo test --all-features`

## License

[Apache-2.0](LICENSE) © Cryptid Technologies