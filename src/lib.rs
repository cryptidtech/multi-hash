// SPDX-License-Identifier: Apache-2.0
//! # multi-hash
//!
//! Self-describing cryptographic hash implementation following the
//! [Multihash](https://github.com/multiformats/multihash) specification.
//!
//! ## Overview
//!
//! Multihash is a protocol for differentiating outputs from various well-established
//! cryptographic hash functions, addressing size and encoding considerations. It is
//! useful for applications that may switch between hash functions or need to future-proof
//! their use of hashes.
//!
//! This crate provides:
//! - Support for 25 cryptographic hash algorithms, including the
//!   extendable-output functions BLAKE3, SHAKE128, and SHAKE256
//! - Type-safe hash digest and algorithm wrappers
//! - Encoding/decoding with multibase support
//! - Serde serialization (optional)
//! - Builder pattern for hash creation
//!
//! ## Supported Algorithms
//!
//! **Secure algorithms** (recommended for cryptographic use):
//! - Blake2b (256, 384, 512 bits)
//! - Blake2s (256 bits)
//! - Blake3 (extendable-output function)
//! - SHA3 (256, 384, 512 bits)
//! - SHAKE128 and SHAKE256 extendable-output functions
//!
//! **Legacy algorithms** (for compatibility):
//! - SHA1, SHA2 (224, 256, 384, 512, 512/224, 512/256 bits)
//! - MD5, RIPEMD (128, 160, 256, 320 bits)
//! - Blake2b-224, Blake2s-224, SHA3-224
//!
//! See [`HASH_CODECS`] for the complete list and [`SAFE_HASH_CODECS`] for the
//! recommended algorithms. With the `fips` feature enabled, the crate also
//! exports `FIPS_CODECS` and `SAFE_FIPS_CODECS`, which list the hash
//! algorithms on the NIST FIPS approved lists.
//!
//! ## Quick Start
//!
//! ### Computing a Hash
//!
//! ```rust
//! use multi_hash::Builder;
//! use multi_codec::Codec;
//! use multi_util::CodecInfo;
//!
//! // Compute a SHA2-256 hash
//! let mut builder = Builder::new(Codec::Sha2256).unwrap();
//! builder.update(b"hello world");
//! let multihash = builder.try_build().unwrap();
//!
//! assert_eq!(multihash.codec(), Codec::Sha2256);
//! assert_eq!(multihash.as_ref().len(), 32); // SHA2-256 outputs 32 bytes
//! ```
//!
//! ### Computing a SHAKE256 Digest of a Chosen Length
//!
//! The `Shake256` extendable-output function produces a digest of any
//! length from 1 to `MAX_HASH_LENGTH` bytes. Set the length with
//! [`Builder::output_len`] before `try_build`:
//!
//! ```rust
//! use multi_hash::Builder;
//! use multi_codec::Codec;
//! use multi_util::CodecInfo;
//!
//! let mut builder = Builder::new(Codec::Shake256).unwrap();
//! builder.update(b"hello world");
//! builder.output_len(64);
//! let multihash = builder.try_build().unwrap();
//!
//! assert_eq!(multihash.codec(), Codec::Shake256);
//! assert_eq!(multihash.as_ref().len(), 64);
//! ```
//!
//! ### Creating from Existing Hash
//!
//! ```rust
//! use multi_hash::Builder;
//! use multi_codec::Codec;
//!
//! // If you already have a hash digest
//! let digest = vec![0u8; 32]; // SHA2-256 digest
//! let multihash = Builder::new(Codec::Sha2256)
//!     .unwrap()
//!     .with_hash(digest)
//!     .try_build()
//!     .unwrap();
//! ```
//!
//! ### Encoding and Decoding
//!
//! ```rust
//! use multi_hash::{Builder, Multihash};
//! use multi_codec::Codec;
//!
//! let mut builder = Builder::new(Codec::Sha2256).unwrap();
//! builder.update(b"data");
//! let mh1 = builder.try_build().unwrap();
//!
//! // Encode to bytes
//! let bytes: Vec<u8> = mh1.clone().into();
//!
//! // Decode from bytes
//! let mh2 = Multihash::try_from(bytes.as_ref()).unwrap();
//! assert_eq!(mh1, mh2);
//! ```
//!
//! ### Base Encoding
//!
//! ```rust
//! use multi_hash::Builder;
//! use multi_codec::Codec;
//! use multi_base::Base;
//!
//! // Create with specific base encoding
//! let mut builder = Builder::new(Codec::Sha2256).unwrap();
//! builder.update(b"data");
//! let encoded = builder
//!     .with_base_encoding(Base::Base58Btc)
//!     .try_build_encoded()
//!     .unwrap();
//!
//! // Display as base58-encoded string
//! let base58_string = encoded.to_string();
//! println!("Multihash: {}", base58_string);
//! ```
//!
//! ## Type Safety
//!
//! Use the newtype wrappers for additional type safety:
//!
//! ```rust
//! use multi_hash::types::{HashDigest, AlgorithmId};
//! use multi_codec::Codec;
//!
//! // Type-safe hash digest
//! let digest = HashDigest::new(vec![0u8; 32]);
//! assert_eq!(digest.len(), 32);
//!
//! // Type-safe algorithm identifier
//! let algo = AlgorithmId::new(Codec::Sha2256);
//! assert_eq!(algo.name(), "sha2-256");
//! ```
//!
//! ## Error Handling
//!
//! ```rust
//! use multi_hash::{Builder, Error};
//! use multi_codec::Codec;
//!
//! // Handle unsupported algorithms
//! match Builder::new(Codec::Identity) {
//!     Ok(_) => println!("Success"),
//!     Err(Error::UnsupportedHash { codec }) => {
//!         eprintln!("Algorithm {:?} not supported", codec);
//!     }
//!     Err(e) => eprintln!("Other error: {}", e),
//! }
//!
//! // Handle missing hash data
//! match Builder::new(Codec::Sha2256).unwrap().try_build() {
//!     Ok(_) => println!("Success"),
//!     Err(Error::MissingHash) => {
//!         eprintln!("Must call with_hash() or update() before try_build()");
//!     }
//!     Err(e) => eprintln!("Other error: {}", e),
//! }
//!
//! // A streamed extendable-output build needs an output length
//! let mut builder = Builder::new(Codec::Shake256).unwrap();
//! builder.update(b"hello world");
//! match builder.try_build() {
//!     Ok(_) => println!("Success"),
//!     Err(Error::OutputLenRequired { codec }) => {
//!         eprintln!("Set an output length for {:?} with output_len()", codec);
//!     }
//!     Err(e) => eprintln!("Other error: {}", e),
//! }
//! ```
//!
//! ## Thread Safety
//!
//! All types are `Send + Sync` and safe for concurrent use:
//!
//! ```rust
//! use std::sync::Arc;
//! use std::thread;
//! use multi_hash::Builder;
//! use multi_codec::Codec;
//!
//! let mut builder = Builder::new(Codec::Sha2256).unwrap();
//! builder.update(b"shared data");
//! let multihash = Arc::new(builder.try_build().unwrap());
//!
//! let handle = thread::spawn(move || {
//!     println!("Hash: {}", hex::encode(multihash.as_ref()));
//! });
//!
//! handle.join().unwrap();
//! ```
//!
//! ## Performance
//!
//! - Hash computation uses optimized cryptographic libraries
//! - Encoding/decoding is efficient with minimal allocations
//! - Builder pattern enables fluent, zero-cost construction
//! - Benchmarks available: `cargo bench -p multi-hash`
//!
//! ## Extendable-Output Functions
//!
//! BLAKE3, SHAKE128, and SHAKE256 are extendable-output functions (XOFs).
//! They produce a digest of any length from 1 to `MAX_HASH_LENGTH` bytes.
//! The builder applies these properties:
//!
//! - **Prefix consistency.** For the same input, the first N bytes of a
//!   longer output equal the output at the shorter length. A 32-byte
//!   SHAKE256 digest is the start of the 64-byte digest of the same
//!   input.
//! - **No extension of a built digest.** A `Multihash` is a completed value.
//!   A digest cannot grow from 32 to 64 bytes without a rehash of the
//!   message through a fresh builder.
//! - **Distinct encodings at every length.** Two outputs of different
//!   lengths encode as distinct multihashes. The encoded length prefix
//!   differs for the two values.
//! - **Capacity versus collision resistance.** The sponge capacity fixes
//!   the security strength of the XOF. The chosen output length bounds the
//!   collision resistance. Recommended minimum outputs are 32 bytes for
//!   BLAKE3 and SHAKE128, and 64 bytes for SHAKE256. A BLAKE3 output
//!   longer than 32 bytes gives no additional collision resistance.
//! - **SHA3 is not truncated SHAKE.** SHA3-256 and 32 bytes of SHAKE256 are
//!   different algorithms with different sponge rates. The codecs
//!   `Sha3256` and `Shake256` name different algorithms.
//!
//! ## Features
//!
//! - **`serde`** (default): Enables serde serialization support
//! - **`fips`**: Exports the `FIPS_CODECS` and `SAFE_FIPS_CODECS`
//!   constants. They list the hash algorithms on the NIST FIPS approved
//!   lists. `SAFE_FIPS_CODECS` omits SHA-1 and the 224-bit algorithms that
//!   SP 800-131A restricts.
//!
//! To disable serde:
//! ```toml
//! [dependencies]
//! multi-hash = { version = "2.0", default-features = false }
//! ```

#![warn(missing_docs)]
#![deny(
    unsafe_code,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

/// Errors produced by this library
pub mod error;
pub use error::Error;

/// Multihash type and functions
pub mod mh;
pub use mh::{
    Builder, EncodedMultihash, HASH_CODECS, MAX_HASH_LENGTH, Multihash, SAFE_HASH_CODECS,
};
// the FIPS approved codec constants export only with the `fips` feature
#[cfg(feature = "fips")]
pub use mh::{FIPS_CODECS, SAFE_FIPS_CODECS};

/// Type-safe wrappers for multihash components
pub mod types;
pub use types::{AlgorithmId, HashDigest};

/// Serde serialization for Multihash
#[cfg(feature = "serde")]
pub mod serde;

/// Commonly used items
///
/// ```
/// use multi_hash::prelude::*;
///
/// let mut builder = Builder::new(Codec::Sha2256).unwrap();
/// builder.update(b"test");
/// let mh = builder.try_build().unwrap();
/// // CodecInfo trait is in prelude
/// assert_eq!(mh.codec(), Codec::Sha2256);
/// ```
pub mod prelude {
    pub use super::*;
    /// re-exports
    pub use multi_base::Base;
    pub use multi_codec::Codec;
    pub use multi_util::{BaseEncoded, CodecInfo};
}
