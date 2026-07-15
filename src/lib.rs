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
//! - Support for 23 cryptographic hash algorithms
//! - Type-safe hash digest and algorithm wrappers
//! - Encoding/decoding with multibase support
//! - Serde serialization (optional)
//! - Builder pattern for hash creation
//!
//! ## Supported Algorithms
//!
//! **Secure algorithms** (recommended for cryptographic use):
//! - Blake2b (224, 256, 384, 512 bits)
//! - Blake2s (224, 256 bits)
//! - Blake3
//! - SHA3 (224, 256, 384, 512 bits)
//!
//! **Legacy algorithms** (for compatibility):
//! - SHA1, SHA2 (224, 256, 384, 512, 512/224, 512/256 bits)
//! - MD5, RIPEMD (128, 160, 256, 320 bits)
//!
//! See [`HASH_CODECS`] for the complete list and [`SAFE_HASH_CODECS`] for recommended algorithms.
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
//! let multihash = Builder::new_from_bytes(Codec::Sha2256, b"hello world")
//!     .unwrap()
//!     .try_build()
//!     .unwrap();
//!
//! assert_eq!(multihash.codec(), Codec::Sha2256);
//! assert_eq!(multihash.as_ref().len(), 32); // SHA2-256 outputs 32 bytes
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
//! let mh1 = Builder::new_from_bytes(Codec::Sha2256, b"data")
//!     .unwrap()
//!     .try_build()
//!     .unwrap();
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
//! let encoded = Builder::new_from_bytes(Codec::Sha2256, b"data")
//!     .unwrap()
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
//! match Builder::new_from_bytes(Codec::Identity, b"data") {
//!     Ok(_) => println!("Success"),
//!     Err(Error::UnsupportedHash { codec }) => {
//!         eprintln!("Algorithm {:?} not supported", codec);
//!     }
//!     Err(e) => eprintln!("Other error: {}", e),
//! }
//!
//! // Handle missing hash data
//! match Builder::new(Codec::Sha2256).try_build() {
//!     Ok(_) => println!("Success"),
//!     Err(Error::MissingHash) => {
//!         eprintln!("Must call with_hash() before build()");
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
//! let multihash = Arc::new(
//!     Builder::new_from_bytes(Codec::Sha2256, b"shared data")
//!         .unwrap()
//!         .try_build()
//!         .unwrap()
//! );
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
//! ## Features
//!
//! - **`serde`** (default): Enables serde serialization support
//!
//! To disable serde:
//! ```toml
//! [dependencies]
//! multi-hash = { version = "1.0", default-features = false }
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
pub use mh::{Builder, EncodedMultihash, HASH_CODECS, Multihash, SAFE_HASH_CODECS};

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
/// let mh = Builder::new_from_bytes(Codec::Sha2256, b"test")
///     .unwrap()
///     .try_build()
///     .unwrap();
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
