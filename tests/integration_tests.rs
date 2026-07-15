// SPDX-License-Identifier: Apache-2.0
//! Integration tests for multi-hash with other workspace crates
#![allow(clippy::unreadable_literal)]

use multi_base::Base;
use multi_codec::Codec;
use multi_hash::{Builder, Multihash};
use multi_trait::TryDecodeFrom;
use multi_util::{CodecInfo, EncodingInfo};

/// Test integration with multi-codec
#[test]
fn test_multicodec_integration() {
    // Verify all hash codecs are valid Codec values
    use multi_hash::HASH_CODECS;

    for &codec in &HASH_CODECS {
        // Should be able to get codec properties
        let code = codec.code();
        let name = codec.as_str();

        assert!(code > 0);
        assert!(!name.is_empty());
    }
}

/// Test integration with multi-base through `EncodedMultihash`
#[test]
fn test_multibase_integration() {
    // Test with various base encodings
    let bases = vec![
        Base::Base16Lower,
        Base::Base32Lower,
        Base::Base58Btc,
        Base::Base64,
    ];

    for base in bases {
        let encoded = Builder::new_from_bytes(Codec::Sha2256, b"test data")
            .unwrap()
            .with_base_encoding(base)
            .try_build_encoded()
            .unwrap();

        // Should be able to convert to string and back
        let s = encoded.to_string();
        assert!(!s.is_empty());

        // Encoding should preserve the base
        assert_eq!(encoded.encoding(), base);
    }
}

/// Test integration with multi-trait
#[test]
fn test_multitrait_integration() {
    let mh1 = Builder::new_from_bytes(Codec::Sha3256, b"multitrait test")
        .unwrap()
        .try_build()
        .unwrap();

    // Convert to bytes using Into (from multitrait patterns)
    let bytes: Vec<u8> = mh1.clone().into();

    // Use TryDecodeFrom from multitrait
    let (mh2, remaining) = Multihash::try_decode_from(&bytes).unwrap();

    assert_eq!(mh1, mh2);
    assert!(remaining.is_empty());
}

/// Test integration with multi-util `BaseEncoded`
#[test]
fn test_multiutil_integration() {
    let mh = Builder::new_from_bytes(Codec::Blake3, b"multiutil test")
        .unwrap()
        .try_build()
        .unwrap();

    // CodecInfo trait from multiutil
    assert_eq!(mh.codec(), Codec::Blake3);
    assert_eq!(Multihash::preferred_codec(), Codec::Multihash);

    // EncodingInfo trait from multiutil
    assert_eq!(mh.encoding(), Base::Base16Lower);
    assert_eq!(Multihash::preferred_encoding(), Base::Base16Lower);
}

/// Test `EncodedMultihash` uses `BaseEncoded` from multiutil
#[test]
fn test_encoded_multihash_type() {
    use multi_hash::EncodedMultihash;

    let encoded = Builder::new_from_bytes(Codec::Sha2512, b"encoded test")
        .unwrap()
        .with_base_encoding(Base::Base64)
        .try_build_encoded()
        .unwrap();

    // EncodedMultihash is a type alias to BaseEncoded
    let _: &EncodedMultihash = &encoded;

    // Should have encoding info
    assert_eq!(encoded.encoding(), Base::Base64);
}

/// Test multihash in data structures
#[test]
fn test_in_collections() {
    use std::collections::BTreeMap;

    let mh1 = Builder::new_from_bytes(Codec::Sha2256, b"key1")
        .unwrap()
        .try_build()
        .unwrap();
    let mh2 = Builder::new_from_bytes(Codec::Sha2256, b"key2")
        .unwrap()
        .try_build()
        .unwrap();

    // BTreeMap (requires Ord)
    let mut btree = BTreeMap::new();
    btree.insert(mh1.clone(), "value1");
    btree.insert(mh2.clone(), "value2");
    assert_eq!(btree.len(), 2);

    // Vec
    let vec = [mh1, mh2];
    assert_eq!(vec.len(), 2);
}

/// Test builder pattern fluency
#[test]
fn test_builder_fluent_api() {
    let result = Builder::new(Codec::Sha3384)
        .with_hash(vec![0u8; 48])
        .with_base_encoding(Base::Base58Btc)
        .try_build_encoded();

    assert!(result.is_ok());
}

/// Test all workspace crate types work together
#[test]
fn test_full_workspace_integration() {
    // Use types from all workspace crates together
    let codec = Codec::Sha2256; // multi-codec
    let base = Base::Base32Lower; // multi-base

    // Create multihash (multi-hash)
    let mh = Builder::new_from_bytes(codec, b"integration")
        .unwrap()
        .try_build()
        .unwrap();

    // Verify traits from multi-util work
    assert_eq!(mh.codec(), codec);
    assert_eq!(mh.encoding(), Base::Base16Lower);

    // Verify we can create encoded version (uses BaseEncoded from multiutil)
    let encoded = Builder::new_from_bytes(codec, b"integration")
        .unwrap()
        .with_base_encoding(base)
        .try_build_encoded()
        .unwrap();

    assert_eq!(encoded.encoding(), base);

    // Verify encoding works
    let s = encoded.to_string();
    assert!(!s.is_empty());
}

#[cfg(feature = "serde")]
mod serde_integration {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// Test multihash in serde structs
    #[test]
    fn test_multihash_in_struct() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Document {
            hash: Multihash,
            timestamp: u64,
        }

        let doc = Document {
            hash: Builder::new_from_bytes(Codec::Sha2256, b"document")
                .unwrap()
                .try_build()
                .unwrap(),
            timestamp: 1234567890,
        };

        // JSON roundtrip
        let json = serde_json::to_string(&doc).unwrap();
        let decoded: Document = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, decoded);

        // CBOR roundtrip
        let cbor = serde_cbor::to_vec(&doc).unwrap();
        let decoded: Document = serde_cbor::from_slice(&cbor).unwrap();
        assert_eq!(doc, decoded);
    }
}
