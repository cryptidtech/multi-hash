// SPDX-License-Identifier: Apache-2.0
//! Edge case tests for multi-hash

use multi_codec::Codec;
use multi_hash::{Builder, Error, HASH_CODECS, Multihash, SAFE_HASH_CODECS};
use multi_trait::{Null, TryDecodeFrom};
use multi_util::CodecInfo;

/// Test all supported hash algorithms with empty input
#[test]
fn test_all_algorithms_empty_input() {
    for &codec in &HASH_CODECS {
        let result = Builder::new_from_bytes(codec, []);
        assert!(result.is_ok(), "Failed for {codec:?}");

        let mh = result.unwrap().try_build().unwrap();
        assert_eq!(mh.codec(), codec);
    }
}

/// Test all supported hash algorithms with single byte
#[test]
fn test_all_algorithms_single_byte() {
    for &codec in &HASH_CODECS {
        let mh = Builder::new_from_bytes(codec, [0x42])
            .unwrap()
            .try_build()
            .unwrap();
        assert_eq!(mh.codec(), codec);
        assert!(!mh.as_ref().is_empty());
    }
}

/// Test null/default multihash
#[test]
fn test_null_multihash() {
    let null_mh = Multihash::null();
    assert!(null_mh.is_null());
    assert_eq!(null_mh, Multihash::default());

    // Null should have Identity codec and empty hash
    assert_eq!(null_mh.codec(), Codec::Identity);
    assert_eq!(null_mh.as_ref(), &[] as &[u8]);
}

/// Test builder without hash data fails
#[test]
fn test_builder_missing_hash() {
    let result = Builder::new(Codec::Sha2256).try_build();
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::MissingHash));
}

/// Test unsupported hash algorithm
#[test]
fn test_unsupported_algorithm() {
    let result = Builder::new_from_bytes(Codec::Identity, b"data");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::UnsupportedHash { .. }));
}

/// Test multihash with maximum size data
#[test]
fn test_large_data() {
    let large_data = vec![0u8; 1024 * 1024]; // 1MB
    let mh = Builder::new_from_bytes(Codec::Sha2256, &large_data)
        .unwrap()
        .try_build()
        .unwrap();
    assert_eq!(mh.codec(), Codec::Sha2256);
    assert_eq!(mh.as_ref().len(), 32); // SHA2-256 always outputs 32 bytes
}

/// Test binary encoding/decoding roundtrip
#[test]
fn test_binary_roundtrip_all_algorithms() {
    let data = b"test data";

    for &codec in &HASH_CODECS {
        let mh1 = Builder::new_from_bytes(codec, data)
            .unwrap()
            .try_build()
            .unwrap();

        let bytes: Vec<u8> = mh1.clone().into();
        let mh2 = Multihash::try_from(bytes.as_ref()).unwrap();

        assert_eq!(mh1, mh2);
        assert_eq!(mh1.codec(), mh2.codec());
    }
}

/// Test `SAFE_HASH_CODECS` are subset of `HASH_CODECS`
#[test]
fn test_safe_codecs_subset() {
    for &safe_codec in &SAFE_HASH_CODECS {
        assert!(
            HASH_CODECS.contains(&safe_codec),
            "{safe_codec:?} not in HASH_CODECS"
        );
    }
}

/// Test multihash equality
#[test]
fn test_multihash_equality() {
    let mh1 = Builder::new_from_bytes(Codec::Sha2256, b"data")
        .unwrap()
        .try_build()
        .unwrap();
    let mh2 = mh1.clone();

    assert_eq!(mh1, mh2);
    assert_eq!(mh1, mh1);
}

/// Test multihash ordering
#[test]
fn test_multihash_ordering() {
    let mh1 = Builder::new_from_bytes(Codec::Sha2256, b"aaa")
        .unwrap()
        .try_build()
        .unwrap();
    let mh2 = Builder::new_from_bytes(Codec::Sha2256, b"bbb")
        .unwrap()
        .try_build()
        .unwrap();

    // Different data produces different hashes, so ordering is meaningful
    assert_ne!(mh1, mh2);
}

/// Test `AsRef` implementation
#[test]
fn test_as_ref() {
    let mh = Builder::new_from_bytes(Codec::Sha2256, b"test")
        .unwrap()
        .try_build()
        .unwrap();

    let bytes: &[u8] = mh.as_ref();
    assert_eq!(bytes.len(), 32); // SHA2-256 output size
}

/// Test Debug formatting
#[test]
fn test_debug_format() {
    let mh = Builder::new_from_bytes(Codec::Sha2256, b"test")
        .unwrap()
        .try_build()
        .unwrap();

    let debug_str = format!("{mh:?}");
    assert!(!debug_str.is_empty());
    assert!(debug_str.len() > 10);
}

/// Test builder with manual hash setting
#[test]
fn test_builder_with_hash() {
    let hash_bytes = vec![0u8; 32];
    let mh = Builder::new(Codec::Sha2256)
        .with_hash(hash_bytes.clone())
        .try_build()
        .unwrap();

    assert_eq!(mh.codec(), Codec::Sha2256);
    assert_eq!(mh.as_ref(), hash_bytes.as_slice());
}

/// Test that Clone works correctly
#[test]
fn test_clone() {
    let mh1 = Builder::new_from_bytes(Codec::Sha3256, b"clone test")
        .unwrap()
        .try_build()
        .unwrap();
    let mh2 = mh1.clone();

    assert_eq!(mh1, mh2);
    assert_eq!(mh1.codec(), mh2.codec());
    assert_eq!(mh1.as_ref(), mh2.as_ref());
}

/// Test `TryDecodeFrom` with trailing data
#[test]
fn test_decode_with_trailing_data() {
    let mh1 = Builder::new_from_bytes(Codec::Sha2256, b"test")
        .unwrap()
        .try_build()
        .unwrap();

    let mut bytes: Vec<u8> = mh1.clone().into();
    bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

    let (mh2, remaining) = Multihash::try_decode_from(&bytes).unwrap();
    assert_eq!(mh1, mh2);
    assert_eq!(remaining, &[0xAA, 0xBB, 0xCC]);
}

/// Test that truncated data fails gracefully
#[test]
fn test_truncated_data() {
    let mh = Builder::new_from_bytes(Codec::Sha2256, b"test")
        .unwrap()
        .try_build()
        .unwrap();

    let bytes: Vec<u8> = mh.into();

    // Try decoding with just first byte (codec only, no length/hash)
    if !bytes.is_empty() {
        let truncated = &bytes[..1];
        let result = Multihash::try_from(truncated);
        // Should fail due to insufficient data
        assert!(result.is_err());
    }
}

/// Test Send and Sync bounds
#[test]
fn test_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<Multihash>();
    assert_sync::<Multihash>();
    assert_send::<Builder>();
    assert_sync::<Builder>();
}
