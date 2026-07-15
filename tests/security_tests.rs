// SPDX-License-Identifier: Apache-2.0
//! Security-focused tests for multi-hash

use multi_codec::Codec;
use multi_hash::{Builder, Error, Multihash, SAFE_HASH_CODECS};
use multi_util::CodecInfo;

/// Test that invalid codec is rejected
#[test]
fn test_invalid_codec_rejected() {
    let result = Builder::new_from_bytes(Codec::DagCbor, b"data");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::UnsupportedHash { .. }));
}

/// Test that empty hash data is detected
#[test]
fn test_missing_hash_detected() {
    let result = Builder::new(Codec::Sha2256).try_build();
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::MissingHash));
}

/// Test malformed multihash data is rejected
#[test]
fn test_malformed_data_rejected() {
    // Invalid varint encoding
    let invalid = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let result = Multihash::try_from(invalid.as_ref());
    assert!(result.is_err());
}

/// Test truncated multihash is rejected
#[test]
fn test_truncated_multihash() {
    // Just a codec byte, no length or hash data
    let truncated = vec![0x12]; // SHA2-256 codec
    let result = Multihash::try_from(truncated.as_ref());
    assert!(result.is_err());
}

/// Test empty byte array is rejected
#[test]
fn test_empty_bytes_rejected() {
    let result = Multihash::try_from(&[] as &[u8]);
    assert!(result.is_err());
}

/// Test concurrent hash computation
#[test]
fn test_concurrent_hashing() {
    use std::sync::Arc;
    use std::thread;

    let data = Arc::new(b"concurrent test data".to_vec());
    let mut handles = vec![];

    for _ in 0..4 {
        let data_clone = Arc::clone(&data);
        let handle = thread::spawn(move || {
            for _ in 0..10 {
                let mh = Builder::new_from_bytes(Codec::Sha2256, data_clone.as_ref())
                    .unwrap()
                    .try_build()
                    .unwrap();
                assert_eq!(mh.codec(), Codec::Sha2256);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

/// Test that same input produces same hash across threads
#[test]
fn test_deterministic_across_threads() {
    use std::thread;

    let data = b"deterministic test";

    let mh1 = Builder::new_from_bytes(Codec::Sha2256, data)
        .unwrap()
        .try_build()
        .unwrap();

    let handle = thread::spawn(move || {
        Builder::new_from_bytes(Codec::Sha2256, data)
            .unwrap()
            .try_build()
            .unwrap()
    });

    let mh2 = handle.join().unwrap();
    assert_eq!(mh1, mh2);
}

/// Test null multihash is safe
#[test]
fn test_null_safety() {
    use multi_trait::Null;

    let null_mh = Multihash::null();
    assert!(null_mh.is_null());

    // Encoding null should not panic
    let bytes: Vec<u8> = null_mh.into();
    let decoded = Multihash::try_from(bytes.as_ref()).unwrap();
    assert!(decoded.is_null());
}

/// Test error types are Send + Sync
#[test]
fn test_error_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<Error>();
    assert_sync::<Error>();
}

/// Test all safe hash codecs work
#[test]
fn test_safe_hash_codecs_functional() {
    let data = b"safety test data";

    for &codec in &SAFE_HASH_CODECS {
        let mh = Builder::new_from_bytes(codec, data)
            .unwrap()
            .try_build()
            .unwrap();

        assert_eq!(mh.codec(), codec);

        // Should roundtrip
        let bytes: Vec<u8> = mh.clone().into();
        let decoded = Multihash::try_from(bytes.as_ref()).unwrap();
        assert_eq!(mh, decoded);
    }
}
