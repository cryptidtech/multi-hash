// SPDX-License-Identifier: Apache-2.0
//! Property-based tests for multi-hash using proptest

use multi_codec::Codec;
use multi_hash::{Builder, HASH_CODECS, Multihash};
use multi_trait::TryDecodeFrom;
use multi_util::CodecInfo;
use proptest::prelude::*;

/// Property: Multihash encoding and decoding should roundtrip
#[test]
fn test_multihash_roundtrip() {
    proptest!(|(data in prop::collection::vec(any::<u8>(), 0..1024))| {
        for &codec in &HASH_CODECS {
            let mh1 = Builder::new_from_bytes(codec, &data).unwrap().try_build().unwrap();
            let bytes: Vec<u8> = mh1.clone().into();
            let (mh2, remaining) = Multihash::try_decode_from(&bytes).unwrap();

            prop_assert_eq!(mh1, mh2);
            prop_assert!(remaining.is_empty());
        }
    });
}

/// Property: Hash output should be deterministic
#[test]
fn test_hash_deterministic() {
    proptest!(|(data in prop::collection::vec(any::<u8>(), 0..256))| {
        for &codec in HASH_CODECS.iter().take(5) {
            let mh1 = Builder::new_from_bytes(codec, &data).unwrap().try_build().unwrap();
            let mh2 = Builder::new_from_bytes(codec, &data).unwrap().try_build().unwrap();

            prop_assert_eq!(&mh1, &mh2);

            let bytes1: Vec<u8> = mh1.into();
            let bytes2: Vec<u8> = mh2.into();
            prop_assert_eq!(&bytes1, &bytes2);
        }
    });
}

/// Property: Different data should produce different hashes
#[test]
fn test_different_data_different_hash() {
    proptest!(|(data1 in prop::collection::vec(any::<u8>(), 1..256),
                data2 in prop::collection::vec(any::<u8>(), 1..256))| {
        if data1 != data2 {
            let mh1 = Builder::new_from_bytes(Codec::Sha2256, &data1).unwrap().try_build().unwrap();
            let mh2 = Builder::new_from_bytes(Codec::Sha2256, &data2).unwrap().try_build().unwrap();

            prop_assert_ne!(mh1, mh2);
        }
    });
}

/// Property: Codec is preserved through encoding/decoding
#[test]
fn test_codec_preserved() {
    proptest!(|(data in prop::collection::vec(any::<u8>(), 0..256))| {
        for &codec in &HASH_CODECS {
            let mh1 = Builder::new_from_bytes(codec, &data).unwrap().try_build().unwrap();
            let bytes: Vec<u8> = mh1.clone().into();
            let mh2 = Multihash::try_from(bytes.as_ref()).unwrap();

            prop_assert_eq!(mh1.codec(), codec);
            prop_assert_eq!(mh2.codec(), codec);
            prop_assert_eq!(mh1.codec(), mh2.codec());
        }
    });
}

/// Property: Empty data should produce valid hash
#[test]
fn test_empty_data_valid() {
    proptest!(|(_unit in 0..1u8)| {
        for &codec in &HASH_CODECS {
            let result = Builder::new_from_bytes(codec, []);
            prop_assert!(result.is_ok());
        }
    });
}

/// Property: Multihash equality is reflexive
#[test]
fn test_equality_reflexive() {
    proptest!(|(data in prop::collection::vec(any::<u8>(), 0..256))| {
        let mh = Builder::new_from_bytes(Codec::Sha2256, &data).unwrap().try_build().unwrap();
        prop_assert_eq!(&mh, &mh);
    });
}

/// Property: Multihash equality is symmetric
#[test]
fn test_equality_symmetric() {
    proptest!(|(data in prop::collection::vec(any::<u8>(), 0..256))| {
        let mh1 = Builder::new_from_bytes(Codec::Sha2256, &data).unwrap().try_build().unwrap();
        let mh2 = mh1.clone();

        prop_assert_eq!(&mh1, &mh2);
        prop_assert_eq!(&mh2, &mh1);
    });
}

/// Property: Multihash ordering is consistent
#[test]
fn test_ordering_consistent() {
    proptest!(|(data1 in prop::collection::vec(any::<u8>(), 0..128),
                data2 in prop::collection::vec(any::<u8>(), 0..128))| {
        let mh1 = Builder::new_from_bytes(Codec::Sha2256, &data1).unwrap().try_build().unwrap();
        let mh2 = Builder::new_from_bytes(Codec::Sha2256, &data2).unwrap().try_build().unwrap();

        if mh1 < mh2 {
            prop_assert!((mh2 >= mh1));
        }
    });
}
