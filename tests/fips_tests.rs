// SPDX-License-Identifier: Apache-2.0
//! FIPS approved codec tests for multi-hash
//!
//! With the `fips` feature enabled, the crate exposes the `FIPS_CODECS`
//! and `SAFE_FIPS_CODECS` constants covering the hash algorithms on the
//! NIST FIPS approved lists. These tests pin the shape of both lists,
//! keep them contained in the general codec lists, and build a multihash
//! for every approved codec through the builder, checking the digests
//! of a sample against independently generated known-answer values.
#![cfg(feature = "fips")]

use multi_codec::Codec;
use multi_hash::{Builder, FIPS_CODECS, HASH_CODECS, Multihash, SAFE_FIPS_CODECS};
use multi_util::CodecInfo;

/// the FIPS approved codec entries the safe FIPS list omits
///
/// SHA-1 is restricted to verification-only use under SP 800-131A Rev. 2,
/// and the 224-bit hashes SHA-224, SHA-512/224, and SHA3-224 fall under the
/// SP 800-131A Rev. 3 draft restrictions through 2030. SHA-512/256 does not
/// fall under those restrictions, but the safe list omits it under the same
/// reduced-selection principle that `SAFE_HASH_CODECS` applies.
/// `SAFE_FIPS_CODECS` must omit exactly these entries.
const RESTRICTED_FIPS_CODECS: [Codec; 5] = [
    Codec::Sha1,
    Codec::Sha2224,
    Codec::Sha2512224,
    Codec::Sha2512256,
    Codec::Sha3224,
];

/// the message the known-answer vectors hash
const KAT_MESSAGE: &[u8] = b"multihash";

/// sha1 digest of `KAT_MESSAGE`, per `coreutils sha1sum` and
/// `openssl dgst -sha1`
const SHA1_KAT: [u8; 20] = [
    0x88, 0xc2, 0xf1, 0x1f, 0xb2, 0xce, 0x39, 0x2a, 0xcb, 0x5b, 0x29, 0x86, 0xe6, 0x40, 0x21, 0x1c,
    0x46, 0x90, 0x07, 0x3e,
];

/// sha2-256 digest of `KAT_MESSAGE`, the multiformats example vector, also
/// matching `coreutils sha256sum` and `openssl dgst -sha256`
const SHA2_256_KAT: [u8; 32] = [
    0x9c, 0xbc, 0x07, 0xc3, 0xf9, 0x91, 0x72, 0x58, 0x36, 0xa3, 0xaa, 0x2a, 0x58, 0x1c, 0xa2, 0x02,
    0x91, 0x98, 0xaa, 0x42, 0x0b, 0x9d, 0x99, 0xbc, 0x0e, 0x13, 0x1d, 0x9f, 0x3e, 0x2c, 0xbe, 0x47,
];

/// sha3-256 digest of `KAT_MESSAGE`, per `openssl dgst -sha3-256` and GNU
/// coreutils `sha3sum`
const SHA3_256_KAT: [u8; 32] = [
    0x08, 0xc3, 0x79, 0x2b, 0x2a, 0x4d, 0xee, 0xd1, 0xbd, 0x7e, 0xa2, 0x32, 0x8f, 0xb5, 0xde, 0x55,
    0x31, 0xec, 0xcf, 0x0f, 0xbf, 0xa0, 0x4a, 0x7d, 0x80, 0x0c, 0xdc, 0x26, 0x71, 0x37, 0xc6, 0x35,
];

/// shake128 of `KAT_MESSAGE` in 32 bytes, per `openssl dgst -shake128
/// -xoflen 32`
const SHAKE128_KAT: [u8; 32] = [
    0xd3, 0x70, 0x45, 0x66, 0x3a, 0x07, 0xfb, 0x35, 0xec, 0x57, 0x1d, 0x8f, 0x6e, 0xf9, 0x83, 0x00,
    0xa2, 0xda, 0xa5, 0xa8, 0x2d, 0x9d, 0x05, 0x5e, 0x68, 0x4b, 0xc2, 0x92, 0xe9, 0x8a, 0x02, 0xa3,
];

/// one known-answer vector: the codec and the digest it must produce
struct KatVector {
    /// the FIPS codec the vector applies to
    codec: Codec,

    /// the expected digest, digest bytes only, with no multihash coding
    expected: &'static [u8],
}

/// known-answer vectors for one codec from each FIPS family
///
/// Each vector hashes [`KAT_MESSAGE`]: SHA-1 for the SHA-1 family, SHA-256
/// for the SHA-2 family, SHA3-256 for the SHA-3 family, and SHAKE128 for
/// the SHAKE extendable-output functions.
const KAT_VECTORS: [KatVector; 4] = [
    KatVector {
        codec: Codec::Sha1,
        expected: &SHA1_KAT,
    },
    KatVector {
        codec: Codec::Sha2256,
        expected: &SHA2_256_KAT,
    },
    KatVector {
        codec: Codec::Sha3256,
        expected: &SHA3_256_KAT,
    },
    KatVector {
        codec: Codec::Shake128,
        expected: &SHAKE128_KAT,
    },
];

/// the output length these tests request for an XOF codec
///
/// Fixed-output codecs ignore an output length, so the helper applies
/// only to the Shake arms.
const fn xof_output_len(codec: Codec) -> Option<usize> {
    match codec {
        Codec::Shake128 => Some(32),
        Codec::Shake256 => Some(64),
        _ => None,
    }
}

/// the digest length each FIPS codec must produce
///
/// The fixed-output entries are the algorithms' exact output lengths, and
/// the Shake entries are the recommended minimum outputs, 32 bytes for
/// `Shake128` and 64 bytes for `Shake256`. Returns `None` for codecs
/// outside `FIPS_CODECS`.
const fn expected_digest_len(codec: Codec) -> Option<usize> {
    match codec {
        Codec::Sha1 => Some(20),
        Codec::Sha2224 | Codec::Sha2512224 | Codec::Sha3224 => Some(28),
        Codec::Sha2256 | Codec::Sha2512256 | Codec::Sha3256 | Codec::Shake128 => Some(32),
        Codec::Sha2384 | Codec::Sha3384 => Some(48),
        Codec::Sha2512 | Codec::Sha3512 | Codec::Shake256 => Some(64),
        _ => None,
    }
}

/// stream `message` through the builder in chunks of at most three bytes,
/// request the recommended output length for an XOF codec, and build the
/// multihash
fn streamed_multihash(codec: Codec, message: &[u8]) -> Multihash {
    let mut builder = Builder::new(codec).unwrap();
    for chunk in message.chunks(3) {
        builder.update(chunk);
    }
    if let Some(output_len) = xof_output_len(codec) {
        builder.output_len(output_len);
    }
    builder.try_build().unwrap()
}

/// the full FIPS list holds 13 codecs and the safe list holds 8, with no
/// duplicate entries in either constant
#[test]
fn test_fips_constant_lengths() {
    assert_eq!(FIPS_CODECS.len(), 13);
    assert_eq!(SAFE_FIPS_CODECS.len(), 8);

    for (index, codec) in FIPS_CODECS.iter().enumerate() {
        assert!(
            !FIPS_CODECS[..index].contains(codec),
            "{codec:?} appears more than once in FIPS_CODECS"
        );
    }
    for (index, codec) in SAFE_FIPS_CODECS.iter().enumerate() {
        assert!(
            !SAFE_FIPS_CODECS[..index].contains(codec),
            "{codec:?} appears more than once in SAFE_FIPS_CODECS"
        );
    }
}

/// every entry of the full FIPS list is a supported hash codec
#[test]
fn test_fips_codecs_are_supported_hash_codecs() {
    for &codec in &FIPS_CODECS {
        assert!(
            HASH_CODECS.contains(&codec),
            "{codec:?} is missing from HASH_CODECS"
        );
    }
}

/// every entry of the safe FIPS list is a full-list FIPS codec
#[test]
fn test_safe_fips_codecs_are_fips_codecs() {
    for &codec in &SAFE_FIPS_CODECS {
        assert!(
            FIPS_CODECS.contains(&codec),
            "{codec:?} is missing from FIPS_CODECS"
        );
    }
}

/// the safe FIPS list omits exactly the restricted and deprecated entries
#[test]
fn test_safe_list_excludes_restricted_and_deprecated_codecs() {
    for &codec in &RESTRICTED_FIPS_CODECS {
        assert!(
            FIPS_CODECS.contains(&codec),
            "{codec:?} is missing from FIPS_CODECS"
        );
        assert!(
            !SAFE_FIPS_CODECS.contains(&codec),
            "{codec:?} must not appear in SAFE_FIPS_CODECS"
        );
    }

    // with the length test pinning 13 and 8 entries, this complement
    // check makes `SAFE_FIPS_CODECS` the exact remainder of
    // `FIPS_CODECS` once the restricted and deprecated entries are
    // removed
    for &codec in &FIPS_CODECS {
        assert_eq!(
            SAFE_FIPS_CODECS.contains(&codec),
            !RESTRICTED_FIPS_CODECS.contains(&codec),
            "{codec:?} membership disagrees between the two FIPS lists"
        );
    }
}

/// every FIPS codec builds a streamed multihash with its expected digest
/// length
#[test]
fn test_each_fips_codec_builds_with_expected_digest_length() {
    let message: &[u8] = b"every FIPS approved codec hashes through the streaming builder";

    for &codec in &FIPS_CODECS {
        let mh = streamed_multihash(codec, message);
        let expected_len =
            expected_digest_len(codec).expect("FIPS codec has an expected digest length");

        assert_eq!(mh.codec(), codec, "codec of the built {codec:?} multihash");
        assert_eq!(mh.as_ref().len(), expected_len, "{codec:?} digest length");
    }
}

/// each known-answer vector hashes the message to its expected digest
#[test]
fn test_known_answer_digests() {
    for vector in &KAT_VECTORS {
        let mh = streamed_multihash(vector.codec, KAT_MESSAGE);
        assert_eq!(
            mh.as_ref(),
            vector.expected,
            "{:?} digest of the known-answer message",
            vector.codec
        );
    }
}
