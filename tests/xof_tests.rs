// SPDX-License-Identifier: Apache-2.0
//! XOF tests for the `Shake128` and `Shake256` codecs
//!
//! The known-answer vectors below come from the Keccak team FIPS 202 KAT
//! files `ShortMsgKAT_SHAKE128.txt` and `ShortMsgKAT_SHAKE256.txt` in the
//! XKCP repository at <https://github.com/XKCP/XKCP>. Each file's
//! `Squeezed` field supplies a 512-byte output stream; the constants here
//! are the first 128 bytes of that field. SHAKE output is
//! prefix-consistent: the same input squeezed to a short length is a
//! prefix of the same input squeezed to a longer length, so any prefix up
//! to the full 128 bytes is a valid expected value for the same message.
#![allow(clippy::unreadable_literal)]

use multi_base::Base;
use multi_codec::Codec;
use multi_hash::{Builder, EncodedMultihash, Error, MAX_HASH_LENGTH, Multihash};
use multi_util::{CodecInfo, EncodingInfo};

/// SHAKE128 of the empty message, first 128 bytes of the 512-byte
/// `Squeezed` field in `ShortMsgKAT_SHAKE128.txt` at
/// <https://github.com/XKCP/XKCP>
const SHAKE128_EMPTY: &str = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea";

/// SHAKE128 of the single byte 0xCC, first 128 bytes of the 512-byte
/// `Squeezed` field in `ShortMsgKAT_SHAKE128.txt` at
/// <https://github.com/XKCP/XKCP>
const SHAKE128_ONE_CC: &str = "4dd4b0004a7d9e613a0f488b4846f804015f0f8ccdba5f7c16810bbc5a1c6fb254efc81969c5eb49e682babae02238a31fd2708e418d7b754e21e4b75b65e7d39b5b42d739066e7c63595daf26c3a6a2f7001ee636c7cb2a6c69b1ec7314a21ff24833eab61258327517b684928c7444380a6eacd60a6e9400da37a61050e4cd";

/// SHAKE256 of the empty message, first 128 bytes of the 512-byte
/// `Squeezed` field in `ShortMsgKAT_SHAKE256.txt` at
/// <https://github.com/XKCP/XKCP>
const SHAKE256_EMPTY: &str = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86";

/// SHAKE256 of the single byte 0xCC, first 128 bytes of the 512-byte
/// `Squeezed` field in `ShortMsgKAT_SHAKE256.txt` at
/// <https://github.com/XKCP/XKCP>
const SHAKE256_ONE_CC: &str = "ddbf55dbf65977e3e2a3674d33e479f78163d592666bc576feb5e4c404ea5e5329c3a416be758687de1a55e23d9e48a7d3f3ce6d8f0b2006a935800eca9c9fc903d86f065367221067658b4d7473ed54800d196fbe1089811dd9b47f21e3698b1573653adad231c39f145b586d6c0133378416138e4423f7af7dacffe965706a";

/// one known-answer vector: the codec, the message it hashes, and the
/// expected digest
struct KatVector {
    /// the XOF codec the vector applies to
    codec: Codec,

    /// the message the vector hashes
    message: &'static [u8],

    /// the expected digest, lowercase hex, as a prefix of the 512-byte
    /// `Squeezed` stream from the XKCP KAT file
    expected: &'static str,
}

/// the four known-answer vectors: `{Shake128, Shake256}` each over the
/// empty message and the single byte 0xCC
const KAT_VECTORS: [KatVector; 4] = [
    KatVector {
        codec: Codec::Shake128,
        message: &[],
        expected: SHAKE128_EMPTY,
    },
    KatVector {
        codec: Codec::Shake128,
        message: &[0xCC],
        expected: SHAKE128_ONE_CC,
    },
    KatVector {
        codec: Codec::Shake256,
        message: &[],
        expected: SHAKE256_EMPTY,
    },
    KatVector {
        codec: Codec::Shake256,
        message: &[0xCC],
        expected: SHAKE256_ONE_CC,
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

/// stream `message` through the builder in chunks of at most three bytes,
/// request `output_len` digest bytes, and build the multihash
///
/// The empty message still gets one empty update call, so the builder owns
/// hashing state when it builds.
fn streamed_multihash(codec: Codec, message: &[u8], output_len: usize) -> Multihash {
    let mut builder = Builder::new(codec).unwrap();
    if message.is_empty() {
        builder.update([]);
    }
    for chunk in message.chunks(3) {
        builder.update(chunk);
    }
    builder.output_len(output_len);
    builder.try_build().unwrap()
}

/// each KAT vector matches at short, medium, and full digest lengths, with
/// the message streamed through the builder in chunks
#[test]
fn test_kat_vectors_at_multiple_lengths() {
    for vector in &KAT_VECTORS {
        let expected = hex::decode(vector.expected).unwrap();
        assert_eq!(
            expected.len(),
            128,
            "vector {:?}: not 128 digest bytes",
            vector.codec
        );

        for &output_len in &[1usize, 8, 32, 64, 100, 128] {
            let mh = streamed_multihash(vector.codec, vector.message, output_len);
            assert_eq!(
                mh.codec(),
                vector.codec,
                "codec of the {output_len}-byte digest"
            );
            assert_eq!(
                mh.as_ref().len(),
                output_len,
                "{:?} digest length",
                vector.codec
            );
            assert_eq!(
                mh.as_ref(),
                &expected[..output_len],
                "{:?} of message {:02x?} squeezed to {output_len} bytes",
                vector.codec,
                vector.message
            );
        }
    }
}

/// streaming the same input in chunks produces the same multihash as one
/// full update, at several digest lengths
#[test]
fn test_streaming_matches_one_shot() {
    let message: &[u8] = b"the same input must hash to the same digest however it is chunked";

    for &codec in &[Codec::Shake128, Codec::Shake256] {
        for &output_len in &[32usize, 64, 100] {
            let mut builder = Builder::new(codec).unwrap();
            builder.update(&message[..12]);
            builder.update(&message[12..33]);
            builder.update(&message[33..]);
            builder.output_len(output_len);
            let chunked = builder.try_build().unwrap();

            let one_shot = streamed_multihash(codec, message, output_len);

            assert_eq!(chunked, one_shot, "{codec:?} at {output_len} bytes");
        }
    }
}

/// the digest of a shorter squeeze is a prefix of the digest of a longer
/// squeeze of the same input, for both codecs
#[test]
fn test_digest_prefix_consistency() {
    let message: &[u8] = b"prefix consistency across squeeze lengths";

    for &codec in &[Codec::Shake128, Codec::Shake256] {
        let lengths = [1usize, 16, 32, 64, 128];
        let digests: Vec<Multihash> = lengths
            .iter()
            .map(|&output_len| streamed_multihash(codec, message, output_len))
            .collect();

        for window in digests.windows(2) {
            let (short, long) = (&window[0], &window[1]);
            assert!(
                long.as_ref().starts_with(short.as_ref()),
                "{codec:?}: short digest is not a prefix of the long digest"
            );
        }
    }
}

/// two digest lengths of the same input encode as distinct multihashes:
/// the raw encodings differ and the encoded digest-length field differs,
/// even though the short digest prefixes the long one
#[test]
fn test_distinct_lengths_distinct_encodings() {
    let message: &[u8] = b"the digest length is part of the identity of a multihash";

    for &codec in &[Codec::Shake128, Codec::Shake256] {
        let short = streamed_multihash(codec, message, 32);
        let long = streamed_multihash(codec, message, 64);
        assert!(
            long.as_ref().starts_with(short.as_ref()),
            "{codec:?}: short digest is not a prefix of the long digest"
        );

        let short_bytes: Vec<u8> = short.clone().into();
        let long_bytes: Vec<u8> = long.into();
        assert_ne!(short_bytes, long_bytes, "{codec:?}: encodings matched");

        // one codec varint byte and one digest-length varint byte: 32 and
        // 64 fit in one unsigned varint byte each, so the second encoded
        // byte carries the digest length
        assert_ne!(
            short_bytes[1], long_bytes[1],
            "{codec:?}: length prefix matched"
        );

        let short_decoded = Multihash::try_from(short_bytes.as_ref()).unwrap();
        let long_decoded = Multihash::try_from(long_bytes.as_ref()).unwrap();
        assert_eq!(short_decoded.as_ref().len(), 32, "{codec:?}");
        assert_eq!(long_decoded.as_ref().len(), 64, "{codec:?}");
    }
}

/// a built XOF multihash roundtrips through its binary encoding
#[test]
fn test_binary_roundtrip() {
    for &codec in &[Codec::Shake128, Codec::Shake256] {
        for &output_len in &[32usize, 64, 128] {
            let mh = streamed_multihash(codec, b"binary roundtrip", output_len);

            let bytes: Vec<u8> = mh.clone().into();
            let decoded = Multihash::try_from(bytes.as_ref()).unwrap();

            assert_eq!(mh, decoded, "{codec:?} at {output_len} bytes");
        }
    }
}

/// an encoded XOF multihash roundtrips through its multibase string form
#[test]
fn test_multibase_roundtrip() {
    let bases = [
        Base::Base16Lower,
        Base::Base32Lower,
        Base::Base58Btc,
        Base::Base64,
    ];

    for &codec in &[Codec::Shake128, Codec::Shake256] {
        let output_len = xof_output_len(codec).unwrap();

        for &base in &bases {
            let mut builder = Builder::new(codec).unwrap();
            builder.update(b"multibase roundtrip");
            builder.output_len(output_len);
            let encoded = builder
                .with_base_encoding(base)
                .try_build_encoded()
                .unwrap();

            let s = encoded.to_string();
            assert_eq!(
                encoded,
                EncodedMultihash::try_from(s.as_str()).unwrap(),
                "{codec:?} in {base:?}"
            );
            assert_eq!(encoded.encoding(), base, "{codec:?} in {base:?}");
        }
    }
}

/// a zero output length is rejected with the requested length and the
/// maximum named in the error
#[test]
fn test_zero_output_len_rejected() {
    for &codec in &[Codec::Shake128, Codec::Shake256] {
        let mut builder = Builder::new(codec).unwrap();
        builder.update(b"zero output length");
        builder.output_len(0);

        let Err(Error::OutputLenInvalid {
            codec: error_codec,
            output_len,
            max,
        }) = builder.try_build()
        else {
            panic!("{codec:?} accepted a zero output length");
        };

        assert_eq!(error_codec, codec);
        assert_eq!(output_len, 0);
        assert_eq!(max, MAX_HASH_LENGTH);
    }
}

/// an output length one byte over `MAX_HASH_LENGTH` is rejected with the
/// requested length and the maximum named in the error
#[test]
fn test_over_max_output_len_rejected() {
    for &codec in &[Codec::Shake128, Codec::Shake256] {
        let mut builder = Builder::new(codec).unwrap();
        builder.update(b"over-limit output length");
        builder.output_len(MAX_HASH_LENGTH + 1);

        let Err(Error::OutputLenInvalid {
            codec: error_codec,
            output_len,
            max,
        }) = builder.try_build()
        else {
            panic!("{codec:?} accepted an over-limit output length");
        };

        assert_eq!(error_codec, codec);
        assert_eq!(output_len, MAX_HASH_LENGTH + 1);
        assert_eq!(max, MAX_HASH_LENGTH);
    }
}

/// streaming an XOF without an output length is rejected by both
/// `try_build` and `try_build_encoded`, naming the codec
#[test]
fn test_output_len_required_without_setting() {
    for &codec in &[Codec::Shake128, Codec::Shake256] {
        let mut builder = Builder::new(codec).unwrap();
        builder.update(b"no output length");
        let Err(Error::OutputLenRequired { codec: error_codec }) = builder.try_build() else {
            panic!("{codec:?} built without an output length");
        };
        assert_eq!(error_codec, codec);

        let mut builder = Builder::new(codec).unwrap();
        builder.update(b"no output length");
        let Err(Error::OutputLenRequired { codec: error_codec }) = builder.try_build_encoded()
        else {
            panic!("{codec:?} encoded without an output length");
        };
        assert_eq!(error_codec, codec);
    }
}

/// a digest of one byte, and a digest of sixty-four bytes, are accepted as
/// explicit hashes under a Shake codec
#[test]
fn test_with_hash_accepts_valid_lengths() {
    for &codec in &[Codec::Shake128, Codec::Shake256] {
        for &hash_len in &[1usize, 64] {
            let hash = vec![7u8; hash_len];
            let mh = Builder::new(codec)
                .unwrap()
                .with_hash(hash.clone())
                .try_build()
                .unwrap();

            assert_eq!(mh.codec(), codec, "{codec:?} with {hash_len}-byte digest");
            assert_eq!(
                mh.as_ref(),
                hash.as_slice(),
                "{codec:?} with {hash_len}-byte digest"
            );
        }
    }
}

/// an empty explicit digest, and a digest one byte over the maximum, are
/// rejected with `OutputLenInvalid` naming the digest length
#[test]
fn test_with_hash_rejects_out_of_policy_lengths() {
    for &codec in &[Codec::Shake128, Codec::Shake256] {
        let empty = Builder::new(codec)
            .unwrap()
            .with_hash(Vec::new())
            .try_build();
        assert!(
            matches!(
                empty,
                Err(Error::OutputLenInvalid {
                    output_len: 0,
                    max,
                    ..
                }) if max == MAX_HASH_LENGTH
            ),
            "{codec:?} accepted an empty digest"
        );
    }

    // the over-limit digest is checked against the output policy without
    // being squeezed
    let over: Vec<u8> = vec![0u8; MAX_HASH_LENGTH + 1];
    let result = Builder::new(Codec::Shake128)
        .unwrap()
        .with_hash(over)
        .try_build();
    assert!(
        matches!(
            result,
            Err(Error::OutputLenInvalid {
                output_len,
                max,
                ..
            }) if output_len == MAX_HASH_LENGTH + 1 && max == MAX_HASH_LENGTH
        ),
        "Shake128 accepted a digest one byte over the maximum"
    );
}

/// a valid explicit digest takes precedence over streamed data and an
/// output length setting
#[test]
fn test_with_hash_precedes_streamed_data_and_output_len() {
    for &codec in &[Codec::Shake128, Codec::Shake256] {
        let hash = vec![0x5au8; 32];

        let mut builder = Builder::new(codec).unwrap();
        builder.update(b"streamed data that must be ignored");
        builder.output_len(64);
        let mh = builder.with_hash(hash.clone()).try_build().unwrap();

        assert_eq!(mh.codec(), codec);
        assert_eq!(mh.as_ref(), hash.as_slice(), "{codec:?}");
    }
}

/// a multihash whose digest is shorter than the codec's output policy
/// still decodes, in binary and through a multibase string: decode stays
/// format-validity only
#[test]
fn test_truncated_sha2_256_multihash_decodes() {
    // sha2-256 (codec 0x12) with a declared digest length of 16 bytes
    let mut bytes = vec![0x12u8, 0x10];
    bytes.extend_from_slice(&[0u8; 16]);

    let mh = Multihash::try_from(bytes.as_ref()).unwrap();
    assert_eq!(mh.codec(), Codec::Sha2256);
    assert_eq!(mh.as_ref().len(), 16);

    // `f` is the multibase prefix for base 16 lower
    let s = format!("f{}", hex::encode(&bytes));
    let decoded = EncodedMultihash::try_from(s.as_str()).unwrap();
    assert_eq!(decoded.encoding(), Base::Base16Lower);
    assert_eq!(decoded.to_inner(), mh);
}
