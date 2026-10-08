// SPDX-License-Identifier: Apache-2.0
//! Multihash implementation with support for multiple cryptographic hash algorithms
//!
//! This module provides the core [`Multihash`] type and [`Builder`] for creating
//! self-describing hash digests.

use crate::Error;
use core::fmt;
use core::hash::Hash;
use digest::{Digest, ExtendableOutput, Update};
use multi_base::Base;
use multi_codec::Codec;
use multi_trait::{EncodeInto, Null, TryDecodeFrom};
use multi_util::{BaseEncoded, CodecInfo, DetectedEncoder, EncodingInfo, Varbytes};
use subtle::ConstantTimeEq;
use typenum::consts::{U28, U32, U48, U64};

/// the maximum multihash digest output length in bytes
///
/// The builder rejects XOF output lengths above this value before any
/// allocation or squeeze. The value is 16 MiB, aligned with the 16 MiB
/// decode cap that `Varbytes` in `multi-util` enforces.
pub const MAX_HASH_LENGTH: usize = 16 * 1024 * 1024;

/// the hash codecs currently supported
///
/// The two extendable-output codecs, `Shake128` and `Shake256`, end the
/// list; a builder for them requires an explicit digest output length
/// through [`Builder::output_len`].
pub const HASH_CODECS: [Codec; 25] = [
    Codec::Blake2B224,
    Codec::Blake2B256,
    Codec::Blake2B384,
    Codec::Blake2B512,
    Codec::Blake2S224,
    Codec::Blake2S256,
    Codec::Blake3,
    Codec::Md5,
    Codec::Ripemd128,
    Codec::Ripemd160,
    Codec::Ripemd256,
    Codec::Ripemd320,
    Codec::Sha1,
    Codec::Sha2224,
    Codec::Sha2256,
    Codec::Sha2384,
    Codec::Sha2512,
    Codec::Sha2512224,
    Codec::Sha2512256,
    Codec::Sha3224,
    Codec::Sha3256,
    Codec::Sha3384,
    Codec::Sha3512,
    Codec::Shake128,
    Codec::Shake256,
];

/// the safe hash codecs current supported
pub const SAFE_HASH_CODECS: [Codec; 10] = [
    Codec::Blake2B256,
    Codec::Blake2B384,
    Codec::Blake2B512,
    Codec::Blake2S256,
    Codec::Blake3,
    Codec::Sha3256,
    Codec::Sha3384,
    Codec::Sha3512,
    Codec::Shake128,
    Codec::Shake256,
];

/// the multicodec sigil for multihash
pub const SIGIL: Codec = Codec::Multihash;

/// a base encoded multihash
pub type EncodedMultihash = BaseEncoded<Multihash, DetectedEncoder>;

/// the digest output policy of a hash codec in [`HASH_CODECS`]
///
/// Fixed-output codecs produce one exact digest length. The XOF codecs,
/// `Shake128` and `Shake256`, produce a length the caller chooses within
/// `1..=MAX_HASH_LENGTH` bytes.
#[derive(Clone, Copy)]
enum OutputPolicy {
    /// exact digest length in bytes
    Fixed(usize),

    /// extendable-output codec; the caller sets the digest length
    Xof,
}

/// the digest output policy for each codec in [`HASH_CODECS`] order
const OUTPUT_POLICIES: [OutputPolicy; 25] = [
    OutputPolicy::Fixed(28), // Blake2B224
    OutputPolicy::Fixed(32), // Blake2B256
    OutputPolicy::Fixed(48), // Blake2B384
    OutputPolicy::Fixed(64), // Blake2B512
    OutputPolicy::Fixed(28), // Blake2S224
    OutputPolicy::Fixed(32), // Blake2S256
    OutputPolicy::Fixed(32), // Blake3
    OutputPolicy::Fixed(16), // Md5
    OutputPolicy::Fixed(16), // Ripemd128
    OutputPolicy::Fixed(20), // Ripemd160
    OutputPolicy::Fixed(32), // Ripemd256
    OutputPolicy::Fixed(40), // Ripemd320
    OutputPolicy::Fixed(20), // Sha1
    OutputPolicy::Fixed(28), // Sha2224
    OutputPolicy::Fixed(32), // Sha2256
    OutputPolicy::Fixed(48), // Sha2384
    OutputPolicy::Fixed(64), // Sha2512
    OutputPolicy::Fixed(28), // Sha2512224
    OutputPolicy::Fixed(32), // Sha2512256
    OutputPolicy::Fixed(28), // Sha3224
    OutputPolicy::Fixed(32), // Sha3256
    OutputPolicy::Fixed(48), // Sha3384
    OutputPolicy::Fixed(64), // Sha3512
    OutputPolicy::Xof,       // Shake128
    OutputPolicy::Xof,       // Shake256
];

// the digest policy table must stay parallel to `HASH_CODECS`
const _: () = assert!(OUTPUT_POLICIES.len() == HASH_CODECS.len());

/// the digest output policy of a supported hash codec
///
/// Returns `None` for codecs outside [`HASH_CODECS`].
fn output_policy(codec: Codec) -> Option<OutputPolicy> {
    let index = HASH_CODECS
        .iter()
        .position(|&candidate| candidate == codec)?;
    OUTPUT_POLICIES.get(index).copied()
}

/// check a digest against the codec's output policy
///
/// Fixed-output codecs require the exact digest length. XOF codecs accept
/// `1..=MAX_HASH_LENGTH` bytes.
fn validate_digest_length(codec: Codec, hash: &[u8]) -> Result<(), Error> {
    match output_policy(codec) {
        Some(OutputPolicy::Fixed(expected)) => {
            let actual = hash.len();
            if actual == expected {
                Ok(())
            } else {
                Err(Error::invalid_digest_length(codec, expected, actual))
            }
        }
        Some(OutputPolicy::Xof) => {
            let actual = hash.len();
            if actual == 0 || actual > MAX_HASH_LENGTH {
                Err(Error::output_len_invalid(codec, actual, MAX_HASH_LENGTH))
            } else {
                Ok(())
            }
        }
        None => Ok(()),
    }
}

/// validate the XOF output length a builder requests at build time
///
/// The length runs through the `1..=MAX_HASH_LENGTH` policy before any
/// allocation or squeeze.
const fn validate_output_len(codec: Codec, output_len: Option<usize>) -> Result<usize, Error> {
    match output_len {
        None => Err(Error::output_len_required(codec)),
        Some(len) if len == 0 || len > MAX_HASH_LENGTH => {
            Err(Error::output_len_invalid(codec, len, MAX_HASH_LENGTH))
        }
        Some(len) => Ok(len),
    }
}

/// the streaming hasher state for one supported codec
///
/// Enum dispatch keeps the hashing state concrete: every arm is `Send`,
/// `Sync`, `Clone`, and `Debug`, and hashing avoids a trait-object
/// allocation per hash.
#[derive(Clone)]
enum Hasher {
    /// blake2b with a 224-bit digest
    Blake2B224(blake2::Blake2b<U28>),
    /// blake2b with a 256-bit digest
    Blake2B256(blake2::Blake2b<U32>),
    /// blake2b with a 384-bit digest
    Blake2B384(blake2::Blake2b<U48>),
    /// blake2b with a 512-bit digest
    Blake2B512(blake2::Blake2b<U64>),
    /// blake2s with a 224-bit digest
    Blake2S224(blake2::Blake2s<U28>),
    /// blake2s with a 256-bit digest
    Blake2S256(blake2::Blake2s<U32>),
    /// blake3 with a 256-bit digest
    ///
    /// `blake3::Hasher` is roughly 2 KB, so its arm is boxed to keep the
    /// other arms, and every [`Builder`] value, small
    Blake3(Box<blake3::Hasher>),
    /// md5 with a 128-bit digest
    Md5(md5::Md5),
    /// ripemd128 with a 128-bit digest
    Ripemd128(ripemd::Ripemd128),
    /// ripemd160 with a 160-bit digest
    Ripemd160(ripemd::Ripemd160),
    /// ripemd256 with a 256-bit digest
    Ripemd256(ripemd::Ripemd256),
    /// ripemd320 with a 320-bit digest
    Ripemd320(ripemd::Ripemd320),
    /// sha1 with a 160-bit digest
    Sha1(sha1::Sha1),
    /// sha2-224 with a 224-bit digest
    Sha2224(sha2::Sha224),
    /// sha2-256 with a 256-bit digest
    Sha2256(sha2::Sha256),
    /// sha2-384 with a 384-bit digest
    Sha2384(sha2::Sha384),
    /// sha2-512 with a 512-bit digest
    Sha2512(sha2::Sha512),
    /// sha2-512/224 with a 224-bit digest
    Sha2512224(sha2::Sha512_224),
    /// sha2-512/256 with a 256-bit digest
    Sha2512256(sha2::Sha512_256),
    /// sha3-224 with a 224-bit digest
    Sha3224(sha3::Sha3_224),
    /// sha3-256 with a 256-bit digest
    Sha3256(sha3::Sha3_256),
    /// sha3-384 with a 384-bit digest
    Sha3384(sha3::Sha3_384),
    /// sha3-512 with a 512-bit digest
    Sha3512(sha3::Sha3_512),
    /// shake128 extendable-output function
    Shake128(shake::Shake128),
    /// shake256 extendable-output function
    Shake256(shake::Shake256),
}

impl Hasher {
    /// create the streaming hasher for a codec
    ///
    /// Returns `None` only for codecs outside [`HASH_CODECS`], which
    /// [`Builder::new`] rejects up front.
    fn new(codec: Codec) -> Option<Self> {
        Some(match codec {
            Codec::Blake2B224 => Self::Blake2B224(blake2::Blake2b::<U28>::new()),
            Codec::Blake2B256 => Self::Blake2B256(blake2::Blake2b::<U32>::new()),
            Codec::Blake2B384 => Self::Blake2B384(blake2::Blake2b::<U48>::new()),
            Codec::Blake2B512 => Self::Blake2B512(blake2::Blake2b::<U64>::new()),
            Codec::Blake2S224 => Self::Blake2S224(blake2::Blake2s::<U28>::new()),
            Codec::Blake2S256 => Self::Blake2S256(blake2::Blake2s::<U32>::new()),
            Codec::Blake3 => Self::Blake3(Box::new(blake3::Hasher::new())),
            Codec::Md5 => Self::Md5(md5::Md5::new()),
            Codec::Ripemd128 => Self::Ripemd128(ripemd::Ripemd128::new()),
            Codec::Ripemd160 => Self::Ripemd160(ripemd::Ripemd160::new()),
            Codec::Ripemd256 => Self::Ripemd256(ripemd::Ripemd256::new()),
            Codec::Ripemd320 => Self::Ripemd320(ripemd::Ripemd320::new()),
            Codec::Sha1 => Self::Sha1(sha1::Sha1::new()),
            Codec::Sha2224 => Self::Sha2224(sha2::Sha224::new()),
            Codec::Sha2256 => Self::Sha2256(sha2::Sha256::new()),
            Codec::Sha2384 => Self::Sha2384(sha2::Sha384::new()),
            Codec::Sha2512 => Self::Sha2512(sha2::Sha512::new()),
            Codec::Sha2512224 => Self::Sha2512224(sha2::Sha512_224::new()),
            Codec::Sha2512256 => Self::Sha2512256(sha2::Sha512_256::new()),
            Codec::Sha3224 => Self::Sha3224(sha3::Sha3_224::new()),
            Codec::Sha3256 => Self::Sha3256(sha3::Sha3_256::new()),
            Codec::Sha3384 => Self::Sha3384(sha3::Sha3_384::new()),
            Codec::Sha3512 => Self::Sha3512(sha3::Sha3_512::new()),
            Codec::Shake128 => Self::Shake128(shake::Shake128::default()),
            Codec::Shake256 => Self::Shake256(shake::Shake256::default()),
            _ => return None,
        })
    }

    /// feed data to the streaming hasher
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Blake2B224(h) => Digest::update(h, data),
            Self::Blake2B256(h) => Digest::update(h, data),
            Self::Blake2B384(h) => Digest::update(h, data),
            Self::Blake2B512(h) => Digest::update(h, data),
            Self::Blake2S224(h) => Digest::update(h, data),
            Self::Blake2S256(h) => Digest::update(h, data),
            // `update` and `finalize` go through the fully qualified inherent
            // path: blake3 also supplies trait methods of the same names
            Self::Blake3(h) => {
                blake3::Hasher::update(h, data);
            }
            Self::Md5(h) => Digest::update(h, data),
            Self::Ripemd128(h) => Digest::update(h, data),
            Self::Ripemd160(h) => Digest::update(h, data),
            Self::Ripemd256(h) => Digest::update(h, data),
            Self::Ripemd320(h) => Digest::update(h, data),
            Self::Sha1(h) => Digest::update(h, data),
            Self::Sha2224(h) => Digest::update(h, data),
            Self::Sha2256(h) => Digest::update(h, data),
            Self::Sha2384(h) => Digest::update(h, data),
            Self::Sha2512(h) => Digest::update(h, data),
            Self::Sha2512224(h) => Digest::update(h, data),
            Self::Sha2512256(h) => Digest::update(h, data),
            Self::Sha3224(h) => Digest::update(h, data),
            Self::Sha3256(h) => Digest::update(h, data),
            Self::Sha3384(h) => Digest::update(h, data),
            Self::Sha3512(h) => Digest::update(h, data),
            // the XOF arms take `Update::update`; they do not implement
            // the fixed-output `Digest` trait
            Self::Shake128(h) => Update::update(h, data),
            Self::Shake256(h) => Update::update(h, data),
        }
    }

    /// finish the streamed hash and return the digest bytes
    ///
    /// Fixed-output arms ignore `output_len` and produce their policy
    /// length. The XOF arms require an output length of `1..=MAX_HASH_LENGTH`
    /// bytes, checked before any allocation or squeeze.
    fn finalize(self, codec: Codec, output_len: Option<usize>) -> Result<Vec<u8>, Error> {
        match self {
            Self::Blake2B224(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Blake2B256(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Blake2B384(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Blake2B512(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Blake2S224(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Blake2S256(h) => Ok(Digest::finalize(h).to_vec()),
            // see `update`: fully qualified inherent path for blake3
            Self::Blake3(h) => {
                let hash = blake3::Hasher::finalize(&h);
                Ok(hash.as_bytes().to_vec())
            }
            Self::Md5(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Ripemd128(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Ripemd160(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Ripemd256(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Ripemd320(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Sha1(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Sha2224(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Sha2256(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Sha2384(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Sha2512(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Sha2512224(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Sha2512256(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Sha3224(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Sha3256(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Sha3384(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Sha3512(h) => Ok(Digest::finalize(h).to_vec()),
            Self::Shake128(h) => {
                let out_len = validate_output_len(codec, output_len)?;
                Ok(xof_finalize(h, out_len))
            }
            Self::Shake256(h) => {
                let out_len = validate_output_len(codec, output_len)?;
                Ok(xof_finalize(h, out_len))
            }
        }
    }
}

/// squeeze `out_len` XOF bytes into one pre-sized buffer
///
/// `ExtendableOutput::finalize_xof_into` reads the first `out_len` bytes of
/// the XOF stream, so the read always starts at offset zero.
fn xof_finalize<T: ExtendableOutput>(hasher: T, out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    ExtendableOutput::finalize_xof_into(hasher, &mut out);
    out
}

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            Self::Blake2B224(_) => "Blake2B224(..)",
            Self::Blake2B256(_) => "Blake2B256(..)",
            Self::Blake2B384(_) => "Blake2B384(..)",
            Self::Blake2B512(_) => "Blake2B512(..)",
            Self::Blake2S224(_) => "Blake2S224(..)",
            Self::Blake2S256(_) => "Blake2S256(..)",
            Self::Blake3(_) => "Blake3(..)",
            Self::Md5(_) => "Md5(..)",
            Self::Ripemd128(_) => "Ripemd128(..)",
            Self::Ripemd160(_) => "Ripemd160(..)",
            Self::Ripemd256(_) => "Ripemd256(..)",
            Self::Ripemd320(_) => "Ripemd320(..)",
            Self::Sha1(_) => "Sha1(..)",
            Self::Sha2224(_) => "Sha2224(..)",
            Self::Sha2256(_) => "Sha2256(..)",
            Self::Sha2384(_) => "Sha2384(..)",
            Self::Sha2512(_) => "Sha2512(..)",
            Self::Sha2512224(_) => "Sha2512224(..)",
            Self::Sha2512256(_) => "Sha2512256(..)",
            Self::Sha3224(_) => "Sha3224(..)",
            Self::Sha3256(_) => "Sha3256(..)",
            Self::Sha3384(_) => "Sha3384(..)",
            Self::Sha3512(_) => "Sha3512(..)",
            Self::Shake128(_) => "Shake128(..)",
            Self::Shake256(_) => "Shake256(..)",
        };
        f.write_str(name)
    }
}

/// inner implementation of the multihash
///
/// # Constant-Time Comparison
///
/// `Multihash` derives [`PartialEq`], which uses a short-circuiting byte
/// comparison and is **not** suitable for timing-sensitive contexts (e.g.
/// comparing MACs or hashes received from an untrusted party). Use
/// [`ct_eq`](ConstantTimeEq::ct_eq) in those contexts — it compares the
/// `codec`, the hash length, and the hash bytes in constant time.
#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct Multihash {
    /// hash codec
    pub(crate) codec: Codec,

    /// hash value
    pub(crate) hash: Vec<u8>,
}

impl CodecInfo for Multihash {
    /// Return that we are a Multihash object
    fn preferred_codec() -> Codec {
        SIGIL
    }

    /// Return the hashing codec for the multihash
    fn codec(&self) -> Codec {
        self.codec
    }
}

impl EncodingInfo for Multihash {
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl From<Multihash> for Vec<u8> {
    fn from(mh: Multihash) -> Self {
        // Pre-calculate total size: codec varint + length varint + hash bytes
        let codec_bytes: Self = mh.codec.into();
        let len_bytes = mh.hash.len().encode_into();
        let total = codec_bytes.len() + len_bytes.len() + mh.hash.len();

        let mut v = Self::with_capacity(total);
        v.extend_from_slice(&codec_bytes);
        v.extend_from_slice(&len_bytes);
        v.extend_from_slice(&mh.hash);
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Multihash {
    type Error = Error;

    fn try_from(s: &'a [u8]) -> Result<Self, Self::Error> {
        let (mh, _) = Self::try_decode_from(s)?;
        Ok(mh)
    }
}

impl<'a> TryDecodeFrom<'a> for Multihash {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the hashing codec
        let (codec, ptr) = Codec::try_decode_from(bytes)?;
        // decode the hash bytes
        let (hash, ptr) = Varbytes::try_decode_from(ptr)?;
        // pull the inner Vec<u8> out of Varbytes
        let hash = hash.to_inner();
        Ok((Self { codec, hash }, ptr))
    }
}

/// Exposes direct access to the hash data
impl AsRef<[u8]> for Multihash {
    fn as_ref(&self) -> &[u8] {
        self.hash.as_ref()
    }
}

/// Constant-time equality comparison for [`Multihash`].
///
/// Compares `codec`, `hash.len()`, and the hash bytes without
/// short-circuiting. Returns `1u8` if both multihashes are equal, `0u8`
/// otherwise. Use this instead of `PartialEq` in timing-sensitive contexts
/// (e.g. verifying a hash received from an untrusted party).
impl ConstantTimeEq for Multihash {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // Compare codec (Codec is a Copy enum backed by u64)
        let codec_eq = u64::from(self.codec).ct_eq(&u64::from(other.codec));

        // Compare hash lengths in constant time
        let len_eq = self.hash.len().ct_eq(&other.hash.len());

        // Compare hash bytes; ConstantTimeEq on [u8] handles unequal lengths
        // by returning 0 (it first compares lengths, then bytes).
        let bytes_eq = self.hash.as_slice().ct_eq(other.hash.as_slice());

        codec_eq & len_eq & bytes_eq
    }
}

/// Multihashes can have a null value
impl Null for Multihash {
    fn null() -> Self {
        Self::default()
    }

    fn is_null(&self) -> bool {
        *self == Self::default()
    }
}

impl fmt::Debug for Multihash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} - {:?} - {}",
            SIGIL,
            self.codec(),
            hex::encode(&self.hash)
        )
    }
}

/// Hash builder that takes the codec and produces a Multihash
///
/// The builder owns streaming hash state. Feed data with
/// [`update`](Self::update) to hash it, or set a digest computed elsewhere
/// with [`with_hash`](Self::with_hash). [`try_build`](Self::try_build)
/// finalizes the streaming state, or validates the explicit digest, and
/// produces the [`Multihash`].
///
/// `try_build` validates the digest against the codec's output policy and
/// returns `Error::InvalidDigestLength` on a mismatch. Fixed-output codecs
/// require their exact policy length. The XOF codecs `Shake128` and
/// `Shake256` require an output length set through
/// [`output_len`](Self::output_len) and accept `1..=MAX_HASH_LENGTH` bytes.
/// A digest set with `with_hash` takes precedence over streamed data.
///
/// # Examples
///
/// ```
/// use multi_hash::Builder;
/// use multi_codec::Codec;
///
/// let mut builder = Builder::new(Codec::Sha2256).unwrap();
/// builder.update(b"hello ");
/// builder.update(b"world");
/// let multihash = builder.try_build().unwrap();
///
/// assert_eq!(multihash.as_ref().len(), 32);
/// ```
#[derive(Clone, Debug)]
pub struct Builder {
    /// hash codec
    codec: Codec,

    /// streaming hash state, created lazily by [`update`](Self::update)
    hasher: Option<Hasher>,

    /// explicit hash value set by [`with_hash`](Self::with_hash)
    hash: Option<Vec<u8>>,

    /// XOF digest output length set by [`output_len`](Self::output_len)
    output_len: Option<usize>,

    /// base encoding requested through [`with_base_encoding`](Self::with_base_encoding)
    base_encoding: Option<Base>,
}

impl Builder {
    /// create a builder for the given codec
    ///
    /// # Errors
    ///
    /// Returns `Error::UnsupportedHash` if `codec` is not a recognized hash
    /// algorithm in [`HASH_CODECS`].
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::{Builder, Error};
    /// use multi_codec::Codec;
    ///
    /// let result = Builder::new(Codec::Identity);
    /// assert!(matches!(result, Err(Error::UnsupportedHash { .. })));
    /// ```
    pub fn new(codec: Codec) -> Result<Self, Error> {
        if !HASH_CODECS.contains(&codec) {
            return Err(Error::unsupported_hash(codec));
        }
        Ok(Self {
            codec,
            hasher: None,
            hash: None,
            output_len: None,
            base_encoding: None,
        })
    }

    /// feed data to the streaming hasher
    ///
    /// The internal hasher is created lazily on the first call. Call `update`
    /// repeatedly to hash data in chunks; the streamed digest is finalized by
    /// [`try_build`](Self::try_build).
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        // `Builder::new` accepts only codecs in `HASH_CODECS`, for which
        // `Hasher::new` always produces a hasher
        if self.hasher.is_none() {
            self.hasher = Hasher::new(self.codec);
        }
        debug_assert!(
            self.hasher.is_some(),
            "Hasher::new must cover every codec in HASH_CODECS"
        );
        if let Some(hasher) = &mut self.hasher {
            hasher.update(data.as_ref());
        }
    }

    /// set the XOF digest output length in bytes
    ///
    /// The extendable-output codecs `Shake128` and `Shake256` require an
    /// explicit output length; [`try_build`](Self::try_build) and
    /// [`try_build_encoded`](Self::try_build_encoded) return
    /// `Error::OutputLenRequired` without one, and lengths outside
    /// `1..=MAX_HASH_LENGTH` return `Error::OutputLenInvalid` before any
    /// allocation or squeeze. Fixed-output codecs ignore this setting and
    /// always produce their exact policy length.
    ///
    /// # XOF notes
    ///
    /// - A 32-byte `Shake256` digest is `shake-256` at length 32, not
    ///   `sha3-256`: the two codecs name different algorithms with
    ///   different sponge rates.
    /// - A completed multihash digest cannot extend. Producing a different
    ///   length for the same message requires a rehash through a fresh
    ///   builder.
    /// - XOF prefix consistency: the same input produces digest bytes in
    ///   which a short output prefixes the long output. Two digest lengths
    ///   still encode as distinct multihashes, because the encoded length
    ///   prefix differs.
    /// - Recommended minimum outputs are 32 bytes for `Shake128` and 64
    ///   bytes for `Shake256`. The sponge capacity fixes the security
    ///   strength of the XOF, while collision resistance stays bounded by
    ///   the chosen output length.
    pub const fn output_len(&mut self, output_len: usize) {
        self.output_len = Some(output_len);
    }

    /// set the hash data
    ///
    /// The digest must match the output policy of the codec: the exact
    /// output size for fixed-output codecs, or `1..=MAX_HASH_LENGTH` bytes
    /// for the XOF codecs. [`try_build`](Self::try_build) validates it. A
    /// digest set with `with_hash` takes precedence over data streamed with
    /// `update`, and over an `output_len` setting.
    #[must_use]
    pub fn with_hash(mut self, hash: impl Into<Vec<u8>>) -> Self {
        self.hash = Some(hash.into());
        self
    }

    /// set the base encoding codec
    ///
    /// The encoding applies to [`try_build_encoded`](Self::try_build_encoded).
    #[must_use]
    pub const fn with_base_encoding(mut self, base: Base) -> Self {
        self.base_encoding = Some(base);
        self
    }

    /// build a base encoded multihash
    ///
    /// # Errors
    ///
    /// Returns the errors of [`try_build`](Self::try_build).
    pub fn try_build_encoded(self) -> Result<EncodedMultihash, Error> {
        let Self {
            codec,
            hasher,
            hash,
            output_len,
            base_encoding,
        } = self;
        let mh = build_multihash(codec, hasher, hash, output_len)?;
        Ok(BaseEncoded::new(
            base_encoding.unwrap_or_else(Multihash::preferred_encoding),
            mh,
        ))
    }

    /// build the multihash
    ///
    /// A digest set with [`with_hash`](Self::with_hash) takes precedence over
    /// data streamed with [`update`](Self::update). The digest runs through
    /// the codec's output policy: fixed-output codecs require their exact
    /// policy length, and the XOF codecs accept `1..=MAX_HASH_LENGTH` bytes.
    ///
    /// # Errors
    ///
    /// Returns `Error::MissingHash` if no hash was set and no data was
    /// streamed. Returns `Error::InvalidDigestLength` if a fixed-output
    /// digest length does not match the codec's policy. For the XOF codecs,
    /// returns `Error::OutputLenRequired` when no output length was set for
    /// streamed data, and `Error::OutputLenInvalid` for an output length
    /// outside `1..=MAX_HASH_LENGTH`.
    pub fn try_build(self) -> Result<Multihash, Error> {
        let Self {
            codec,
            hasher,
            hash,
            output_len,
            ..
        } = self;
        build_multihash(codec, hasher, hash, output_len)
    }
}

/// finish hash state into a validated multihash
///
/// An explicit digest takes precedence over the streaming hasher. A missing
/// digest fails with `Error::MissingHash`. The digest then runs through the
/// codec's output policy.
fn build_multihash(
    codec: Codec,
    hasher: Option<Hasher>,
    hash: Option<Vec<u8>>,
    output_len: Option<usize>,
) -> Result<Multihash, Error> {
    let hash = match hash {
        Some(hash) => hash,
        None => match hasher {
            Some(hasher) => hasher.finalize(codec, output_len)?,
            None => return Err(Error::MissingHash),
        },
    };
    validate_digest_length(codec, &hash)?;
    Ok(Multihash { codec, hash })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// the output length these tests request for an XOF codec
    ///
    /// Fixed-output codecs ignore an output length, so the helper applies
    /// only to the Shake arms.
    fn xof_output_len(codec: Codec) -> Option<usize> {
        match codec {
            Codec::Shake128 => Some(32),
            Codec::Shake256 => Some(64),
            _ => None,
        }
    }

    /// build a multihash of `data` with `codec`, streaming the data
    fn streamed_multihash(codec: Codec, data: &[u8]) -> Multihash {
        let mut builder = Builder::new(codec).unwrap();
        builder.update(data);
        if let Some(output_len) = xof_output_len(codec) {
            builder.output_len(output_len);
        }
        builder.try_build().unwrap()
    }

    /// build a base encoded multihash of `data` with `codec`
    fn streamed_encoded(codec: Codec, base: Base, data: &[u8]) -> EncodedMultihash {
        let mut builder = Builder::new(codec).unwrap();
        builder.update(data);
        if let Some(output_len) = xof_output_len(codec) {
            builder.output_len(output_len);
        }
        builder
            .with_base_encoding(base)
            .try_build_encoded()
            .unwrap()
    }

    #[test]
    fn test_matrix() {
        let hashers = vec![
            Codec::Blake2B224,
            Codec::Blake2B256,
            Codec::Blake2B384,
            Codec::Blake2B512,
            Codec::Blake2S224,
            Codec::Blake2S256,
            Codec::Blake3,
            Codec::Md5,
            Codec::Ripemd128,
            Codec::Ripemd160,
            Codec::Ripemd256,
            Codec::Ripemd320,
            Codec::Sha1,
            Codec::Sha2224,
            Codec::Sha2256,
            Codec::Sha2384,
            Codec::Sha2512,
            Codec::Sha2512224,
            Codec::Sha2512256,
            Codec::Sha3224,
            Codec::Sha3256,
            Codec::Sha3384,
            Codec::Sha3512,
            Codec::Shake128,
            Codec::Shake256,
        ];

        let bases = vec![
            Base::Base2,
            Base::Base8,
            Base::Base10,
            Base::Base16Lower,
            Base::Base16Upper,
            Base::Base32Lower,
            Base::Base32Upper,
            Base::Base32PadLower,
            Base::Base32PadUpper,
            Base::Base32HexLower,
            Base::Base32HexUpper,
            Base::Base32HexPadLower,
            Base::Base32HexPadUpper,
            Base::Base32Z,
            Base::Base36Lower,
            Base::Base36Upper,
            Base::Base58Flickr,
            Base::Base58Btc,
            Base::Base64,
            Base::Base64Pad,
            Base::Base64Url,
            Base::Base64UrlPad,
        ];

        for h in &hashers {
            for b in &bases {
                let mh1 = streamed_encoded(*h, *b, b"for great justice, move every zig!");
                let s = mh1.to_string();
                assert_eq!(mh1, EncodedMultihash::try_from(s.as_str()).unwrap());
            }
        }
    }

    #[test]
    fn test_binary_roundtrip() {
        let mh1 = streamed_multihash(Codec::Sha3384, b"for great justice, move every zig!");
        let v: Vec<u8> = mh1.clone().into();
        let mh2 = Multihash::try_from(v.as_ref()).unwrap();
        assert_eq!(mh1, mh2);
    }

    #[test]
    fn test_encoded() {
        let mh = streamed_encoded(
            Codec::Sha3256,
            Base::Base58Btc,
            b"for great justice, move every zig!",
        );
        let s = mh.to_string();
        println!("{mh:?}");
        println!("{s}");
        assert_eq!(mh, EncodedMultihash::try_from(s.as_str()).unwrap());
    }

    #[test]
    fn test_matching() {
        let mh1 = streamed_multihash(Codec::Sha3256, b"for great justice, move every zig!");
        let mh2 = Multihash::try_from(
            hex::decode("16206b761d3b2e7675e088e337a82207b55711d3957efdb877a3d261b0ca2c38e201")
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        assert_eq!(mh1, mh2);
    }

    #[test]
    fn test_null() {
        let mh1 = Multihash::null();
        assert!(mh1.is_null());
        let mh2 = Multihash::default();
        assert_eq!(mh1, mh2);
        assert!(mh2.is_null());
    }

    #[test]
    fn test_multihash_sha1() {
        // test cases from: https://github.com/multiformats/multihash?tab=readme-ov-file#example
        let bases = vec![
            (
                Base::Base16Lower,
                "f111488c2f11fb2ce392acb5b2986e640211c4690073e",
            ),
            (Base::Base32Upper, "BCEKIRQXRD6ZM4OJKZNNSTBXGIAQRYRUQA47A"),
            (Base::Base58Btc, "z5dsgvJGnvAfiR3K6HCBc4hcokSfmjj"),
            (Base::Base64, "mERSIwvEfss45KstbKYbmQCEcRpAHPg"),
        ];

        for (b, h) in bases {
            let mh = streamed_encoded(Codec::Sha1, b, b"multihash");
            let s = mh.to_string();
            assert_eq!(h, s.as_str());
        }
    }

    #[test]
    fn test_multihash_sha2_256() {
        // test cases from: https://github.com/multiformats/multihash?tab=readme-ov-file#example
        let bases = vec![
            (
                Base::Base16Lower,
                "f12209cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe47",
            ),
            (
                Base::Base32Upper,
                "BCIQJZPAHYP4ZC4SYG2R2UKSYDSRAFEMYVJBAXHMZXQHBGHM7HYWL4RY",
            ),
            (
                Base::Base58Btc,
                "zQmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk",
            ),
            (
                Base::Base64,
                "mEiCcvAfD+ZFyWDajqipYHKICkZiqQgudmbwOEx2fPiy+Rw",
            ),
        ];

        for (b, h) in bases {
            let mh = streamed_encoded(Codec::Sha2256, b, b"multihash");
            let s = mh.to_string();
            assert_eq!(h, s.as_str());
        }
    }

    #[test]
    fn test_multihash_in_indexmap() {
        let mut map = std::collections::HashMap::new();

        let mh1 = streamed_multihash(Codec::Sha2256, b"for great justice, move every zig!");

        let mh2 = streamed_multihash(Codec::Sha2256, b"for great justice, move every zag!");

        map.insert(mh1, "zig");
        map.insert(mh2, "zag");

        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_ct_eq_equal() {
        let mh1 = streamed_multihash(Codec::Sha2256, b"hello");
        let mh2 = streamed_multihash(Codec::Sha2256, b"hello");

        assert_eq!(mh1.ct_eq(&mh2).unwrap_u8(), 1);
    }

    #[test]
    fn test_ct_eq_unequal_hash() {
        let mh1 = streamed_multihash(Codec::Sha2256, b"hello");
        let mh2 = streamed_multihash(Codec::Sha2256, b"world");

        assert_eq!(mh1.ct_eq(&mh2).unwrap_u8(), 0);
    }

    #[test]
    fn test_ct_eq_unequal_codec() {
        let mh1 = streamed_multihash(Codec::Sha2256, b"hello");
        let mh2 = streamed_multihash(Codec::Sha2256, b"hello");
        // same hash bytes, different codec
        let mh3 = Multihash {
            codec: Codec::Sha2512,
            hash: mh1.hash.clone(),
        };

        assert_eq!(mh1.ct_eq(&mh2).unwrap_u8(), 1);
        assert_eq!(mh1.ct_eq(&mh3).unwrap_u8(), 0);
    }

    #[test]
    fn test_ct_eq_unequal_length() {
        let mh1 = streamed_multihash(Codec::Sha2256, b"hello");
        // same codec, different length hash
        let mh2 = Multihash {
            codec: mh1.codec,
            hash: vec![0u8; 16],
        };

        assert_eq!(mh1.ct_eq(&mh2).unwrap_u8(), 0);
    }

    /// builder rejects codecs outside `HASH_CODECS`
    #[test]
    fn test_builder_new_unsupported_codec() {
        for &codec in &[Codec::Identity, Codec::DagCbor, Codec::Multihash] {
            let result = Builder::new(codec);
            assert!(
                matches!(result, Err(Error::UnsupportedHash { .. })),
                "codec {codec:?} was accepted"
            );
        }
    }

    /// a builder without streamed data and without an explicit digest fails
    /// at build time
    #[test]
    fn test_builder_missing_hash_state() {
        let result = Builder::new(Codec::Sha2256).unwrap().try_build();
        assert!(matches!(result, Err(Error::MissingHash)));
    }

    /// streaming feeds data through the lazy hasher
    #[test]
    fn test_builder_update_streaming() {
        let mut builder = Builder::new(Codec::Sha2256).unwrap();
        builder.update(b"multi");
        builder.update(b"hash");
        let mh = builder.try_build().unwrap();
        // sha2-256 of "multihash": digest bytes from the multiformats
        // example vector in `test_multihash_sha2_256` (after the multibase
        // prefix `f`, codec `12`, and length `20`)
        assert_eq!(
            hex::encode(mh.as_ref()),
            "9cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe47"
        );
    }

    /// streaming in chunks equals hashing the whole input at once
    #[test]
    fn test_builder_update_chunks_match_whole() {
        let data = b"for great justice, move every zig!";

        let mut chunked = Builder::new(Codec::Sha2256).unwrap();
        chunked.update(&data[..7]);
        chunked.update(&data[7..20]);
        chunked.update(&data[20..]);
        let chunked = chunked.try_build().unwrap();

        let whole = streamed_multihash(Codec::Sha2256, data);

        assert_eq!(chunked, whole);
    }

    /// an exact-length digest is accepted and used as-is
    #[test]
    fn test_builder_with_hash_exact_length() {
        let hash = vec![7u8; 32];
        let mh = Builder::new(Codec::Sha2256)
            .unwrap()
            .with_hash(hash.clone())
            .try_build()
            .unwrap();
        assert_eq!(mh.codec(), Codec::Sha2256);
        assert_eq!(mh.as_ref(), hash.as_slice());
    }

    /// a wrong-length digest is rejected for a fixed-output codec, and an
    /// out-of-policy digest is rejected for an XOF codec
    #[test]
    fn test_builder_with_hash_wrong_length() {
        for &codec in &HASH_CODECS {
            match output_policy(codec) {
                Some(OutputPolicy::Fixed(expected)) => {
                    let result = Builder::new(codec)
                        .unwrap()
                        .with_hash(vec![0u8; expected + 1])
                        .try_build();
                    assert!(
                        matches!(
                            result,
                            Err(Error::InvalidDigestLength {
                                expected: e,
                                actual: a,
                                ..
                            }) if e == expected && a == expected + 1
                        ),
                        "codec {codec:?} accepted a wrong-length digest"
                    );
                }
                Some(OutputPolicy::Xof) => {
                    let result = Builder::new(codec)
                        .unwrap()
                        .with_hash(Vec::new())
                        .try_build();
                    assert!(
                        matches!(result, Err(Error::OutputLenInvalid { output_len: 0, .. })),
                        "codec {codec:?} accepted an empty XOF digest"
                    );
                }
                None => panic!("codec {codec:?} is in HASH_CODECS but has no policy"),
            }
        }
    }

    /// a digest set with `with_hash` takes precedence over streamed data
    #[test]
    fn test_with_hash_precedence() {
        let mut builder = Builder::new(Codec::Sha2256).unwrap();
        builder.update(b"streamed data");
        let explicit = vec![9u8; 32];
        let mh = builder.with_hash(explicit.clone()).try_build().unwrap();
        assert_eq!(mh.as_ref(), explicit.as_slice());
    }

    /// a wrong-length explicit digest fails even with valid streamed data
    #[test]
    fn test_with_hash_precedence_validates_length() {
        let mut builder = Builder::new(Codec::Sha2256).unwrap();
        builder.update(b"streamed data");
        let result = builder.with_hash(vec![0u8; 31]).try_build();
        assert!(matches!(result, Err(Error::InvalidDigestLength { .. })));
    }

    /// every codec streams to its output policy length, and an explicit
    /// digest of that length is accepted
    #[test]
    fn test_builder_stream_policy_lengths() {
        for &codec in &HASH_CODECS {
            match output_policy(codec) {
                Some(OutputPolicy::Xof) => {
                    let output_len = xof_output_len(codec).unwrap();
                    let mut builder = Builder::new(codec).unwrap();
                    builder.update(b"digest policy lengths");
                    builder.output_len(output_len);
                    let mh = builder.try_build().unwrap();
                    assert_eq!(mh.as_ref().len(), output_len, "codec {codec:?}");

                    let mh = Builder::new(codec)
                        .unwrap()
                        .with_hash(vec![0u8; output_len])
                        .try_build()
                        .unwrap();
                    assert_eq!(mh.as_ref().len(), output_len, "codec {codec:?}");
                }
                Some(OutputPolicy::Fixed(expected)) => {
                    let mut builder = Builder::new(codec).unwrap();
                    builder.update(b"digest policy lengths");
                    let mh = builder.try_build().unwrap();
                    assert_eq!(mh.as_ref().len(), expected, "codec {codec:?}");

                    let mh = Builder::new(codec)
                        .unwrap()
                        .with_hash(vec![0u8; expected])
                        .try_build()
                        .unwrap();
                    assert_eq!(mh.as_ref().len(), expected, "codec {codec:?}");
                }
                None => panic!("codec {codec:?} is in HASH_CODECS but has no policy"),
            }
        }
    }

    /// `try_build` consumes the builder; a clone keeps building independently
    #[test]
    fn test_try_build_consumes_builder() {
        for &codec in &[Codec::Sha2256, Codec::Blake3, Codec::Sha3384] {
            let mut original = Builder::new(codec).unwrap();
            original.update(b"consumed");
            let snapshot = original.clone();
            let mh1 = original.try_build().unwrap();
            let mh2 = snapshot.try_build().unwrap();
            assert_eq!(mh1, mh2, "codec {codec:?}");
        }
    }

    /// `try_build_encoded` consumes the builder too
    #[test]
    fn test_try_build_encoded_consumes_builder() {
        let mut builder = Builder::new(Codec::Sha3256).unwrap();
        builder.update(b"encoded consume");
        let mh = builder
            .with_base_encoding(Base::Base58Btc)
            .try_build_encoded()
            .unwrap();
        let s = mh.to_string();
        assert_eq!(mh, EncodedMultihash::try_from(s.as_str()).unwrap());
    }

    /// a builder with live hashing state stays `Send`, `Sync`, `Clone`, and
    /// `Debug`, and its cloned state builds the same digest
    #[test]
    fn test_builder_send_sync_streaming() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        fn assert_clone<T: Clone>() {}
        fn assert_debug<T: fmt::Debug>() {}

        assert_send::<Builder>();
        assert_sync::<Builder>();
        assert_clone::<Builder>();
        assert_debug::<Builder>();

        let mut builder = Builder::new(Codec::Sha3256).unwrap();
        builder.update(b"sent across threads");
        let handle = std::thread::spawn(move || {
            builder.update(b" and more");
            builder.try_build().unwrap()
        });
        let mh = handle.join().unwrap();
        assert_eq!(mh.codec(), Codec::Sha3256);
        assert_eq!(mh.as_ref().len(), 32);
    }

    /// builder debug output names the codec and the active hasher without
    /// exposing hash state
    #[test]
    fn test_builder_debug() {
        let mut builder = Builder::new(Codec::Sha2256).unwrap();
        let codec_debug = format!("{:?}", Codec::Sha2256);
        let debug_idle = format!("{builder:?}");
        assert!(debug_idle.contains(&codec_debug), "idle: {debug_idle}");
        assert!(debug_idle.contains("None"), "idle: {debug_idle}");

        builder.update(b"debug");
        let debug_live = format!("{builder:?}");
        assert!(debug_live.contains(&codec_debug), "live: {debug_live}");
        assert!(
            debug_live.contains("Some(Sha2256(..))"),
            "live: {debug_live}"
        );
    }

    /// decode stays format-validity only: a digest of the wrong length still
    /// decodes outside the builder
    #[test]
    fn test_decode_ignores_digest_policy() {
        let mut bytes = vec![0x12u8, 0x10];
        bytes.extend_from_slice(&[0u8; 16]);
        let mh = Multihash::try_from(bytes.as_ref()).unwrap();
        assert_eq!(mh.codec(), Codec::Sha2256);
        assert_eq!(mh.as_ref().len(), 16);
    }

    /// the codec constants list 25 supported and 10 safe codecs, and the
    /// XOF output cap is the 16 MiB value that matches the `Varbytes`
    /// decode cap in `multi-util`
    #[test]
    fn test_codec_constant_lengths() {
        assert_eq!(HASH_CODECS.len(), 25);
        assert_eq!(SAFE_HASH_CODECS.len(), 10);
        assert_eq!(MAX_HASH_LENGTH, 16 * 1024 * 1024);
        assert_eq!(HASH_CODECS[23], Codec::Shake128);
        assert_eq!(HASH_CODECS[24], Codec::Shake256);
        assert_eq!(SAFE_HASH_CODECS[8], Codec::Shake128);
        assert_eq!(SAFE_HASH_CODECS[9], Codec::Shake256);
    }

    /// a streamed XOF build without an output length fails with
    /// `OutputLenRequired`
    #[test]
    fn test_xof_output_len_required() {
        for &codec in &[Codec::Shake128, Codec::Shake256] {
            let mut builder = Builder::new(codec).unwrap();
            builder.update(b"missing output length");
            let result = builder.try_build();
            assert!(
                matches!(result, Err(Error::OutputLenRequired { .. })),
                "codec {codec:?} built without an output length"
            );

            let mut builder = Builder::new(codec).unwrap();
            builder.update(b"encoded without an output length");
            let result = builder.try_build_encoded();
            assert!(
                matches!(result, Err(Error::OutputLenRequired { .. })),
                "codec {codec:?} encoded without an output length"
            );
        }
    }

    /// a zero or over-limit XOF output length fails with `OutputLenInvalid`
    /// before any allocation or squeeze
    #[test]
    fn test_xof_output_len_invalid() {
        for &codec in &[Codec::Shake128, Codec::Shake256] {
            for &output_len in &[0, MAX_HASH_LENGTH + 1] {
                let mut builder = Builder::new(codec).unwrap();
                builder.update(b"bad output length");
                builder.output_len(output_len);
                let result = builder.try_build();
                assert!(
                    matches!(
                        result,
                        Err(Error::OutputLenInvalid {
                            output_len: requested,
                            max,
                            ..
                        }) if requested == output_len && max == MAX_HASH_LENGTH
                    ),
                    "codec {codec:?} accepted output length {output_len}"
                );
            }
        }
    }

    /// the minimum XOF output length of one byte builds
    #[test]
    fn test_xof_output_len_minimum() {
        for &codec in &[Codec::Shake128, Codec::Shake256] {
            let mut builder = Builder::new(codec).unwrap();
            builder.update(b"one byte output");
            builder.output_len(1);
            let mh = builder.try_build().unwrap();
            assert_eq!(mh.codec(), codec);
            assert_eq!(mh.as_ref().len(), 1);
        }
    }

    /// fixed-output codecs ignore an `output_len` setting
    #[test]
    fn test_fixed_output_ignores_output_len() {
        for &output_len in &[0, 33, MAX_HASH_LENGTH + 1] {
            let mut builder = Builder::new(Codec::Sha2256).unwrap();
            builder.update(b"ignored output length");
            builder.output_len(output_len);
            let mh = builder.try_build().unwrap();
            assert_eq!(mh.codec(), Codec::Sha2256);
            assert_eq!(mh.as_ref().len(), 32);
        }

        let result = Builder::new(Codec::Sha2256)
            .unwrap()
            .with_hash(vec![0u8; 32])
            .try_build();
        assert!(result.is_ok());
    }

    /// XOF prefix consistency: a short streamed digest prefixes the long
    /// digest of the same input, while the two multihashes still encode
    /// differently
    #[test]
    fn test_xof_prefix_consistency() {
        for (codec, short_len) in [(Codec::Shake128, 32usize), (Codec::Shake256, 64usize)] {
            let data = b"prefix consistency";

            let mut builder = Builder::new(codec).unwrap();
            builder.update(data);
            builder.output_len(short_len);
            let short = builder.try_build().unwrap();

            let mut builder = Builder::new(codec).unwrap();
            builder.update(data);
            builder.output_len(short_len * 2);
            let long = builder.try_build().unwrap();

            assert_eq!(short.codec(), long.codec());
            assert_eq!(short.as_ref().len(), short_len);
            assert_eq!(long.as_ref().len(), short_len * 2);
            assert!(
                long.as_ref().starts_with(short.as_ref()),
                "codec {codec:?}: short digest is not a prefix of long digest"
            );

            let short_bytes: Vec<u8> = short.clone().into();
            let long_bytes: Vec<u8> = long.clone().into();
            assert_ne!(
                short_bytes, long_bytes,
                "codec {codec:?}: digest encodings matched across lengths"
            );
        }
    }

    /// a builder streaming an XOF stays `Send` and `Sync`, and the digest
    /// built across a thread matches the one-shot digest
    #[test]
    fn test_xof_send_sync_streaming() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<Builder>();
        assert_sync::<Builder>();

        let mut builder = Builder::new(Codec::Shake128).unwrap();
        builder.update(b"sent across threads");
        builder.output_len(32);
        let handle = std::thread::spawn(move || {
            builder.update(b" and more");
            builder.try_build().unwrap()
        });
        let streamed = handle.join().unwrap();

        let mut one_shot = Builder::new(Codec::Shake128).unwrap();
        one_shot.update(b"sent across threads and more");
        one_shot.output_len(32);
        let one_shot = one_shot.try_build().unwrap();

        assert_eq!(streamed, one_shot);
    }

    /// an explicit XOF digest inside the `1..=MAX_HASH_LENGTH` policy
    /// builds, and the digest takes precedence over an `output_len`
    /// setting
    #[test]
    fn test_xof_with_hash_policy() {
        let hash = vec![3u8; 8];
        let mut builder = Builder::new(Codec::Shake256).unwrap();
        builder.update(b"streamed but ignored");
        builder.output_len(64);
        let mh = builder.with_hash(hash.clone()).try_build().unwrap();
        assert_eq!(mh.codec(), Codec::Shake256);
        assert_eq!(mh.as_ref(), hash.as_slice());
    }
}
