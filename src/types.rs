// SPDX-License-Identifier: Apache-2.0
//! Type-safe wrappers for multihash components
//!
//! This module provides newtype wrappers that prevent mixing up hash digests
//! with other byte arrays and provide type-safe abstractions.

use multi_codec::Codec;
use core::fmt;

/// A cryptographic hash digest
///
/// This newtype wrapper provides type safety for hash digest bytes,
/// preventing accidental confusion with other byte arrays.
///
/// # Examples
///
/// ```
/// use multi_hash::types::HashDigest;
///
/// let digest = HashDigest::new(vec![0u8; 32]);
/// assert_eq!(digest.len(), 32);
/// assert_eq!(digest.as_bytes().len(), 32);
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HashDigest(Vec<u8>);

impl HashDigest {
    /// Create a new HashDigest from bytes
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::types::HashDigest;
    ///
    /// let digest = HashDigest::new(vec![1, 2, 3, 4]);
    /// assert_eq!(digest.len(), 4);
    /// ```
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the digest as a byte slice
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::types::HashDigest;
    ///
    /// let digest = HashDigest::new(vec![1, 2, 3]);
    /// assert_eq!(digest.as_bytes(), &[1, 2, 3]);
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the length of the digest in bytes
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::types::HashDigest;
    ///
    /// let digest = HashDigest::new(vec![0u8; 32]);
    /// assert_eq!(digest.len(), 32);
    /// ```
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the digest is empty
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::types::HashDigest;
    ///
    /// let empty = HashDigest::new(vec![]);
    /// assert!(empty.is_empty());
    ///
    /// let digest = HashDigest::new(vec![1, 2, 3]);
    /// assert!(!digest.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Convert into the inner byte vector
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::types::HashDigest;
    ///
    /// let digest = HashDigest::new(vec![1, 2, 3]);
    /// let bytes: Vec<u8> = digest.into_bytes();
    /// assert_eq!(bytes, vec![1, 2, 3]);
    /// ```
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for HashDigest {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<HashDigest> for Vec<u8> {
    fn from(digest: HashDigest) -> Vec<u8> {
        digest.0
    }
}

impl AsRef<[u8]> for HashDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for HashDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// A hash algorithm identifier
///
/// This newtype wrapper provides type safety for hash algorithm codecs,
/// making it clear when a Codec is being used specifically as a hash algorithm.
///
/// # Examples
///
/// ```
/// use multi_hash::types::AlgorithmId;
/// use multi_codec::Codec;
///
/// let algo = AlgorithmId::new(Codec::Sha2256);
/// assert_eq!(algo.codec(), Codec::Sha2256);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AlgorithmId(Codec);

impl AlgorithmId {
    /// Create a new AlgorithmId
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::types::AlgorithmId;
    /// use multi_codec::Codec;
    ///
    /// let algo = AlgorithmId::new(Codec::Sha2256);
    /// assert_eq!(algo.codec(), Codec::Sha2256);
    /// ```
    pub const fn new(codec: Codec) -> Self {
        Self(codec)
    }

    /// Get the underlying codec
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::types::AlgorithmId;
    /// use multi_codec::Codec;
    ///
    /// let algo = AlgorithmId::new(Codec::Sha2512);
    /// assert_eq!(algo.codec(), Codec::Sha2512);
    /// ```
    pub const fn codec(self) -> Codec {
        self.0
    }

    /// Get the codec code
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::types::AlgorithmId;
    /// use multi_codec::Codec;
    ///
    /// let algo = AlgorithmId::new(Codec::Sha2256);
    /// assert_eq!(algo.code(), 0x12);
    /// ```
    pub fn code(self) -> u64 {
        self.0.code()
    }

    /// Get the algorithm name
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::types::AlgorithmId;
    /// use multi_codec::Codec;
    ///
    /// let algo = AlgorithmId::new(Codec::Sha2256);
    /// assert_eq!(algo.name(), "sha2-256");
    /// ```
    pub fn name(self) -> &'static str {
        self.0.into()
    }
}

impl From<Codec> for AlgorithmId {
    fn from(codec: Codec) -> Self {
        Self(codec)
    }
}

impl From<AlgorithmId> for Codec {
    fn from(algo: AlgorithmId) -> Codec {
        algo.0
    }
}

impl fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_digest_new() {
        let digest = HashDigest::new(vec![1, 2, 3]);
        assert_eq!(digest.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn test_hash_digest_len() {
        let digest = HashDigest::new(vec![0u8; 32]);
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_hash_digest_is_empty() {
        let empty = HashDigest::new(vec![]);
        assert!(empty.is_empty());

        let digest = HashDigest::new(vec![1]);
        assert!(!digest.is_empty());
    }

    #[test]
    fn test_hash_digest_conversions() {
        let bytes = vec![1, 2, 3, 4];
        let digest = HashDigest::from(bytes.clone());
        let back: Vec<u8> = digest.into_bytes();
        assert_eq!(back, bytes);
    }

    #[test]
    fn test_hash_digest_as_ref() {
        let digest = HashDigest::new(vec![1, 2, 3]);
        let slice: &[u8] = digest.as_ref();
        assert_eq!(slice, &[1, 2, 3]);
    }

    #[test]
    fn test_hash_digest_display() {
        let digest = HashDigest::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(digest.to_string(), "deadbeef");
    }

    #[test]
    fn test_hash_digest_equality() {
        let d1 = HashDigest::new(vec![1, 2, 3]);
        let d2 = HashDigest::new(vec![1, 2, 3]);
        let d3 = HashDigest::new(vec![4, 5, 6]);

        assert_eq!(d1, d2);
        assert_ne!(d1, d3);
    }

    #[test]
    fn test_hash_digest_ordering() {
        let d1 = HashDigest::new(vec![1, 2, 3]);
        let d2 = HashDigest::new(vec![1, 2, 4]);

        assert!(d1 < d2);
    }

    #[test]
    fn test_hash_digest_hash_trait() {
        use std::collections::HashMap;

        let mut map = HashMap::new();
        let digest = HashDigest::new(vec![1, 2, 3]);
        map.insert(digest.clone(), "test");

        assert_eq!(map.get(&digest), Some(&"test"));
    }

    #[test]
    fn test_algorithm_id_new() {
        let algo = AlgorithmId::new(Codec::Sha2256);
        assert_eq!(algo.codec(), Codec::Sha2256);
    }

    #[test]
    fn test_algorithm_id_code() {
        let algo = AlgorithmId::new(Codec::Sha2256);
        assert_eq!(algo.code(), 0x12);
    }

    #[test]
    fn test_algorithm_id_name() {
        let algo = AlgorithmId::new(Codec::Sha2256);
        assert_eq!(algo.name(), "sha2-256");
    }

    #[test]
    fn test_algorithm_id_conversions() {
        let codec = Codec::Sha2512;
        let algo = AlgorithmId::from(codec);
        let back: Codec = algo.into();
        assert_eq!(back, codec);
    }

    #[test]
    fn test_algorithm_id_display() {
        let algo = AlgorithmId::new(Codec::Sha3256);
        assert_eq!(algo.to_string(), "sha3-256");
    }

    #[test]
    fn test_algorithm_id_copy() {
        let algo1 = AlgorithmId::new(Codec::Blake3);
        let algo2 = algo1;
        assert_eq!(algo1, algo2);
    }

    #[test]
    fn test_newtypes_are_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<HashDigest>();
        assert_sync::<HashDigest>();
        assert_send::<AlgorithmId>();
        assert_sync::<AlgorithmId>();
    }
}
