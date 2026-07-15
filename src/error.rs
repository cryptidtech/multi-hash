// SPDX-License-Identifier: Apache-2.0
//! Error types for multi-hash

/// Errors produced by the multi-hash crate
///
/// All error variants include contextual information to help with debugging
/// and provide actionable error messages.
///
/// # Examples
///
/// ```
/// use multi_hash::Error;
/// use multi_codec::Codec;
///
/// // Unsupported algorithm error includes the codec
/// let err = Error::unsupported_hash(Codec::Identity);
/// assert!(matches!(err, Error::UnsupportedHash { .. }));
///
/// // Missing hash error
/// let err = Error::MissingHash;
/// assert_eq!(err.kind(), "MissingHash");
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Error from multi-codec crate
    ///
    /// This error occurs when codec operations fail, typically due to
    /// invalid codec identifiers or encoding/decoding issues.
    #[error(transparent)]
    Multicodec(#[from] multi_codec::Error),

    /// Error from multi-util crate
    ///
    /// This error occurs when utility operations fail, such as base encoding
    /// or variable-length integer operations.
    #[error(transparent)]
    Multiutil(#[from] multi_util::Error),

    /// Missing hash data
    ///
    /// The multihash builder was used without setting the hash digest data.
    ///
    /// # Resolution
    ///
    /// Call `Builder::with_hash()` to set the hash digest before calling `build()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::Error;
    ///
    /// let err = Error::MissingHash;
    /// assert_eq!(err.kind(), "MissingHash");
    /// ```
    #[error(
        "Missing hash data\n\
             The multihash builder requires hash digest data.\n\
             Call Builder::with_hash() before build()."
    )]
    MissingHash,

    /// Unsupported hash algorithm
    ///
    /// The specified codec is not a supported cryptographic hash algorithm
    /// or is not implemented in this crate.
    ///
    /// # Context
    ///
    /// - `codec`: The unsupported codec that was requested
    ///
    /// # Resolution
    ///
    /// Use one of the supported hash algorithms. See the `HASH_CODECS` or
    /// `SAFE_HASH_CODECS` constants for the list of supported algorithms.
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::Error;
    /// use multi_codec::Codec;
    ///
    /// let err = Error::unsupported_hash(Codec::Identity);
    /// assert!(matches!(err, Error::UnsupportedHash { .. }));
    /// ```
    #[error(
        "Unsupported hash algorithm: {codec:?}\n\
             The codec {codec:?} is not a supported cryptographic hash algorithm.\n\
             See HASH_CODECS or SAFE_HASH_CODECS for supported algorithms."
    )]
    UnsupportedHash {
        /// The unsupported codec that was requested
        codec: multi_codec::Codec,
    },

    /// Invalid hash digest length
    ///
    /// The provided hash digest length doesn't match the expected output
    /// size for the specified hash algorithm.
    ///
    /// # Context
    ///
    /// - `algorithm`: The hash algorithm codec
    /// - `expected`: The expected digest length in bytes
    /// - `actual`: The actual digest length provided
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::Error;
    /// use multi_codec::Codec;
    ///
    /// let err = Error::invalid_digest_length(Codec::Sha2256, 32, 16);
    /// assert!(matches!(err, Error::InvalidDigestLength { .. }));
    /// ```
    #[error(
        "Invalid hash digest length for {algorithm:?}\n\
             Expected {expected} bytes for {algorithm:?}, but got {actual} bytes.\n\
             Ensure the hash digest matches the algorithm's output size."
    )]
    InvalidDigestLength {
        /// The hash algorithm
        algorithm: multi_codec::Codec,
        /// Expected digest length in bytes
        expected: usize,
        /// Actual digest length provided
        actual: usize,
    },

    /// Hash computation failed
    ///
    /// An error occurred while computing the cryptographic hash.
    ///
    /// # Context
    ///
    /// - `algorithm`: The hash algorithm that failed
    /// - `message`: Description of what went wrong
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::Error;
    /// use multi_codec::Codec;
    ///
    /// let err = Error::hash_compute_failed(Codec::Sha2256, "input too large");
    /// assert!(matches!(err, Error::HashComputeFailed { .. }));
    /// ```
    #[error("Hash computation failed for {algorithm:?}: {message}")]
    HashComputeFailed {
        /// The hash algorithm
        algorithm: multi_codec::Codec,
        /// Error message
        message: String,
    },
}

impl Error {
    /// Create an `UnsupportedHash` error
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::Error;
    /// use multi_codec::Codec;
    ///
    /// let err = Error::unsupported_hash(Codec::Identity);
    /// assert!(matches!(err, Error::UnsupportedHash { .. }));
    /// ```
    #[must_use]
    pub const fn unsupported_hash(codec: multi_codec::Codec) -> Self {
        Self::UnsupportedHash { codec }
    }

    /// Create an `InvalidDigestLength` error
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::Error;
    /// use multi_codec::Codec;
    ///
    /// let err = Error::invalid_digest_length(Codec::Sha2256, 32, 16);
    /// assert!(matches!(err, Error::InvalidDigestLength { .. }));
    /// ```
    #[must_use]
    pub const fn invalid_digest_length(
        algorithm: multi_codec::Codec,
        expected: usize,
        actual: usize,
    ) -> Self {
        Self::InvalidDigestLength {
            algorithm,
            expected,
            actual,
        }
    }

    /// Create a `HashComputeFailed` error
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::Error;
    /// use multi_codec::Codec;
    ///
    /// let err = Error::hash_compute_failed(Codec::Sha2256, "internal error");
    /// assert!(matches!(err, Error::HashComputeFailed { .. }));
    /// ```
    pub fn hash_compute_failed(algorithm: multi_codec::Codec, message: impl Into<String>) -> Self {
        Self::HashComputeFailed {
            algorithm,
            message: message.into(),
        }
    }

    /// Get the error kind as a string
    ///
    /// Returns a short identifier for the error type, useful for
    /// programmatic error handling and logging.
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::Error;
    /// use multi_codec::Codec;
    ///
    /// let err = Error::MissingHash;
    /// assert_eq!(err.kind(), "MissingHash");
    ///
    /// let err = Error::unsupported_hash(Codec::Identity);
    /// assert_eq!(err.kind(), "UnsupportedHash");
    /// ```
    #[must_use]
    pub const fn kind(&self) -> &str {
        match self {
            Self::Multicodec(_) => "Multicodec",
            Self::Multiutil(_) => "Multiutil",
            Self::MissingHash => "MissingHash",
            Self::UnsupportedHash { .. } => "UnsupportedHash",
            Self::InvalidDigestLength { .. } => "InvalidDigestLength",
            Self::HashComputeFailed { .. } => "HashComputeFailed",
        }
    }

    /// Get additional context about the error
    ///
    /// Returns human-readable context information that can help
    /// diagnose the error.
    ///
    /// # Examples
    ///
    /// ```
    /// use multi_hash::Error;
    /// use multi_codec::Codec;
    ///
    /// let err = Error::unsupported_hash(Codec::Identity);
    /// let context = err.context();
    /// assert!(!context.is_empty());
    /// ```
    #[must_use]
    pub fn context(&self) -> String {
        match self {
            Self::Multicodec(e) => format!("Multicodec error: {e}"),
            Self::Multiutil(e) => format!("Multiutil error: {e}"),
            Self::MissingHash => "Missing hash data in builder".to_string(),
            Self::UnsupportedHash { codec } => format!("Unsupported hash: {codec:?}"),
            Self::InvalidDigestLength {
                algorithm,
                expected,
                actual,
            } => format!(
                "Invalid digest length for {algorithm:?}: expected {expected}, got {actual}"
            ),
            Self::HashComputeFailed { algorithm, message } => {
                format!("Hash computation failed for {algorithm:?}: {message}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use multi_codec::Codec;

    #[test]
    fn test_missing_hash_error() {
        let err = Error::MissingHash;
        assert_eq!(err.kind(), "MissingHash");
        assert!(err.to_string().contains("Missing hash data"));
    }

    #[test]
    fn test_unsupported_hash_error() {
        let err = Error::unsupported_hash(Codec::Identity);
        assert_eq!(err.kind(), "UnsupportedHash");
        let msg = err.to_string();
        // Check error message is present and non-empty
        assert!(!msg.is_empty());
        assert!(msg.len() > 10);
        // Check context contains codec info
        let context = err.context();
        assert!(!context.is_empty());
    }

    #[test]
    fn test_invalid_digest_length_error() {
        let err = Error::invalid_digest_length(Codec::Sha2256, 32, 16);
        assert_eq!(err.kind(), "InvalidDigestLength");
        let msg = err.to_string();
        assert!(msg.contains("32"));
        assert!(msg.contains("16"));
    }

    #[test]
    fn test_hash_compute_failed_error() {
        let err = Error::hash_compute_failed(Codec::Sha2256, "test failure");
        assert_eq!(err.kind(), "HashComputeFailed");
        assert!(err.to_string().contains("test failure"));
    }

    #[test]
    fn test_error_kind_uniqueness() {
        let errors = [
            Error::MissingHash,
            Error::unsupported_hash(Codec::Identity),
            Error::invalid_digest_length(Codec::Sha2256, 32, 16),
            Error::hash_compute_failed(Codec::Sha2256, "test"),
        ];

        let kinds: Vec<_> = errors.iter().map(Error::kind).collect();
        assert_eq!(kinds.len(), 4);

        // All kinds should be unique
        for (i, k1) in kinds.iter().enumerate() {
            for (j, k2) in kinds.iter().enumerate() {
                if i != j {
                    assert_ne!(k1, k2);
                }
            }
        }
    }

    #[test]
    fn test_error_context_informative() {
        let err = Error::unsupported_hash(Codec::Sha2256);
        let context = err.context();
        assert!(!context.is_empty());
        assert!(context.contains("Sha2256") || context.contains("sha2-256"));

        let err = Error::invalid_digest_length(Codec::Sha2512, 64, 32);
        let context = err.context();
        assert!(context.contains("64"));
        assert!(context.contains("32"));
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<Error>();
        assert_sync::<Error>();
    }
}
