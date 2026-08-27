//! Unified error type for the `pqc-kem` crate.
//!
//! All KEM operations return `Result<T, KemError>`. This type is designed to be
//! `no_std`-compatible (with `alloc`) and serializable for WASM boundary crossing.

extern crate alloc;
use alloc::string::{String, ToString};

use thiserror::Error;

/// Errors that can occur during KEM operations.
#[derive(Debug, Error)]
pub enum KemError {
    /// Key generation failed (e.g., RNG failure).
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    /// Encapsulation failed (e.g., invalid public key length).
    #[error("encapsulation failed: {0}")]
    Encapsulation(String),

    /// Decapsulation failed (e.g., ciphertext tampered, wrong key).
    #[error("decapsulation failed: {0}")]
    Decapsulation(String),

    /// Invalid key material (wrong length, malformed encoding).
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Invalid ciphertext (wrong length, malformed encoding).
    #[error("invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    /// Base64 decoding error.
    #[error("base64 decode error: {0}")]
    Base64Decode(String),

    /// Hex decoding error.
    #[error("hex decode error: {0}")]
    HexDecode(String),

    /// JSON serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// The requested algorithm is not available (feature not enabled).
    #[error("algorithm not available: {0} (enable the '{1}' feature)")]
    AlgorithmNotAvailable(String, String),

    /// HKDF key derivation failed.
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    /// Symmetric encryption/decryption failed.
    #[error("symmetric cipher error: {0}")]
    SymmetricCipher(String),

    /// Generic internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl KemError {
    /// Convert to a string suitable for crossing the WASM boundary.
    pub fn to_wasm_string(&self) -> String {
        self.to_string()
    }
}

/// Convenience type alias for KEM results.
pub type KemResult<T> = Result<T, KemError>;
