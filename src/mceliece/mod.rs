//! Classic McEliece — NIST Round 4 Alternate Candidate
//!
//! Classic McEliece is a code-based KEM with the longest security track record
//! of any post-quantum algorithm (based on Goppa codes, secure since 1978).
//!
//! # ⚠️ Key Size Warning
//! Classic McEliece has extremely large public keys:
//! - mceliece348864:  261,120 bytes (~255 KB)
//! - mceliece460896:  524,160 bytes (~512 KB)
//! - mceliece6688128: 1,044,992 bytes (~1 MB)
//!
//! These sizes make it impractical for most network protocols but suitable for
//! offline key exchange or long-term archival encryption.
//!
//! # Feature Gate
//! This module requires the `mceliece` feature flag:
//! ```toml
//! pqc-kem = { version = "0.1", features = ["mceliece"] }
//! ```
//!
//! # WASM Compatibility Note
//! Classic McEliece uses C FFI and has keys too large for practical WASM use.
//! Use ML-KEM for WASM targets.
//!
//! **⚠️ NOT YET IMPLEMENTED** — The `mceliece` feature is currently a stub.
//! Enabling it will produce a compile-time error. Classic McEliece support
//! will be added in a future release.

#[cfg(feature = "mceliece")]
compile_error!(
    "The `mceliece` feature is not yet implemented. \
     pqcrypto-classicmceliece's published API does not match this crate's \
     calls against mceliece348864 (25 compile errors on the real build). \
     Remove `--features mceliece` from your build command. \
     Classic McEliece support will be added in a future release."
);

// Below this point, every struct/impl is gated `#[cfg(any())]`, not
// `#[cfg(feature = "mceliece")]` -- deliberate: it never compiles, regardless
// of the `mceliece` feature. The `compile_error!` above already halts the
// build the instant `mceliece` is enabled, but a `compile_error!` is just an
// item -- it doesn't exclude the rest of the module from being type-checked
// in the same pass, so without this guard enabling `mceliece` surfaces the
// real (broken) pqcrypto_classicmceliece errors alongside the intended one,
// burying the single clear message this feature gate exists to give. Kept
// only as a shape reference for a future real implementation.

extern crate alloc;


use crate::error::KemError;

/// Classic McEliece keypair (NIST Round 4 alternate candidate).
///
/// Uses mceliece348864 (smallest parameter set, ~255 KB public key) by default.
///
/// # ⚠️ Performance Warning
/// Key generation for Classic McEliece is slow (seconds on modern hardware).
/// Cache the keypair and do not regenerate frequently.
#[cfg(any())]
pub struct McElieceKeypair {
    public_key_bytes: Vec<u8>,
    secret_key_bytes: Vec<u8>,
}

#[cfg(any())]
impl McElieceKeypair {
    /// Generate a new Classic McEliece keypair.
    ///
    /// **Warning:** This operation is slow (may take several seconds).
    pub fn generate<R: CryptoRng + RngCore>(_rng: &mut R) -> KemResult<Self> {
        use pqcrypto_classicmceliece::mceliece348864;
        use pqcrypto_traits::kem::{PublicKey, SecretKey};

        let (pk, sk) = mceliece348864::keypair();
        Ok(Self {
            public_key_bytes: pk.as_bytes().to_vec(),
            secret_key_bytes: sk.as_bytes().to_vec(),
        })
    }

    /// Returns the public key (~255 KB for mceliece348864).
    pub fn public_key(&self) -> KemPublicKey {
        KemPublicKey::new(KemAlgorithm::ClassicMceliece, self.public_key_bytes.clone())
    }

    /// Returns the secret key.
    pub fn secret_key(&self) -> KemSecretKey {
        KemSecretKey::new(KemAlgorithm::ClassicMceliece, self.secret_key_bytes.clone())
    }

    /// Encapsulate to a recipient's Classic McEliece public key.
    pub fn encapsulate<R: CryptoRng + RngCore>(
        _rng: &mut R,
        recipient_public_key: &KemPublicKey,
    ) -> KemResult<(KemCiphertext, SharedSecret)> {
        use pqcrypto_classicmceliece::mceliece348864;
        use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret as PqSharedSecret};

        if recipient_public_key.algorithm != KemAlgorithm::ClassicMceliece {
            return Err(KemError::InvalidKey(
                format!("expected Classic McEliece key, got {:?}", recipient_public_key.algorithm)
            ));
        }

        let pk = mceliece348864::PublicKey::from_bytes(&recipient_public_key.bytes)
            .map_err(|e| KemError::InvalidKey(format!("{:?}", e)))?;

        let (ss, ct) = mceliece348864::encapsulate(&pk);

        Ok((
            KemCiphertext::new(KemAlgorithm::ClassicMceliece, ct.as_bytes().to_vec()),
            SharedSecret::new(ss.as_bytes().to_vec()),
        ))
    }

    /// Decapsulate a ciphertext, recovering the shared secret.
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> KemResult<SharedSecret> {
        use pqcrypto_classicmceliece::mceliece348864;
        use pqcrypto_traits::kem::{Ciphertext, SecretKey, SharedSecret as PqSharedSecret};

        if ciphertext.algorithm != KemAlgorithm::ClassicMceliece {
            return Err(KemError::InvalidCiphertext(
                format!("expected Classic McEliece ciphertext, got {:?}", ciphertext.algorithm)
            ));
        }

        let sk = mceliece348864::SecretKey::from_bytes(&self.secret_key_bytes)
            .map_err(|e| KemError::InvalidKey(format!("{:?}", e)))?;
        let ct = mceliece348864::Ciphertext::from_bytes(&ciphertext.bytes)
            .map_err(|e| KemError::InvalidCiphertext(format!("{:?}", e)))?;

        let ss = mceliece348864::decapsulate(&ct, &sk);
        Ok(SharedSecret::new(ss.as_bytes().to_vec()))
    }
}

/// Returns an error indicating Classic McEliece is not available without the `mceliece` feature.
#[cfg(not(feature = "mceliece"))]
pub fn mceliece_not_available() -> KemError {
    KemError::AlgorithmNotAvailable("Classic McEliece".into(), "mceliece".into())
}
