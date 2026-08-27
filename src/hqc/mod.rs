//! HQC (Hamming Quasi-Cyclic) — NIST 2025 Standard
//!
//! HQC was selected as a NIST standard in 2025 as a code-based KEM alternative
//! to ML-KEM, providing diversity in the post-quantum algorithm portfolio.
//!
//! # Parameter Sets
//! - [`Hqc128`] — Security Level 1 (AES-128 equivalent)
//! - [`Hqc192`] — Security Level 3 (AES-192 equivalent)
//! - [`Hqc256`] — Security Level 5 (AES-256 equivalent)
//!
//! # Feature Gate
//! This module requires the `hqc` feature flag:
//! ```toml
//! pqc-kem = { version = "0.1", features = ["hqc"] }
//! ```
//!
//! # WASM Compatibility Note
//! HQC uses C FFI via `pqcrypto-hqc`. It is NOT compatible with
//! `wasm32-unknown-unknown`. For WASM targets, use ML-KEM instead.
//! HQC can be used in native (x86_64, aarch64) environments.
//!
//! **⚠️ NOT YET IMPLEMENTED** — The `hqc` feature is currently a stub.
//! Enabling it will produce a compile-time error. HQC support will be added
//! in a future release.

#[cfg(feature = "hqc")]
compile_error!(
    "The `hqc` feature is not yet implemented. \
     pqcrypto-hqc 0.1's published API does not expose the hqc128/192/256 \
     modules this crate calls against (82 compile errors on the real build). \
     Remove `--features hqc` from your build command. \
     HQC support will be added in a future release."
);

// Below this point, every struct/impl is gated `#[cfg(any())]`, not
// `#[cfg(feature = "hqc")]` -- deliberate: it never compiles, regardless of
// the `hqc` feature. The `compile_error!` above already halts the build the
// instant `hqc` is enabled, but a `compile_error!` is just an item -- it
// doesn't exclude the rest of the module from being type-checked in the
// same pass, so without this guard enabling `hqc` surfaces the real (broken)
// pqcrypto_hqc errors alongside the intended one, burying the single clear
// message this feature gate exists to give. Kept only as a shape reference
// for a future real implementation.

extern crate alloc;


use crate::error::KemError;

// ── HQC-128 ───────────────────────────────────────────────────────────────────

/// HQC-128 keypair (NIST 2025, Security Level 1).
///
/// Public key: 2249 bytes | Ciphertext: 4481 bytes | Shared secret: 64 bytes (truncated to 32)
#[cfg(any())]
pub struct Hqc128Keypair {
    public_key_bytes:  Vec<u8>,
    secret_key_bytes:  Vec<u8>,
}

#[cfg(any())]
impl Hqc128Keypair {
    /// Generate a new HQC-128 keypair.
    ///
    /// Note: The RNG parameter is accepted for API consistency but HQC key generation
    /// uses the system entropy source internally via pqcrypto-hqc.
    pub fn generate<R: CryptoRng + RngCore>(_rng: &mut R) -> KemResult<Self> {
        use pqcrypto_hqc::hqc128;
        use pqcrypto_traits::kem::{PublicKey, SecretKey};

        let (pk, sk) = hqc128::keypair();
        Ok(Self {
            public_key_bytes: pk.as_bytes().to_vec(),
            secret_key_bytes: sk.as_bytes().to_vec(),
        })
    }

    /// Returns the public key.
    pub fn public_key(&self) -> KemPublicKey {
        KemPublicKey::new(KemAlgorithm::Hqc128, self.public_key_bytes.clone())
    }

    /// Returns the secret key (zeroized on drop).
    pub fn secret_key(&self) -> KemSecretKey {
        KemSecretKey::new(KemAlgorithm::Hqc128, self.secret_key_bytes.clone())
    }

    /// Encapsulate to a recipient's HQC-128 public key.
    pub fn encapsulate<R: CryptoRng + RngCore>(
        _rng: &mut R,
        recipient_public_key: &KemPublicKey,
    ) -> KemResult<(KemCiphertext, SharedSecret)> {
        use pqcrypto_hqc::hqc128;
        use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret as PqSharedSecret};

        if recipient_public_key.algorithm != KemAlgorithm::Hqc128 {
            return Err(KemError::InvalidKey(
                format!("expected HQC-128 key, got {:?}", recipient_public_key.algorithm)
            ));
        }

        let pk = hqc128::PublicKey::from_bytes(&recipient_public_key.bytes)
            .map_err(|e| KemError::InvalidKey(format!("{:?}", e)))?;

        let (ss, ct) = hqc128::encapsulate(&pk);

        // HQC shared secret is 64 bytes; truncate to 32 for consistency
        let ss_bytes = ss.as_bytes();
        let ss_32 = ss_bytes[..32].to_vec();

        Ok((
            KemCiphertext::new(KemAlgorithm::Hqc128, ct.as_bytes().to_vec()),
            SharedSecret::new(ss_32),
        ))
    }

    /// Decapsulate a ciphertext, recovering the shared secret.
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> KemResult<SharedSecret> {
        use pqcrypto_hqc::hqc128;
        use pqcrypto_traits::kem::{Ciphertext, SecretKey, SharedSecret as PqSharedSecret};

        if ciphertext.algorithm != KemAlgorithm::Hqc128 {
            return Err(KemError::InvalidCiphertext(
                format!("expected HQC-128 ciphertext, got {:?}", ciphertext.algorithm)
            ));
        }

        let sk = hqc128::SecretKey::from_bytes(&self.secret_key_bytes)
            .map_err(|e| KemError::InvalidKey(format!("{:?}", e)))?;
        let ct = hqc128::Ciphertext::from_bytes(&ciphertext.bytes)
            .map_err(|e| KemError::InvalidCiphertext(format!("{:?}", e)))?;

        let ss = hqc128::decapsulate(&ct, &sk);
        let ss_bytes = ss.as_bytes();
        let ss_32 = ss_bytes[..32].to_vec();

        Ok(SharedSecret::new(ss_32))
    }
}

// ── HQC-192 ───────────────────────────────────────────────────────────────────

/// HQC-192 keypair (NIST 2025, Security Level 3).
///
/// Public key: 4522 bytes | Ciphertext: 8978 bytes | Shared secret: 64 bytes (truncated to 32)
#[cfg(any())]
pub struct Hqc192Keypair {
    public_key_bytes: Vec<u8>,
    secret_key_bytes: Vec<u8>,
}

#[cfg(any())]
impl Hqc192Keypair {
    /// Generate a new HQC-192 keypair.
    pub fn generate<R: CryptoRng + RngCore>(_rng: &mut R) -> KemResult<Self> {
        use pqcrypto_hqc::hqc192;
        use pqcrypto_traits::kem::{PublicKey, SecretKey};

        let (pk, sk) = hqc192::keypair();
        Ok(Self {
            public_key_bytes: pk.as_bytes().to_vec(),
            secret_key_bytes: sk.as_bytes().to_vec(),
        })
    }

    /// Returns the public key.
    pub fn public_key(&self) -> KemPublicKey {
        KemPublicKey::new(KemAlgorithm::Hqc192, self.public_key_bytes.clone())
    }

    /// Returns the secret key.
    pub fn secret_key(&self) -> KemSecretKey {
        KemSecretKey::new(KemAlgorithm::Hqc192, self.secret_key_bytes.clone())
    }

    /// Encapsulate to a recipient's HQC-192 public key.
    pub fn encapsulate<R: CryptoRng + RngCore>(
        _rng: &mut R,
        recipient_public_key: &KemPublicKey,
    ) -> KemResult<(KemCiphertext, SharedSecret)> {
        use pqcrypto_hqc::hqc192;
        use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret as PqSharedSecret};

        if recipient_public_key.algorithm != KemAlgorithm::Hqc192 {
            return Err(KemError::InvalidKey(
                format!("expected HQC-192 key, got {:?}", recipient_public_key.algorithm)
            ));
        }

        let pk = hqc192::PublicKey::from_bytes(&recipient_public_key.bytes)
            .map_err(|e| KemError::InvalidKey(format!("{:?}", e)))?;

        let (ss, ct) = hqc192::encapsulate(&pk);
        let ss_bytes = ss.as_bytes();
        let ss_32 = ss_bytes[..32].to_vec();

        Ok((
            KemCiphertext::new(KemAlgorithm::Hqc192, ct.as_bytes().to_vec()),
            SharedSecret::new(ss_32),
        ))
    }

    /// Decapsulate a ciphertext, recovering the shared secret.
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> KemResult<SharedSecret> {
        use pqcrypto_hqc::hqc192;
        use pqcrypto_traits::kem::{Ciphertext, SecretKey, SharedSecret as PqSharedSecret};

        if ciphertext.algorithm != KemAlgorithm::Hqc192 {
            return Err(KemError::InvalidCiphertext(
                format!("expected HQC-192 ciphertext, got {:?}", ciphertext.algorithm)
            ));
        }

        let sk = hqc192::SecretKey::from_bytes(&self.secret_key_bytes)
            .map_err(|e| KemError::InvalidKey(format!("{:?}", e)))?;
        let ct = hqc192::Ciphertext::from_bytes(&ciphertext.bytes)
            .map_err(|e| KemError::InvalidCiphertext(format!("{:?}", e)))?;

        let ss = hqc192::decapsulate(&ct, &sk);
        let ss_bytes = ss.as_bytes();
        let ss_32 = ss_bytes[..32].to_vec();

        Ok(SharedSecret::new(ss_32))
    }
}

// ── HQC-256 ───────────────────────────────────────────────────────────────────

/// HQC-256 keypair (NIST 2025, Security Level 5).
///
/// Public key: 7245 bytes | Ciphertext: 14469 bytes | Shared secret: 64 bytes (truncated to 32)
#[cfg(any())]
pub struct Hqc256Keypair {
    public_key_bytes: Vec<u8>,
    secret_key_bytes: Vec<u8>,
}

#[cfg(any())]
impl Hqc256Keypair {
    /// Generate a new HQC-256 keypair.
    pub fn generate<R: CryptoRng + RngCore>(_rng: &mut R) -> KemResult<Self> {
        use pqcrypto_hqc::hqc256;
        use pqcrypto_traits::kem::{PublicKey, SecretKey};

        let (pk, sk) = hqc256::keypair();
        Ok(Self {
            public_key_bytes: pk.as_bytes().to_vec(),
            secret_key_bytes: sk.as_bytes().to_vec(),
        })
    }

    /// Returns the public key.
    pub fn public_key(&self) -> KemPublicKey {
        KemPublicKey::new(KemAlgorithm::Hqc256, self.public_key_bytes.clone())
    }

    /// Returns the secret key.
    pub fn secret_key(&self) -> KemSecretKey {
        KemSecretKey::new(KemAlgorithm::Hqc256, self.secret_key_bytes.clone())
    }

    /// Encapsulate to a recipient's HQC-256 public key.
    pub fn encapsulate<R: CryptoRng + RngCore>(
        _rng: &mut R,
        recipient_public_key: &KemPublicKey,
    ) -> KemResult<(KemCiphertext, SharedSecret)> {
        use pqcrypto_hqc::hqc256;
        use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret as PqSharedSecret};

        if recipient_public_key.algorithm != KemAlgorithm::Hqc256 {
            return Err(KemError::InvalidKey(
                format!("expected HQC-256 key, got {:?}", recipient_public_key.algorithm)
            ));
        }

        let pk = hqc256::PublicKey::from_bytes(&recipient_public_key.bytes)
            .map_err(|e| KemError::InvalidKey(format!("{:?}", e)))?;

        let (ss, ct) = hqc256::encapsulate(&pk);
        let ss_bytes = ss.as_bytes();
        let ss_32 = ss_bytes[..32].to_vec();

        Ok((
            KemCiphertext::new(KemAlgorithm::Hqc256, ct.as_bytes().to_vec()),
            SharedSecret::new(ss_32),
        ))
    }

    /// Decapsulate a ciphertext, recovering the shared secret.
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> KemResult<SharedSecret> {
        use pqcrypto_hqc::hqc256;
        use pqcrypto_traits::kem::{Ciphertext, SecretKey, SharedSecret as PqSharedSecret};

        if ciphertext.algorithm != KemAlgorithm::Hqc256 {
            return Err(KemError::InvalidCiphertext(
                format!("expected HQC-256 ciphertext, got {:?}", ciphertext.algorithm)
            ));
        }

        let sk = hqc256::SecretKey::from_bytes(&self.secret_key_bytes)
            .map_err(|e| KemError::InvalidKey(format!("{:?}", e)))?;
        let ct = hqc256::Ciphertext::from_bytes(&ciphertext.bytes)
            .map_err(|e| KemError::InvalidCiphertext(format!("{:?}", e)))?;

        let ss = hqc256::decapsulate(&ct, &sk);
        let ss_bytes = ss.as_bytes();
        let ss_32 = ss_bytes[..32].to_vec();

        Ok(SharedSecret::new(ss_32))
    }
}

// ── Unavailability stubs (when feature not enabled) ───────────────────────────

/// Returns an error indicating HQC is not available without the `hqc` feature.
#[cfg(not(feature = "hqc"))]
pub fn hqc_not_available() -> KemError {
    KemError::AlgorithmNotAvailable("HQC".into(), "hqc".into())
}
