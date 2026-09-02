//! HQC (Hamming Quasi-Cyclic) — NIST 2025 Standard
//!
//! HQC was selected as a NIST standard in 2025 as a code-based KEM alternative
//! to ML-KEM, providing diversity in the post-quantum algorithm portfolio.
//!
//! # Parameter Sets
//! - [`Hqc128Keypair`] — Security Level 1 (AES-128 equivalent)
//! - [`Hqc192Keypair`] — Security Level 3 (AES-192 equivalent)
//! - [`Hqc256Keypair`] — Security Level 5 (AES-256 equivalent)
//!
//! # Feature Gate
//! This module requires the `hqc` feature flag:
//! ```toml
//! pqc-kem = { version = "0.2", features = ["hqc"] }
//! ```
//!
//! # WASM Compatibility Note
//! HQC uses C FFI via `liboqs` (the `oqs` crate). It is NOT compatible with
//! `wasm32-unknown-unknown`. For WASM targets, use ML-KEM instead.
//! HQC can be used in native (x86_64, aarch64) environments.
//!
//! # Dependency: `liboqs` (`oqs` crate), not `pqcrypto-hqc`
//!
//! This module was originally a `compile_error!` stub whose comment claimed
//! `pqcrypto-hqc 0.1`'s published API didn't expose the `hqc128`/`192`/`256`
//! modules this crate needed (82 compile errors on the real build). That was
//! re-verified live rather than trusted: the current published `pqcrypto-hqc`
//! (0.2.x) API *does* match what this module needs almost exactly. However,
//! live testing surfaced a more serious, independent defect: `pqcrypto-hqc`
//! 0.2.2's `decapsulate()` wraps the underlying PQClean C reference
//! implementation's informational "decapsulation check failed" return code —
//! which is the FO-transform's normal, *expected* implicit-rejection outcome
//! for **any** ciphertext/secret-key mismatch, not a rare adversarial edge
//! case — in a hard `assert_eq!(.., 0)`. That panics (and, under a
//! `panic = "abort"` profile, aborts the whole process) instead of surfacing
//! an error, for something as ordinary as decapsulating a ciphertext with a
//! secret key it wasn't encapsulated to. That is unacceptable for a KEM whose
//! entire purpose is decapsulating counterparty-supplied ciphertexts.
//!
//! `liboqs` (via the `oqs` crate) wraps the identical underlying C return
//! code as a proper `Result` instead. This was verified live: neither a
//! bit-flipped ciphertext nor an honestly mismatched secret key panics via
//! `oqs`; both cleanly return `Err`. Byte sizes are identical between the two
//! bindings (both ultimately wrap the same NIST HQC parameter sets), so this
//! is a drop-in-equivalent, strictly safer choice — not a design compromise.
//! See `CHANGELOG.md` and `README.md` for the full writeup.
//!
//! Building the `hqc` feature requires a C toolchain, `cmake`, and
//! `libclang` (for `bindgen`) to compile `liboqs`'s vendored HQC sources —
//! verified to **not** additionally require OpenSSL when only the `hqc`
//! feature (and not `oqs`'s `kems`/`sigs`/`openssl` defaults) is enabled.
//!
//! # Wire Sizes — Corrected From the Original Stub
//!
//! The dead shape-reference code this module replaced assumed HQC-128's
//! ciphertext was 4481 bytes and HQC-256's was 14469 bytes. Live testing
//! against **both** `pqcrypto-hqc` 0.2.2 and `liboqs` 0.13.0 (independent
//! implementations of the same NIST submission) agree the real sizes are
//! 4433 and 14421 bytes respectively — HQC-192's 8978-byte ciphertext was
//! already correct. This is consistent with the HQC round-4/2023 parameter
//! revision changing the error-correcting code parameters for the 128- and
//! 256-bit levels; [`crate::types::KemAlgorithm::ciphertext_size`] has been
//! corrected to match. Public key sizes (2249/4522/7245 bytes) were already
//! correct and are unchanged.

#[cfg(feature = "hqc")]
extern crate alloc;

#[cfg(feature = "hqc")]
use alloc::{format, vec::Vec};

#[cfg(feature = "hqc")]
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "hqc")]
use oqs::kem::{Algorithm as OqsAlgorithm, Kem as OqsKem};

use crate::error::KemError;

#[cfg(feature = "hqc")]
use crate::error::KemResult;
#[cfg(feature = "hqc")]
use crate::types::{KemAlgorithm, KemCiphertext, KemPublicKey, KemSecretKey, SharedSecret};

/// HQC's native shared secret is 64 bytes (a SHAKE256 hash output, per the
/// HQC KEM construction — not raw algebraic vector material), which is
/// truncated to this crate's uniform 32-byte [`SharedSecret`] size. Since the
/// 64-byte value is already a hash/KDF output, taking its first 32 bytes is
/// a standard, cryptographically sound truncation (equivalent to using a
/// shorter-output hash), not a weakening of independently-structured secret
/// material.
#[cfg(feature = "hqc")]
const TRUNCATED_SHARED_SECRET_LEN: usize = 32;

#[cfg(feature = "hqc")]
fn truncate_shared_secret(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.truncate(TRUNCATED_SHARED_SECRET_LEN);
    bytes
}

// ── HQC-128 ───────────────────────────────────────────────────────────────────

/// HQC-128 keypair (NIST 2025, Security Level 1).
///
/// Public key: 2249 bytes | Ciphertext: 4433 bytes | Shared secret: 64 bytes (truncated to 32)
///
/// # Example
/// ```rust,no_run
/// use rand::rngs::OsRng;
/// use pqc_kem::hqc::Hqc128Keypair;
///
/// let keypair = Hqc128Keypair::generate(&mut OsRng).unwrap();
/// let pk = keypair.public_key();
///
/// let (ciphertext, shared_secret) = Hqc128Keypair::encapsulate(&mut OsRng, &pk).unwrap();
/// let recovered = keypair.decapsulate(&ciphertext).unwrap();
///
/// assert_eq!(shared_secret.bytes, recovered.bytes);
/// ```
#[cfg(feature = "hqc")]
pub struct Hqc128Keypair {
    public_key_bytes: Vec<u8>,
    secret_key_bytes: Vec<u8>,
}

#[cfg(feature = "hqc")]
impl Hqc128Keypair {
    /// Generate a new HQC-128 keypair.
    ///
    /// Note: The RNG parameter is accepted for API consistency but HQC key
    /// generation uses `liboqs`'s own internal entropy source, not the
    /// caller's RNG.
    pub fn generate<R: CryptoRng + RngCore>(_rng: &mut R) -> KemResult<Self> {
        oqs::init();
        let kem = OqsKem::new(OqsAlgorithm::Hqc128)
            .map_err(|e| KemError::KeyGeneration(format!("HQC-128 KEM init failed: {e}")))?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|e| KemError::KeyGeneration(format!("HQC-128 keygen failed: {e}")))?;
        Ok(Self {
            public_key_bytes: pk.into_vec(),
            secret_key_bytes: sk.into_vec(),
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
        if recipient_public_key.algorithm != KemAlgorithm::Hqc128 {
            return Err(KemError::InvalidKey(format!(
                "expected HQC-128 key, got {:?}",
                recipient_public_key.algorithm
            )));
        }

        oqs::init();
        let kem = OqsKem::new(OqsAlgorithm::Hqc128)
            .map_err(|e| KemError::Encapsulation(format!("HQC-128 KEM init failed: {e}")))?;

        let pk_ref = kem.public_key_from_bytes(&recipient_public_key.bytes).ok_or_else(|| {
            KemError::InvalidKey(format!(
                "HQC-128 public key must be {} bytes, got {}",
                kem.length_public_key(),
                recipient_public_key.bytes.len()
            ))
        })?;

        let (ct, ss) = kem
            .encapsulate(pk_ref)
            .map_err(|e| KemError::Encapsulation(format!("HQC-128 encapsulate failed: {e}")))?;

        Ok((
            KemCiphertext::new(KemAlgorithm::Hqc128, ct.into_vec()),
            SharedSecret::new(truncate_shared_secret(ss.into_vec())),
        ))
    }

    /// Decapsulate a ciphertext, recovering the shared secret.
    ///
    /// Returns `Err(KemError::Decapsulation(..))` — never panics — if the
    /// ciphertext doesn't correspond to this keypair's secret key (e.g. a
    /// different sender's ciphertext, or a tampered/malformed one).
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> KemResult<SharedSecret> {
        if ciphertext.algorithm != KemAlgorithm::Hqc128 {
            return Err(KemError::InvalidCiphertext(format!(
                "expected HQC-128 ciphertext, got {:?}",
                ciphertext.algorithm
            )));
        }

        oqs::init();
        let kem = OqsKem::new(OqsAlgorithm::Hqc128)
            .map_err(|e| KemError::Decapsulation(format!("HQC-128 KEM init failed: {e}")))?;

        let sk_ref = kem.secret_key_from_bytes(&self.secret_key_bytes).ok_or_else(|| {
            KemError::InvalidKey("HQC-128 secret key has an unexpected length".into())
        })?;
        let ct_ref = kem.ciphertext_from_bytes(&ciphertext.bytes).ok_or_else(|| {
            KemError::InvalidCiphertext(format!(
                "HQC-128 ciphertext must be {} bytes, got {}",
                kem.length_ciphertext(),
                ciphertext.bytes.len()
            ))
        })?;

        let ss = kem
            .decapsulate(sk_ref, ct_ref)
            .map_err(|e| KemError::Decapsulation(format!("HQC-128 decapsulate failed: {e}")))?;

        Ok(SharedSecret::new(truncate_shared_secret(ss.into_vec())))
    }
}

// ── HQC-192 ───────────────────────────────────────────────────────────────────

/// HQC-192 keypair (NIST 2025, Security Level 3).
///
/// Public key: 4522 bytes | Ciphertext: 8978 bytes | Shared secret: 64 bytes (truncated to 32)
#[cfg(feature = "hqc")]
pub struct Hqc192Keypair {
    public_key_bytes: Vec<u8>,
    secret_key_bytes: Vec<u8>,
}

#[cfg(feature = "hqc")]
impl Hqc192Keypair {
    /// Generate a new HQC-192 keypair.
    pub fn generate<R: CryptoRng + RngCore>(_rng: &mut R) -> KemResult<Self> {
        oqs::init();
        let kem = OqsKem::new(OqsAlgorithm::Hqc192)
            .map_err(|e| KemError::KeyGeneration(format!("HQC-192 KEM init failed: {e}")))?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|e| KemError::KeyGeneration(format!("HQC-192 keygen failed: {e}")))?;
        Ok(Self {
            public_key_bytes: pk.into_vec(),
            secret_key_bytes: sk.into_vec(),
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
        if recipient_public_key.algorithm != KemAlgorithm::Hqc192 {
            return Err(KemError::InvalidKey(format!(
                "expected HQC-192 key, got {:?}",
                recipient_public_key.algorithm
            )));
        }

        oqs::init();
        let kem = OqsKem::new(OqsAlgorithm::Hqc192)
            .map_err(|e| KemError::Encapsulation(format!("HQC-192 KEM init failed: {e}")))?;

        let pk_ref = kem.public_key_from_bytes(&recipient_public_key.bytes).ok_or_else(|| {
            KemError::InvalidKey(format!(
                "HQC-192 public key must be {} bytes, got {}",
                kem.length_public_key(),
                recipient_public_key.bytes.len()
            ))
        })?;

        let (ct, ss) = kem
            .encapsulate(pk_ref)
            .map_err(|e| KemError::Encapsulation(format!("HQC-192 encapsulate failed: {e}")))?;

        Ok((
            KemCiphertext::new(KemAlgorithm::Hqc192, ct.into_vec()),
            SharedSecret::new(truncate_shared_secret(ss.into_vec())),
        ))
    }

    /// Decapsulate a ciphertext, recovering the shared secret.
    ///
    /// Returns `Err(KemError::Decapsulation(..))` — never panics — on a
    /// ciphertext/secret-key mismatch.
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> KemResult<SharedSecret> {
        if ciphertext.algorithm != KemAlgorithm::Hqc192 {
            return Err(KemError::InvalidCiphertext(format!(
                "expected HQC-192 ciphertext, got {:?}",
                ciphertext.algorithm
            )));
        }

        oqs::init();
        let kem = OqsKem::new(OqsAlgorithm::Hqc192)
            .map_err(|e| KemError::Decapsulation(format!("HQC-192 KEM init failed: {e}")))?;

        let sk_ref = kem.secret_key_from_bytes(&self.secret_key_bytes).ok_or_else(|| {
            KemError::InvalidKey("HQC-192 secret key has an unexpected length".into())
        })?;
        let ct_ref = kem.ciphertext_from_bytes(&ciphertext.bytes).ok_or_else(|| {
            KemError::InvalidCiphertext(format!(
                "HQC-192 ciphertext must be {} bytes, got {}",
                kem.length_ciphertext(),
                ciphertext.bytes.len()
            ))
        })?;

        let ss = kem
            .decapsulate(sk_ref, ct_ref)
            .map_err(|e| KemError::Decapsulation(format!("HQC-192 decapsulate failed: {e}")))?;

        Ok(SharedSecret::new(truncate_shared_secret(ss.into_vec())))
    }
}

// ── HQC-256 ───────────────────────────────────────────────────────────────────

/// HQC-256 keypair (NIST 2025, Security Level 5).
///
/// Public key: 7245 bytes | Ciphertext: 14421 bytes | Shared secret: 64 bytes (truncated to 32)
#[cfg(feature = "hqc")]
pub struct Hqc256Keypair {
    public_key_bytes: Vec<u8>,
    secret_key_bytes: Vec<u8>,
}

#[cfg(feature = "hqc")]
impl Hqc256Keypair {
    /// Generate a new HQC-256 keypair.
    pub fn generate<R: CryptoRng + RngCore>(_rng: &mut R) -> KemResult<Self> {
        oqs::init();
        let kem = OqsKem::new(OqsAlgorithm::Hqc256)
            .map_err(|e| KemError::KeyGeneration(format!("HQC-256 KEM init failed: {e}")))?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|e| KemError::KeyGeneration(format!("HQC-256 keygen failed: {e}")))?;
        Ok(Self {
            public_key_bytes: pk.into_vec(),
            secret_key_bytes: sk.into_vec(),
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
        if recipient_public_key.algorithm != KemAlgorithm::Hqc256 {
            return Err(KemError::InvalidKey(format!(
                "expected HQC-256 key, got {:?}",
                recipient_public_key.algorithm
            )));
        }

        oqs::init();
        let kem = OqsKem::new(OqsAlgorithm::Hqc256)
            .map_err(|e| KemError::Encapsulation(format!("HQC-256 KEM init failed: {e}")))?;

        let pk_ref = kem.public_key_from_bytes(&recipient_public_key.bytes).ok_or_else(|| {
            KemError::InvalidKey(format!(
                "HQC-256 public key must be {} bytes, got {}",
                kem.length_public_key(),
                recipient_public_key.bytes.len()
            ))
        })?;

        let (ct, ss) = kem
            .encapsulate(pk_ref)
            .map_err(|e| KemError::Encapsulation(format!("HQC-256 encapsulate failed: {e}")))?;

        Ok((
            KemCiphertext::new(KemAlgorithm::Hqc256, ct.into_vec()),
            SharedSecret::new(truncate_shared_secret(ss.into_vec())),
        ))
    }

    /// Decapsulate a ciphertext, recovering the shared secret.
    ///
    /// Returns `Err(KemError::Decapsulation(..))` — never panics — on a
    /// ciphertext/secret-key mismatch.
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> KemResult<SharedSecret> {
        if ciphertext.algorithm != KemAlgorithm::Hqc256 {
            return Err(KemError::InvalidCiphertext(format!(
                "expected HQC-256 ciphertext, got {:?}",
                ciphertext.algorithm
            )));
        }

        oqs::init();
        let kem = OqsKem::new(OqsAlgorithm::Hqc256)
            .map_err(|e| KemError::Decapsulation(format!("HQC-256 KEM init failed: {e}")))?;

        let sk_ref = kem.secret_key_from_bytes(&self.secret_key_bytes).ok_or_else(|| {
            KemError::InvalidKey("HQC-256 secret key has an unexpected length".into())
        })?;
        let ct_ref = kem.ciphertext_from_bytes(&ciphertext.bytes).ok_or_else(|| {
            KemError::InvalidCiphertext(format!(
                "HQC-256 ciphertext must be {} bytes, got {}",
                kem.length_ciphertext(),
                ciphertext.bytes.len()
            ))
        })?;

        let ss = kem
            .decapsulate(sk_ref, ct_ref)
            .map_err(|e| KemError::Decapsulation(format!("HQC-256 decapsulate failed: {e}")))?;

        Ok(SharedSecret::new(truncate_shared_secret(ss.into_vec())))
    }
}

// ── Unavailability stub (when feature not enabled) ────────────────────────────

/// Returns an error indicating HQC is not available without the `hqc` feature.
#[cfg(not(feature = "hqc"))]
pub fn hqc_not_available() -> KemError {
    KemError::AlgorithmNotAvailable("HQC".into(), "hqc".into())
}
