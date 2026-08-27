//! ML-KEM-768 (NIST FIPS 203, Security Level 3) — Recommended Default
//!
//! Parameter sizes:
//! - Public key:  1184 bytes
//! - Secret key:   64 bytes (seed) — used for serialization
//! - Ciphertext:  1088 bytes
//! - Shared secret: 32 bytes

extern crate alloc;
use alloc::format;

use ml_kem::{
    MlKem768,
    DecapsulationKey, EncapsulationKey,
    kem::{Decapsulate, KeyExport},
    Seed,
};
use rand_core::{CryptoRng, RngCore};

use crate::error::{KemError, KemResult};
use crate::types::{KemAlgorithm, KemCiphertext, KemPublicKey, KemSecretKey, SharedSecret};

/// ML-KEM-768 keypair (NIST FIPS 203, Security Level 3).
///
/// This is the **recommended default** parameter set, providing AES-192-equivalent
/// security against both classical and quantum adversaries.
///
/// # Example
/// ```rust,no_run
/// use rand::rngs::OsRng;
/// use pqc_kem::fips203::MlKem768Keypair;
///
/// let keypair = MlKem768Keypair::generate(&mut OsRng).unwrap();
/// let pk = keypair.public_key();
///
/// let (ciphertext, shared_secret) = MlKem768Keypair::encapsulate(&mut OsRng, &pk).unwrap();
/// let recovered = keypair.decapsulate(&ciphertext).unwrap();
///
/// assert_eq!(shared_secret.bytes, recovered.bytes);
/// ```
pub struct MlKem768Keypair {
    encapsulation_key: EncapsulationKey<MlKem768>,
    decapsulation_key: DecapsulationKey<MlKem768>,
}

impl MlKem768Keypair {
    /// Generate a new ML-KEM-768 keypair using the provided RNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> KemResult<Self> {
        let mut seed_bytes = [0u8; 64];
        rng.fill_bytes(&mut seed_bytes);
        let seed: Seed = seed_bytes.into();
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        let ek = dk.encapsulation_key().clone();
        Ok(Self {
            encapsulation_key: ek,
            decapsulation_key: dk,
        })
    }

    /// Returns the public (encapsulation) key.
    pub fn public_key(&self) -> KemPublicKey {
        KemPublicKey::new(
            KemAlgorithm::MlKem768,
            self.encapsulation_key.to_bytes().as_slice().to_vec(),
        )
    }

    /// Returns the secret (decapsulation) key as a 64-byte seed.
    pub fn secret_key(&self) -> KemSecretKey {
        let seed = self.decapsulation_key.to_seed()
            .map(|s| s.as_slice().to_vec())
            .unwrap_or_default();
        KemSecretKey::new(KemAlgorithm::MlKem768, seed)
    }

    /// Encapsulate to a recipient's ML-KEM-768 public key.
    pub fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R,
        recipient_public_key: &KemPublicKey,
    ) -> KemResult<(KemCiphertext, SharedSecret)> {
        if recipient_public_key.algorithm != KemAlgorithm::MlKem768 {
            return Err(KemError::InvalidKey(
                format!("expected ML-KEM-768 key, got {:?}", recipient_public_key.algorithm)
            ));
        }

        let ek_bytes: &[u8] = &recipient_public_key.bytes;
        let ek_key: ml_kem::kem::Key<EncapsulationKey<MlKem768>> = ek_bytes.try_into()
            .map_err(|_| KemError::InvalidKey(
                format!("ML-KEM-768 public key must be 1184 bytes, got {}", ek_bytes.len())
            ))?;

        let ek = EncapsulationKey::<MlKem768>::new(&ek_key)
            .map_err(|_| KemError::InvalidKey("ML-KEM-768 public key validation failed".into()))?;

        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);
        let m_arr: ml_kem::B32 = m.into();
        let (ct, ss) = ek.encapsulate_deterministic(&m_arr);

        Ok((
            KemCiphertext::new(KemAlgorithm::MlKem768, ct.as_slice().to_vec()),
            SharedSecret::new(ss.as_slice().to_vec()),
        ))
    }

    /// Decapsulate a ciphertext, recovering the shared secret.
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> KemResult<SharedSecret> {
        if ciphertext.algorithm != KemAlgorithm::MlKem768 {
            return Err(KemError::InvalidCiphertext(
                format!("expected ML-KEM-768 ciphertext, got {:?}", ciphertext.algorithm)
            ));
        }

        let ct_bytes: &[u8] = &ciphertext.bytes;
        let ct: ml_kem::Ciphertext<MlKem768> = ct_bytes.try_into()
            .map_err(|_| KemError::InvalidCiphertext(
                format!("ML-KEM-768 ciphertext must be 1088 bytes, got {}", ct_bytes.len())
            ))?;

        let ss = self.decapsulation_key.decapsulate(&ct);

        Ok(SharedSecret::new(ss.as_slice().to_vec()))
    }

    /// Restore a keypair from a 64-byte seed.
    pub fn from_secret_key_bytes(bytes: &[u8]) -> KemResult<Self> {
        let seed_arr: [u8; 64] = bytes.try_into()
            .map_err(|_| KemError::InvalidKey(
                format!("ML-KEM-768 seed must be 64 bytes, got {}", bytes.len())
            ))?;
        let seed: Seed = seed_arr.into();
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        let ek = dk.encapsulation_key().clone();

        Ok(Self {
            encapsulation_key: ek,
            decapsulation_key: dk,
        })
    }
}
