//! ML-KEM-512 (NIST FIPS 203, Security Level 1)
//!
//! Parameter sizes:
//! - Public key:   800 bytes
//! - Secret key:   64 bytes (seed) — used for serialization
//! - Ciphertext:   768 bytes
//! - Shared secret: 32 bytes

extern crate alloc;
use alloc::format;

use ml_kem::{
    MlKem512,
    DecapsulationKey, EncapsulationKey,
    kem::{Decapsulate, KeyExport},
    Seed,
};
use rand_core::{CryptoRng, RngCore};

use crate::error::{KemError, KemResult};
use crate::types::{KemAlgorithm, KemCiphertext, KemPublicKey, KemSecretKey, SharedSecret};

/// ML-KEM-512 keypair (NIST FIPS 203, Security Level 1).
///
/// # Example
/// ```rust,no_run
/// use rand::rngs::OsRng;
/// use pqc_kem::fips203::MlKem512Keypair;
///
/// let keypair = MlKem512Keypair::generate(&mut OsRng).unwrap();
/// let pk = keypair.public_key();
///
/// let (ciphertext, shared_secret) = MlKem512Keypair::encapsulate(&mut OsRng, &pk).unwrap();
/// let recovered = keypair.decapsulate(&ciphertext).unwrap();
///
/// assert_eq!(shared_secret.bytes, recovered.bytes);
/// ```
pub struct MlKem512Keypair {
    encapsulation_key: EncapsulationKey<MlKem512>,
    decapsulation_key: DecapsulationKey<MlKem512>,
}

impl MlKem512Keypair {
    /// Generate a new ML-KEM-512 keypair using the provided RNG.
    ///
    /// We generate a 64-byte seed with the caller's RNG, then derive the keypair
    /// deterministically. This avoids a `rand_core` version conflict between our
    /// public API (`rand_core 0.6`) and ml-kem's internal API (`rand_core 0.10`).
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> KemResult<Self> {
        let mut seed_bytes = [0u8; 64];
        rng.fill_bytes(&mut seed_bytes);
        let seed: Seed = seed_bytes.into();
        let dk = DecapsulationKey::<MlKem512>::from_seed(seed);
        let ek = dk.encapsulation_key().clone();
        Ok(Self {
            encapsulation_key: ek,
            decapsulation_key: dk,
        })
    }

    /// Returns the public (encapsulation) key.
    pub fn public_key(&self) -> KemPublicKey {
        KemPublicKey::new(
            KemAlgorithm::MlKem512,
            self.encapsulation_key.to_bytes().as_slice().to_vec(),
        )
    }

    /// Returns the secret (decapsulation) key as a 64-byte seed.
    ///
    /// **Warning:** Handle with care. The returned `KemSecretKey` is zeroized on drop.
    pub fn secret_key(&self) -> KemSecretKey {
        let seed = self.decapsulation_key.to_seed()
            .map(|s| s.as_slice().to_vec())
            .unwrap_or_default();
        KemSecretKey::new(KemAlgorithm::MlKem512, seed)
    }

    /// Encapsulate to a recipient's ML-KEM-512 public key.
    ///
    /// Returns `(ciphertext, shared_secret)`.
    pub fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R,
        recipient_public_key: &KemPublicKey,
    ) -> KemResult<(KemCiphertext, SharedSecret)> {
        if recipient_public_key.algorithm != KemAlgorithm::MlKem512 {
            return Err(KemError::InvalidKey(
                format!("expected ML-KEM-512 key, got {:?}", recipient_public_key.algorithm)
            ));
        }

        let ek_bytes: &[u8] = &recipient_public_key.bytes;
        let ek_key: ml_kem::kem::Key<EncapsulationKey<MlKem512>> = ek_bytes.try_into()
            .map_err(|_| KemError::InvalidKey(
                format!("ML-KEM-512 public key must be 800 bytes, got {}", ek_bytes.len())
            ))?;

        let ek = EncapsulationKey::<MlKem512>::new(&ek_key)
            .map_err(|_| KemError::InvalidKey("ML-KEM-512 public key validation failed".into()))?;

        // Generate randomness with our RNG, then encapsulate deterministically.
        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);
        let m_arr: ml_kem::B32 = m.into();
        let (ct, ss) = ek.encapsulate_deterministic(&m_arr);

        Ok((
            KemCiphertext::new(KemAlgorithm::MlKem512, ct.as_slice().to_vec()),
            SharedSecret::new(ss.as_slice().to_vec()),
        ))
    }

    /// Decapsulate a ciphertext, recovering the shared secret.
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> KemResult<SharedSecret> {
        if ciphertext.algorithm != KemAlgorithm::MlKem512 {
            return Err(KemError::InvalidCiphertext(
                format!("expected ML-KEM-512 ciphertext, got {:?}", ciphertext.algorithm)
            ));
        }

        let ct_bytes: &[u8] = &ciphertext.bytes;
        let ct: ml_kem::Ciphertext<MlKem512> = ct_bytes.try_into()
            .map_err(|_| KemError::InvalidCiphertext(
                format!("ML-KEM-512 ciphertext must be 768 bytes, got {}", ct_bytes.len())
            ))?;

        let ss = self.decapsulation_key.decapsulate(&ct);

        Ok(SharedSecret::new(ss.as_slice().to_vec()))
    }

    /// Restore a keypair from a 64-byte seed.
    ///
    /// The seed must be exactly 64 bytes (ML-KEM-512 seed size).
    pub fn from_secret_key_bytes(bytes: &[u8]) -> KemResult<Self> {
        let seed_arr: [u8; 64] = bytes.try_into()
            .map_err(|_| KemError::InvalidKey(
                format!("ML-KEM-512 seed must be 64 bytes, got {}", bytes.len())
            ))?;
        let seed: Seed = seed_arr.into();
        let dk = DecapsulationKey::<MlKem512>::from_seed(seed);
        let ek = dk.encapsulation_key().clone();

        Ok(Self {
            encapsulation_key: ek,
            decapsulation_key: dk,
        })
    }
}
