//! Hybrid KEM: X25519 + ML-KEM-768 (FIPS 203)
//!
//! This is this crate's **primary hybrid KEM construction**.
//! Breaking it requires breaking BOTH X25519 AND ML-KEM-768 simultaneously,
//! providing security against both classical and quantum adversaries.
//!
//! # Construction
//! ```text
//! x25519_ss  = X25519(ephemeral_private, recipient_x25519_public)
//! mlkem_ss   = ML-KEM-768.Decaps(ciphertext, recipient_mlkem_secret)
//! combined   = x25519_ss ‖ mlkem_ss          (64 bytes)
//! shared_key = HKDF-SHA256(combined, info="pqc-kem-hybrid-v1", len=32)
//! ```

extern crate alloc;
use alloc::{format, vec::Vec};

use hkdf::Hkdf;
use ml_kem::{
    MlKem768,
    DecapsulationKey, EncapsulationKey,
    kem::{Decapsulate, KeyExport},
    Seed,
};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

use crate::error::{KemError, KemResult};
use crate::types::{HybridKemCiphertext, HybridPublicKey, SharedSecret};

/// HKDF info string for the hybrid KEM construction.
const HYBRID_KEM_INFO: &[u8] = b"pqc-kem-hybrid-v1";

/// Hybrid X25519 + ML-KEM-768 keypair.
///
/// This is this crate's recommended KEM construction for all operations.
/// The hybrid construction ensures that even if one component is broken,
/// the overall security is maintained.
pub struct HybridKemKeypair {
    /// X25519 static secret key (for decapsulation).
    x25519_secret: StaticSecret,
    /// X25519 public key.
    x25519_public: X25519PublicKey,
    /// ML-KEM-768 encapsulation (public) key.
    mlkem_ek: EncapsulationKey<MlKem768>,
    /// ML-KEM-768 decapsulation (secret) key.
    mlkem_dk: DecapsulationKey<MlKem768>,
}

impl HybridKemKeypair {
    /// Generate a new hybrid keypair using the provided RNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> KemResult<Self> {
        // Generate X25519 keypair
        let x25519_secret = StaticSecret::random_from_rng(&mut *rng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Generate ML-KEM-768 keypair via seed
        let mut seed_bytes = [0u8; 64];
        rng.fill_bytes(&mut seed_bytes);
        let seed: Seed = seed_bytes.into();
        let mlkem_dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        let mlkem_ek = mlkem_dk.encapsulation_key().clone();

        Ok(Self {
            x25519_secret,
            x25519_public,
            mlkem_ek,
            mlkem_dk,
        })
    }

    /// Returns the hybrid public key (for distribution and DID Documents).
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey::new(
            self.x25519_public.as_bytes(),
            self.mlkem_ek.to_bytes().as_slice(),
        )
    }

    /// Returns the X25519 public key bytes (32 bytes).
    pub fn x25519_public_bytes(&self) -> [u8; 32] {
        *self.x25519_public.as_bytes()
    }

    /// Returns the ML-KEM-768 public key bytes (1184 bytes).
    pub fn mlkem_public_bytes(&self) -> Vec<u8> {
        self.mlkem_ek.to_bytes().as_slice().to_vec()
    }

    /// Encapsulate to a recipient's hybrid public key.
    ///
    /// Returns `(ciphertext, shared_secret)` where:
    /// - `ciphertext` contains the X25519 ephemeral public key and ML-KEM-768 ciphertext
    /// - `shared_secret` is 32 bytes derived via HKDF-SHA256
    pub fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R,
        recipient_x25519_pub: &[u8; 32],
        recipient_mlkem_pub: &[u8],
    ) -> KemResult<(HybridKemCiphertext, SharedSecret)> {
        // ── Step 1: X25519 ephemeral key exchange ─────────────────────────────
        let ephemeral_secret = EphemeralSecret::random_from_rng(&mut *rng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

        let recipient_x25519 = X25519PublicKey::from(*recipient_x25519_pub);
        let x25519_ss = ephemeral_secret.diffie_hellman(&recipient_x25519);

        // ── Step 2: ML-KEM-768 encapsulation ─────────────────────────────────
        let ek_key: ml_kem::kem::Key<EncapsulationKey<MlKem768>> = recipient_mlkem_pub.try_into()
            .map_err(|_| KemError::InvalidKey(
                format!("ML-KEM-768 public key must be 1184 bytes, got {}", recipient_mlkem_pub.len())
            ))?;

        let mlkem_ek = EncapsulationKey::<MlKem768>::new(&ek_key)
            .map_err(|_| KemError::InvalidKey("ML-KEM-768 public key validation failed".into()))?;

        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);
        let m_arr: ml_kem::B32 = m.into();
        let (mlkem_ct, mlkem_ss) = mlkem_ek.encapsulate_deterministic(&m_arr);

        // ── Step 3: Combine shared secrets via HKDF-SHA256 ───────────────────
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(x25519_ss.as_bytes());
        combined[32..].copy_from_slice(mlkem_ss.as_slice());

        let hkdf = Hkdf::<Sha256>::new(None, &combined);
        let mut shared_key = [0u8; 32];
        hkdf.expand(HYBRID_KEM_INFO, &mut shared_key)
            .map_err(|e| KemError::KeyDerivation(format!("{:?}", e)))?;

        // ── Step 4: Build wire types ──────────────────────────────────────────
        let ciphertext = HybridKemCiphertext::new(
            ephemeral_public.as_bytes(),
            mlkem_ct.as_slice(),
        );

        Ok((ciphertext, SharedSecret::new(shared_key.to_vec())))
    }

    /// Encapsulate using a [`HybridPublicKey`] wire type directly.
    ///
    /// Convenience wrapper around [`Self::encapsulate`].
    pub fn encapsulate_to<R: CryptoRng + RngCore>(
        rng: &mut R,
        recipient_public_key: &HybridPublicKey,
    ) -> KemResult<(HybridKemCiphertext, SharedSecret)> {
        let x25519_bytes = recipient_public_key.x25519_bytes()?;
        let x25519_arr: &[u8; 32] = x25519_bytes.as_slice().try_into()
            .map_err(|_| KemError::InvalidKey(
                format!("X25519 public key must be 32 bytes, got {}", x25519_bytes.len())
            ))?;

        let mlkem_bytes = recipient_public_key.mlkem_bytes()?;

        Self::encapsulate(rng, x25519_arr, &mlkem_bytes)
    }

    /// Decapsulate a hybrid ciphertext, recovering the shared secret.
    pub fn decapsulate(&self, ciphertext: &HybridKemCiphertext) -> KemResult<SharedSecret> {
        // ── Step 1: Decode wire types ─────────────────────────────────────────
        let x25519_eph_bytes = ciphertext.x25519_bytes()?;
        let x25519_eph_arr: &[u8; 32] = x25519_eph_bytes.as_slice().try_into()
            .map_err(|_| KemError::InvalidCiphertext(
                format!("X25519 ephemeral key must be 32 bytes, got {}", x25519_eph_bytes.len())
            ))?;

        let mlkem_ct_bytes = ciphertext.mlkem_bytes()?;

        // ── Step 2: X25519 static DH ──────────────────────────────────────────
        let ephemeral_public = X25519PublicKey::from(*x25519_eph_arr);
        let x25519_ss = self.x25519_secret.diffie_hellman(&ephemeral_public);

        // ── Step 3: ML-KEM-768 decapsulation ─────────────────────────────────
        let ct: ml_kem::Ciphertext<MlKem768> = mlkem_ct_bytes.as_slice().try_into()
            .map_err(|_| KemError::InvalidCiphertext(
                format!("ML-KEM-768 ciphertext must be 1088 bytes, got {}", mlkem_ct_bytes.len())
            ))?;

        let mlkem_ss = self.mlkem_dk.decapsulate(&ct);

        // ── Step 4: Combine shared secrets via HKDF-SHA256 ───────────────────
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(x25519_ss.as_bytes());
        combined[32..].copy_from_slice(mlkem_ss.as_slice());

        let hkdf = Hkdf::<Sha256>::new(None, &combined);
        let mut shared_key = [0u8; 32];
        hkdf.expand(HYBRID_KEM_INFO, &mut shared_key)
            .map_err(|e| KemError::KeyDerivation(format!("{:?}", e)))?;

        Ok(SharedSecret::new(shared_key.to_vec()))
    }

    /// Restore a hybrid keypair from raw component bytes.
    ///
    /// - `x25519_secret_bytes`: 32 bytes (X25519 static secret)
    /// - `mlkem_secret_bytes`: 64 bytes (ML-KEM-768 seed)
    pub fn from_secret_key_bytes(
        x25519_secret_bytes: &[u8],
        mlkem_secret_bytes: &[u8],
    ) -> KemResult<Self> {
        // Restore X25519 secret
        let x25519_arr: &[u8; 32] = x25519_secret_bytes.try_into()
            .map_err(|_| KemError::InvalidKey(
                format!("X25519 secret key must be 32 bytes, got {}", x25519_secret_bytes.len())
            ))?;
        let x25519_secret = StaticSecret::from(*x25519_arr);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Restore ML-KEM-768 decapsulation key from seed
        let seed_arr: [u8; 64] = mlkem_secret_bytes.try_into()
            .map_err(|_| KemError::InvalidKey(
                format!("ML-KEM-768 seed must be 64 bytes, got {}", mlkem_secret_bytes.len())
            ))?;
        let seed: Seed = seed_arr.into();
        let mlkem_dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        let mlkem_ek = mlkem_dk.encapsulation_key().clone();

        Ok(Self {
            x25519_secret,
            x25519_public,
            mlkem_ek,
            mlkem_dk,
        })
    }

    /// Returns the X25519 secret key bytes (32 bytes).
    ///
    /// **Warning:** Handle with care — these are raw secret key bytes.
    pub fn x25519_secret_bytes(&self) -> [u8; 32] {
        self.x25519_secret.to_bytes()
    }

    /// Returns the ML-KEM-768 seed bytes (64 bytes).
    ///
    /// **Warning:** Handle with care — these are raw secret key bytes.
    pub fn mlkem_secret_bytes(&self) -> Vec<u8> {
        self.mlkem_dk.to_seed()
            .map(|s| s.as_slice().to_vec())
            .unwrap_or_default()
    }
}
