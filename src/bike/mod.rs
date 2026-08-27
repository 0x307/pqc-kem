//! BIKE (Bit Flipping Key Encapsulation) — NIST Round 4 Alternate Candidate
//!
//! **⚠️ NOT YET IMPLEMENTED** — The `bike` feature is currently a stub.
//! Enabling it will produce a compile-time error. BIKE support will be added
//! in a future release.
//!
//! BIKE is a code-based KEM that was a Round 4 alternate candidate in the NIST
//! post-quantum standardization process. It offers smaller key sizes than
//! Classic McEliece at the cost of more complex decapsulation.
//!
//! # Feature Gate
//! This module requires the `bike` feature flag:
//! ```toml
//! pqc-kem = { version = "0.1", features = ["bike"] }
//! ```
//!
//! # WASM Compatibility Note
//! BIKE uses C FFI via `pqcrypto-bike`. It is NOT compatible with
//! `wasm32-unknown-unknown`. Use ML-KEM for WASM targets.

#[cfg(feature = "bike")]
compile_error!(
    "The `bike` feature is not yet implemented. \
     The vendored pqcrypto-bike crate is a stub that panics at runtime. \
     Remove `--features bike` from your build command. \
     BIKE support will be added in a future release."
);

extern crate alloc;


use crate::error::KemError;

/// BIKE keypair (NIST Round 4 alternate candidate).
///
/// Uses BIKE Level 1 (128-bit security) by default.
/// For higher security levels, use the `bike_l3` or `bike_l5` variants.
///
/// `#[cfg(any())]`, not `#[cfg(feature = "bike")]`, is deliberate: this code
/// never compiles, regardless of the `bike` feature. The `compile_error!`
/// above already halts the build the instant `bike` is enabled, but a
/// `compile_error!` is just an item -- it doesn't exclude the rest of the
/// module from being type-checked in the same pass, so without this guard
/// enabling `bike` surfaces the real (broken) errors below alongside the
/// intended one, burying the single clear message this feature gate exists
/// to give. Kept only as a shape reference for a future real implementation.
#[cfg(any())]
pub struct BikeKeypair {
    public_key_bytes: Vec<u8>,
    secret_key_bytes: Vec<u8>,
}

#[cfg(any())]
impl BikeKeypair {
    /// Generate a new BIKE keypair.
    pub fn generate<R: CryptoRng + RngCore>(_rng: &mut R) -> KemResult<Self> {
        use pqcrypto_bike::bikel1;
        use pqcrypto_traits::kem::{PublicKey, SecretKey};

        let (pk, sk) = bikel1::keypair();
        Ok(Self {
            public_key_bytes: pk.as_bytes().to_vec(),
            secret_key_bytes: sk.as_bytes().to_vec(),
        })
    }

    /// Returns the public key.
    pub fn public_key(&self) -> KemPublicKey {
        KemPublicKey::new(KemAlgorithm::Bike, self.public_key_bytes.clone())
    }

    /// Returns the secret key.
    pub fn secret_key(&self) -> KemSecretKey {
        KemSecretKey::new(KemAlgorithm::Bike, self.secret_key_bytes.clone())
    }

    /// Encapsulate to a recipient's BIKE public key.
    pub fn encapsulate<R: CryptoRng + RngCore>(
        _rng: &mut R,
        recipient_public_key: &KemPublicKey,
    ) -> KemResult<(KemCiphertext, SharedSecret)> {
        use pqcrypto_bike::bikel1;
        use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret as PqSharedSecret};

        if recipient_public_key.algorithm != KemAlgorithm::Bike {
            return Err(KemError::InvalidKey(
                format!("expected BIKE key, got {:?}", recipient_public_key.algorithm)
            ));
        }

        let pk = bikel1::PublicKey::from_bytes(&recipient_public_key.bytes)
            .map_err(|e| KemError::InvalidKey(format!("{:?}", e)))?;

        let (ss, ct) = bikel1::encapsulate(&pk);
        let ss_bytes = ss.as_bytes().to_vec();

        Ok((
            KemCiphertext::new(KemAlgorithm::Bike, ct.as_bytes().to_vec()),
            SharedSecret::new(ss_bytes),
        ))
    }

    /// Decapsulate a ciphertext, recovering the shared secret.
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> KemResult<SharedSecret> {
        use pqcrypto_bike::bikel1;
        use pqcrypto_traits::kem::{Ciphertext, SecretKey, SharedSecret as PqSharedSecret};

        if ciphertext.algorithm != KemAlgorithm::Bike {
            return Err(KemError::InvalidCiphertext(
                format!("expected BIKE ciphertext, got {:?}", ciphertext.algorithm)
            ));
        }

        let sk = bikel1::SecretKey::from_bytes(&self.secret_key_bytes)
            .map_err(|e| KemError::InvalidKey(format!("{:?}", e)))?;
        let ct = bikel1::Ciphertext::from_bytes(&ciphertext.bytes)
            .map_err(|e| KemError::InvalidCiphertext(format!("{:?}", e)))?;

        let ss = bikel1::decapsulate(&ct, &sk);
        Ok(SharedSecret::new(ss.as_bytes().to_vec()))
    }
}

/// Returns an error indicating BIKE is not available without the `bike` feature.
#[cfg(not(feature = "bike"))]
pub fn bike_not_available() -> KemError {
    KemError::AlgorithmNotAvailable("BIKE".into(), "bike".into())
}
