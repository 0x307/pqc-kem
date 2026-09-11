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
///
/// # Secret handling
/// `decapsulation_key` is an `ml_kem::DecapsulationKey`, whose `Drop` impl
/// (enabled by this crate's `ml-kem/zeroize` feature) zeroizes the 64-byte
/// seed (`d ‖ z`) and the expanded decryption key when this keypair is
/// dropped — no explicit `Drop` needs to be written here for that to
/// happen. `encapsulation_key` holds only public key material and is
/// never zeroized (there is no secret to protect there). This type
/// implements [`zeroize::ZeroizeOnDrop`] (see the compile-time check in
/// `tests/zeroize_tests.rs`).
pub struct MlKem512Keypair {
    encapsulation_key: EncapsulationKey<MlKem512>,
    decapsulation_key: DecapsulationKey<MlKem512>,
}

impl zeroize::ZeroizeOnDrop for MlKem512Keypair {}

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
    ///
    /// # Panics
    /// Delegates to [`Self::try_secret_key`] and unwraps it via `.expect(..)`.
    /// This cannot actually panic for any key produced by this crate's
    /// public constructors ([`Self::generate`], [`Self::from_secret_key_bytes`]) —
    /// both build the underlying key via `ml_kem::DecapsulationKey::from_seed`,
    /// which always retains a recoverable seed (verified against the
    /// `ml-kem` 0.3.2 source: `to_seed()` only returns `None` for keys built
    /// via the deprecated, never-called-here `from_expanded` path). Kept for
    /// 0.2.x API compatibility; new code should prefer
    /// [`Self::try_secret_key`], which returns `Err` instead of panicking in
    /// the (here, unreachable) case where no seed is available.
    pub fn secret_key(&self) -> KemSecretKey {
        self.try_secret_key()
            .expect("ML-KEM-512 DecapsulationKey constructed via from_seed always has a recoverable seed")
    }

    /// Fallible form of [`Self::secret_key`] (A-Z1 hardening).
    ///
    /// Replaces the previous `to_seed().unwrap_or_default()` pattern, which
    /// silently returned an empty `Vec` instead of surfacing a failure.
    /// Returns `Err(KemError::Internal(..))` — never panics, never returns
    /// an empty/truncated seed silently — if the underlying
    /// `ml_kem::DecapsulationKey` has no recoverable seed.
    pub fn try_secret_key(&self) -> KemResult<KemSecretKey> {
        let seed = self.decapsulation_key.to_seed().ok_or_else(|| {
            KemError::Internal("ML-KEM-512 decapsulation key has no recoverable seed".into())
        })?;
        Ok(KemSecretKey::new(KemAlgorithm::MlKem512, seed.as_slice().to_vec()))
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

/// **Known-Answer-Test-only entry points.** Gated behind the `kat` Cargo
/// feature (non-default). See `tests/vectors/README.md` and
/// `docs/gap-analysis/pqc-kem-gap-roadmap.md` §3.7 (X-4/P1).
///
/// Every method here exists solely so this crate's output can be checked
/// against externally published Known-Answer-Test vectors (NIST ACVP
/// `ML-KEM-keyGen-FIPS203` / `ML-KEM-encapDecap-FIPS203`). **None of these
/// are appropriate for production key generation, encapsulation, or key
/// storage** — use [`MlKem512Keypair::generate`], [`MlKem512Keypair::encapsulate`],
/// and [`MlKem512Keypair::from_secret_key_bytes`] there instead.
#[cfg(feature = "kat")]
impl MlKem512Keypair {
    /// **KAT-only — do not use for production key generation.**
    ///
    /// Construct a keypair directly from the FIPS 203 keyGen seed halves
    /// `d` and `z` (concatenated as `d ‖ z` per FIPS 203 §7.1 / Algorithm
    /// 16), exactly as published in NIST ACVP `ML-KEM-keyGen-FIPS203`
    /// vectors. Equivalent to `Self::from_secret_key_bytes(&(d ‖ z))`,
    /// provided so KAT loaders don't need to concatenate byte arrays by
    /// hand.
    pub fn from_seed_halves(d: &[u8; 32], z: &[u8; 32]) -> Self {
        let mut seed_bytes = [0u8; 64];
        seed_bytes[..32].copy_from_slice(d);
        seed_bytes[32..].copy_from_slice(z);
        let seed: Seed = seed_bytes.into();
        let dk = DecapsulationKey::<MlKem512>::from_seed(seed);
        let ek = dk.encapsulation_key().clone();
        Self {
            encapsulation_key: ek,
            decapsulation_key: dk,
        }
    }

    /// **KAT-only — do not use for production encapsulation.**
    ///
    /// Deterministic encapsulation using caller-supplied randomness `m`
    /// instead of drawing it from an RNG (FIPS 203 Algorithm 17 /
    /// `ml_kem::EncapsulationKey::encapsulate_deterministic`, which
    /// [`MlKem512Keypair::encapsulate`] already calls internally with an
    /// RNG-drawn `m`). Exposed so test code can reproduce the exact
    /// ciphertext and shared secret published in NIST ACVP
    /// `ML-KEM-encapDecap-FIPS203` `AFT` (encapsulation) test vectors.
    /// Reusing `m` across encapsulations, or supplying non-uniform `m`,
    /// breaks ML-KEM's security guarantees — [`MlKem512Keypair::encapsulate`]
    /// is the correct API for all non-test use.
    pub fn encapsulate_deterministic(
        recipient_public_key: &KemPublicKey,
        m: &[u8; 32],
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

        let m_arr: ml_kem::B32 = (*m).into();
        let (ct, ss) = ek.encapsulate_deterministic(&m_arr);

        Ok((
            KemCiphertext::new(KemAlgorithm::MlKem512, ct.as_slice().to_vec()),
            SharedSecret::new(ss.as_slice().to_vec()),
        ))
    }

    /// **KAT-only — never used for application key storage.**
    ///
    /// Load a decapsulation-only keypair from ML-KEM's deprecated
    /// "expanded" decapsulation-key wire format (1632 bytes for
    /// ML-KEM-512; see `ml_kem::ExpandedKeyEncoding`, deprecated since
    /// `ml-kem` 0.3.0 in favor of the 64-byte seed form). This crate's own
    /// public API never produces this format —
    /// [`MlKem512Keypair::secret_key`] / [`MlKem512Keypair::from_secret_key_bytes`]
    /// always use the 64-byte seed — but NIST ACVP
    /// `ML-KEM-encapDecap-FIPS203` `VAL` (decapsulation) test vectors
    /// publish decapsulation keys in exactly this expanded form, so KAT
    /// loading needs it.
    pub fn from_expanded_decapsulation_key_bytes(bytes: &[u8]) -> KemResult<Self> {
        let expanded: ml_kem::ExpandedDecapsulationKey<MlKem512> = bytes.try_into()
            .map_err(|_| KemError::InvalidKey(
                format!("ML-KEM-512 expanded decapsulation key must be 1632 bytes, got {}", bytes.len())
            ))?;

        #[allow(deprecated)]
        let dk = <DecapsulationKey<MlKem512> as ml_kem::ExpandedKeyEncoding>::from_expanded_bytes(&expanded)
            .map_err(|_| KemError::InvalidKey("ML-KEM-512 expanded decapsulation key failed validation".into()))?;

        let ek = dk.encapsulation_key().clone();
        Ok(Self {
            encapsulation_key: ek,
            decapsulation_key: dk,
        })
    }

    /// **KAT-only.** Serialize this keypair's decapsulation key to the
    /// deprecated "expanded" wire format (see
    /// [`MlKem512Keypair::from_expanded_decapsulation_key_bytes`]), so KAT
    /// tests can compare against the `dk` field published in NIST ACVP
    /// `ML-KEM-keyGen-FIPS203` vectors, which uses this format rather than
    /// the 64-byte seed.
    pub fn to_expanded_decapsulation_key_bytes(&self) -> alloc::vec::Vec<u8> {
        #[allow(deprecated)]
        let expanded = <DecapsulationKey<MlKem512> as ml_kem::ExpandedKeyEncoding>::to_expanded_bytes(&self.decapsulation_key);
        expanded.as_slice().to_vec()
    }
}
