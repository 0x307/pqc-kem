//! X-Wing hybrid KEM: X25519 + ML-KEM-768, per `draft-connolly-cfrg-xwing-kem`.
//!
//! This is hybrid **profile v2** (`HYBRID_PROFILE_V2`,
//! `"HybridKem-X25519-MLKEM768-v2"`) — see `docs/hybrid-profiles.md` for the
//! full normative spec, including the exact draft version/date cited and
//! test-vector provenance. **Recommended for new deployments** (profile v1,
//! [`crate::fips203::HybridKemKeypair`], remains the wire-compatible default
//! for existing deployments — see [`crate::HYBRID_PROFILE_ID`]).
//!
//! # Construction (draft-connolly-cfrg-xwing-kem-10, 2026-03-02)
//! ```text
//! expandDecapsulationKey(sk):
//!   expanded = SHAKE256(sk, 96 bytes)     // sk is a 32-byte seed
//!   (d, z, sk_X) = expanded[0:32], expanded[32:64], expanded[64:96]
//!   (pk_M, sk_M) = ML-KEM-768.KeyGen_internal(d, z)
//!   pk_X = X25519(sk_X, X25519_BASE)
//!
//! Combiner(ss_M, ss_X, ct_X, pk_X):
//!   SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)   // XWingLabel = 5c2e2f2f5e5c
//!
//! Encapsulate(pk):                      pk = pk_M(1184) ‖ pk_X(32)
//!   ek_X = random(32); ct_X = X25519(ek_X, BASE); ss_X = X25519(ek_X, pk_X)
//!   (ss_M, ct_M) = ML-KEM-768.Encaps(pk_M)
//!   ss = Combiner(ss_M, ss_X, ct_X, pk_X); ct = ct_M(1088) ‖ ct_X(32)
//!
//! Decapsulate(ct, sk):
//!   ss_M = ML-KEM-768.Decap(ct_M, sk_M); ss_X = X25519(sk_X, ct_X)
//!   return Combiner(ss_M, ss_X, ct_X, pk_X)
//! ```
//!
//! Note the byte order: X-Wing puts **ML-KEM first** in both `pk` and `ct`
//! (`pk_M ‖ pk_X`, `ct_M ‖ ct_X`) — the opposite of profile v1's
//! `x25519 ‖ mlkem` layout. Do not mix the two profiles' byte encodings.

extern crate alloc;
use alloc::{format, vec::Vec};

use digest::{ExtendableOutput, XofReader};
use ml_kem::{
    MlKem768,
    DecapsulationKey, EncapsulationKey,
    kem::{Decapsulate, KeyExport},
    Seed,
};
use rand_core::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_256, Shake256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{KemError, KemResult};
use crate::types::{KemAlgorithm, KemSecretKey, SharedSecret};

/// `XWingLabel` (draft §4.2): the 6-byte ASCII string `"\./" "/^\"`, hex
/// `5c2e2f2f5e5c`.
const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// X-Wing encapsulation (public) key: `pk_M(1184) ‖ pk_X(32)` = 1216 bytes.
///
/// **Byte order note:** ML-KEM first, unlike profile v1's
/// [`crate::types::HybridPublicKey`] (X25519 first). See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XWingPublicKey(pub [u8; 1216]);

impl XWingPublicKey {
    /// Canonical byte length per the draft's `Encoding and sizes` (§4.1).
    pub const BYTES: usize = 1216;

    /// Returns the raw 1216-byte encoding (`pk_M ‖ pk_X`).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Decode a 1216-byte X-Wing public key. Length-checked; returns
    /// [`KemError::InvalidKey`] (never panics) on a mismatched length.
    pub fn from_bytes(bytes: &[u8]) -> KemResult<Self> {
        let arr: [u8; Self::BYTES] = bytes.try_into().map_err(|_| {
            KemError::InvalidKey(format!(
                "X-Wing public key must be {} bytes, got {}",
                Self::BYTES,
                bytes.len()
            ))
        })?;
        Ok(Self(arr))
    }

    fn pk_m(&self) -> &[u8] {
        &self.0[0..1184]
    }

    fn pk_x(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.0[1184..1216]);
        out
    }
}

/// X-Wing ciphertext: `ct_M(1088) ‖ ct_X(32)` = 1120 bytes.
///
/// **Byte order note:** ML-KEM first, unlike profile v1's
/// [`crate::types::HybridKemCiphertext`] (X25519 first). See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XWingCiphertext(pub [u8; 1120]);

impl XWingCiphertext {
    /// Canonical byte length per the draft's `Encoding and sizes` (§4.1).
    pub const BYTES: usize = 1120;

    /// Returns the raw 1120-byte encoding (`ct_M ‖ ct_X`).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Decode a 1120-byte X-Wing ciphertext. Length-checked; returns
    /// [`KemError::InvalidCiphertext`] (never panics) on a mismatched length.
    pub fn from_bytes(bytes: &[u8]) -> KemResult<Self> {
        let arr: [u8; Self::BYTES] = bytes.try_into().map_err(|_| {
            KemError::InvalidCiphertext(format!(
                "X-Wing ciphertext must be {} bytes, got {}",
                Self::BYTES,
                bytes.len()
            ))
        })?;
        Ok(Self(arr))
    }

    fn ct_m(&self) -> &[u8] {
        &self.0[0..1088]
    }

    fn ct_x(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.0[1088..1120]);
        out
    }
}

/// `expandDecapsulationKey(sk)` (draft §4.2): `SHAKE256(sk, 96 bytes)` split
/// into `d(32) ‖ z(32) ‖ sk_X(32)`.
fn expand_decapsulation_key(sk: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut hasher = Shake256::default();
    digest::Update::update(&mut hasher, sk);
    let mut reader = hasher.finalize_xof();
    let mut expanded = [0u8; 96];
    reader.read(&mut expanded);

    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    let mut sk_x = [0u8; 32];
    d.copy_from_slice(&expanded[0..32]);
    z.copy_from_slice(&expanded[32..64]);
    sk_x.copy_from_slice(&expanded[64..96]);
    (d, z, sk_x)
}

/// `Combiner(ss_M, ss_X, ct_X, pk_X)` (draft §4.3):
/// `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)`.
fn combiner(ss_m: &[u8], ss_x: &[u8; 32], ct_x: &[u8; 32], pk_x: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(ss_m);
    hasher.update(ss_x);
    hasher.update(ct_x);
    hasher.update(pk_x);
    hasher.update(XWING_LABEL);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// X-Wing keypair (hybrid profile v2, `HYBRID_PROFILE_V2`).
///
/// See the module docs for the construction and
/// `docs/hybrid-profiles.md` for the full normative spec.
///
/// # Secret handling
/// `seed` (the 32-byte X-Wing decapsulation key) is wrapped in
/// [`zeroize::Zeroizing`], so it zeroizes on drop by itself. `x25519_secret`
/// (`StaticSecret`, zeroized via this crate's `x25519-dalek/zeroize`
/// feature) and `mlkem_dk` (`DecapsulationKey`, zeroized via `ml-kem/zeroize`)
/// also zeroize themselves. This type implements
/// [`zeroize::ZeroizeOnDrop`] — no explicit `Drop` is needed.
pub struct XWingKeypair {
    /// The 32-byte X-Wing decapsulation key (the seed). Zeroized on drop.
    seed: Zeroizing<[u8; 32]>,
    /// `sk_X` — X25519 static secret derived from the seed.
    x25519_secret: StaticSecret,
    /// `pk_X` — cached X25519 public key.
    x25519_public: X25519PublicKey,
    /// `sk_M` — ML-KEM-768 decapsulation key derived from the seed.
    mlkem_dk: DecapsulationKey<MlKem768>,
    /// `pk_M` — cached ML-KEM-768 encapsulation key.
    mlkem_ek: EncapsulationKey<MlKem768>,
}

impl zeroize::ZeroizeOnDrop for XWingKeypair {}

impl XWingKeypair {
    /// Generate a new X-Wing keypair using the provided RNG (draws a fresh
    /// 32-byte seed, then calls [`Self::from_seed`]).
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> KemResult<Self> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Ok(Self::from_seed(&seed))
    }

    /// Deterministically derive a keypair from a 32-byte seed
    /// (`GenerateKeyPairDerand(sk)` in the draft — the draft notes ordinary
    /// `GenerateKeyPair()` is equivalent to `GenerateKeyPairDerand(random(32))`,
    /// so this is a legitimate non-test constructor, not `kat`-gated).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let (d, z, sk_x) = expand_decapsulation_key(seed);

        let mut ml_seed_bytes = [0u8; 64];
        ml_seed_bytes[..32].copy_from_slice(&d);
        ml_seed_bytes[32..].copy_from_slice(&z);
        let ml_seed: Seed = ml_seed_bytes.into();
        let mlkem_dk = DecapsulationKey::<MlKem768>::from_seed(ml_seed);
        let mlkem_ek = mlkem_dk.encapsulation_key().clone();

        let x25519_secret = StaticSecret::from(sk_x);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        Self {
            seed: Zeroizing::new(*seed),
            x25519_secret,
            x25519_public,
            mlkem_dk,
            mlkem_ek,
        }
    }

    /// Returns the X-Wing public key (`pk_M ‖ pk_X`, 1216 bytes).
    pub fn public_key(&self) -> XWingPublicKey {
        let mut out = [0u8; 1216];
        out[..1184].copy_from_slice(self.mlkem_ek.to_bytes().as_slice());
        out[1184..].copy_from_slice(self.x25519_public.as_bytes());
        XWingPublicKey(out)
    }

    /// Returns the 32-byte seed (the X-Wing decapsulation key) as a
    /// zeroizing [`KemSecretKey`] (algorithm tag [`KemAlgorithm::XWing`]).
    pub fn seed(&self) -> KemSecretKey {
        KemSecretKey::new(KemAlgorithm::XWing, self.seed.to_vec())
    }

    /// Encapsulate to a recipient's X-Wing public key (`Encapsulate(pk)` in
    /// the draft). Performs the FIPS 203 §7.2 encapsulation-key check
    /// (via `ml_kem::EncapsulationKey::new`) and returns
    /// [`KemError::InvalidKey`] if it fails — never panics.
    pub fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R,
        recipient_pk: &XWingPublicKey,
    ) -> KemResult<(XWingCiphertext, SharedSecret)> {
        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);
        let mut eph_x25519 = [0u8; 32];
        rng.fill_bytes(&mut eph_x25519);
        Self::encapsulate_with(recipient_pk, &eph_x25519, &m)
    }

    /// Shared implementation for [`Self::encapsulate`] (random inputs) and
    /// the `kat`-gated [`Self::encapsulate_deterministic`] (caller-supplied
    /// `eseed`) — both ultimately need an ML-KEM randomness value `m` and an
    /// X25519 ephemeral scalar; only where those come from differs.
    fn encapsulate_with(
        recipient_pk: &XWingPublicKey,
        eph_x25519_sk: &[u8; 32],
        m: &[u8; 32],
    ) -> KemResult<(XWingCiphertext, SharedSecret)> {
        let pk_x = recipient_pk.pk_x();

        let ek_key: ml_kem::kem::Key<EncapsulationKey<MlKem768>> =
            recipient_pk.pk_m().try_into().map_err(|_| {
                KemError::InvalidKey("X-Wing public key: ML-KEM-768 component malformed".into())
            })?;
        let mlkem_ek = EncapsulationKey::<MlKem768>::new(&ek_key)
            .map_err(|_| KemError::InvalidKey("X-Wing public key: ML-KEM-768 encapsulation key check failed (FIPS 203 §7.2)".into()))?;

        let eph_secret = StaticSecret::from(*eph_x25519_sk);
        let ct_x_pub = X25519PublicKey::from(&eph_secret);
        let pk_x_pub = X25519PublicKey::from(pk_x);
        let ss_x = eph_secret.diffie_hellman(&pk_x_pub);

        let m_arr: ml_kem::B32 = (*m).into();
        let (mlkem_ct, mlkem_ss) = mlkem_ek.encapsulate_deterministic(&m_arr);

        let ss = combiner(mlkem_ss.as_slice(), ss_x.as_bytes(), ct_x_pub.as_bytes(), &pk_x);

        let mut ct = [0u8; 1120];
        ct[..1088].copy_from_slice(mlkem_ct.as_slice());
        ct[1088..].copy_from_slice(ct_x_pub.as_bytes());

        Ok((XWingCiphertext(ct), SharedSecret::new(ss.to_vec())))
    }

    /// Decapsulate an X-Wing ciphertext, recovering the shared secret
    /// (`Decapsulate(ct, sk)` in the draft).
    pub fn decapsulate(&self, ciphertext: &XWingCiphertext) -> KemResult<SharedSecret> {
        let ct_m: ml_kem::Ciphertext<MlKem768> = ciphertext.ct_m().try_into().map_err(|_| {
            KemError::InvalidCiphertext("X-Wing ciphertext: ML-KEM-768 component malformed".into())
        })?;
        let ss_m = self.mlkem_dk.decapsulate(&ct_m);

        let ct_x = ciphertext.ct_x();
        let ct_x_pub = X25519PublicKey::from(ct_x);
        let ss_x = self.x25519_secret.diffie_hellman(&ct_x_pub);

        let pk_x = *self.x25519_public.as_bytes();
        let ss = combiner(ss_m.as_slice(), ss_x.as_bytes(), &ct_x, &pk_x);

        Ok(SharedSecret::new(ss.to_vec()))
    }
}

/// **KAT-only entry points.** Gated behind the `kat` Cargo feature
/// (non-default). See `docs/hybrid-profiles.md` and
/// `tests/vectors/xwing/xwing.json` for provenance/vectors.
#[cfg(feature = "kat")]
impl XWingKeypair {
    /// **KAT-only — do not use for production encapsulation.**
    ///
    /// `EncapsulateDerand(pk, eseed)` from the draft: `eseed` is 64 bytes,
    /// split as `m = eseed[0:32]` (ML-KEM-768 `EncapsDerand` randomness) and
    /// `ek_X = eseed[32:64]` (the X25519 ephemeral scalar) — exactly the
    /// split the draft's own published test vectors (`spec/test-vectors.json`
    /// in `dconnolly/draft-connolly-cfrg-xwing-kem`) use for their `eseed`
    /// field.
    pub fn encapsulate_deterministic(
        recipient_pk: &XWingPublicKey,
        eseed: &[u8; 64],
    ) -> KemResult<(XWingCiphertext, SharedSecret)> {
        let m: [u8; 32] = eseed[0..32].try_into().expect("32-byte slice");
        let ek_x: [u8; 32] = eseed[32..64].try_into().expect("32-byte slice");
        Self::encapsulate_with(recipient_pk, &ek_x, &m)
    }
}
