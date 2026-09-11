//! Wire types for KEM public keys, ciphertexts, and shared secrets.
//!
//! These types are designed for serialization across WASM boundaries and for
//! use in DID Documents (W3C Decentralized Identifiers).
//!
//! All byte arrays are encoded as base64url (no padding) strings in JSON.

extern crate alloc;
use alloc::{format, string::{String, ToString}, vec::Vec};

use base64ct::{Base64Url, Encoding};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{KemError, KemResult};

// ── Algorithm Identifiers ─────────────────────────────────────────────────────

/// Identifies the KEM algorithm used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KemAlgorithm {
    /// ML-KEM-512 (NIST FIPS 203, Security Level 1)
    MlKem512,
    /// ML-KEM-768 (NIST FIPS 203, Security Level 3) — recommended default
    MlKem768,
    /// ML-KEM-1024 (NIST FIPS 203, Security Level 5)
    MlKem1024,
    /// Hybrid: X25519 + ML-KEM-768 — primary construction (profile v1,
    /// `HYBRID_PROFILE_V1`; see `docs/hybrid-profiles.md`)
    HybridX25519MlKem768,
    /// X-Wing: X25519 + ML-KEM-768, per `draft-connolly-cfrg-xwing-kem`
    /// (profile v2, `HYBRID_PROFILE_V2`) — same component KEMs as
    /// [`KemAlgorithm::HybridX25519MlKem768`], different combiner and byte
    /// layout (ML-KEM first). Recommended for new deployments; see
    /// `docs/hybrid-profiles.md`. Added 0.3.0.
    XWing,
    /// HQC-128 (NIST 2025, Security Level 1) — requires `hqc` feature
    Hqc128,
    /// HQC-192 (NIST 2025, Security Level 3) — requires `hqc` feature
    Hqc192,
    /// HQC-256 (NIST 2025, Security Level 5) — requires `hqc` feature
    Hqc256,
    /// BIKE (NIST Round 4 alternate) — **never implemented in this crate**.
    ///
    /// The `bike` feature and `src/bike` module (a permanent
    /// `compile_error!` stub) were removed entirely in 0.3.0. This variant
    /// is retained only so previously-serialized values (e.g.
    /// `"bike"` in JSON) continue to deserialize without error; it carries
    /// no working implementation in any release and never did. Scheduled
    /// for removal in 0.4.0 per `STABILITY.md` §3's one-minor-version
    /// deprecation floor.
    #[deprecated(
        since = "0.3.0",
        note = "BIKE was never implemented; the `bike` feature/module were removed in 0.3.0. This variant is kept only for wire compatibility and will be removed in 0.4.0."
    )]
    Bike,
    /// Classic McEliece (NIST Round 4 alternate) — **never implemented in this crate**.
    ///
    /// The `mceliece` feature and `src/mceliece` module (a permanent
    /// `compile_error!` stub) were removed entirely in 0.3.0. This variant
    /// is retained only so previously-serialized values (e.g.
    /// `"classic_mceliece"` in JSON) continue to deserialize without error;
    /// it carries no working implementation in any release and never did.
    /// Scheduled for removal in 0.4.0 per `STABILITY.md` §3's
    /// one-minor-version deprecation floor.
    #[deprecated(
        since = "0.3.0",
        note = "Classic McEliece was never implemented; the `mceliece` feature/module were removed in 0.3.0. This variant is kept only for wire compatibility and will be removed in 0.4.0."
    )]
    ClassicMceliece,
}

impl KemAlgorithm {
    /// Returns the algorithm identifier string (for DID Documents, JWK, etc.)
    #[allow(deprecated)] // Bike/ClassicMceliece arms — see variant docs (removed in 0.4.0)
    pub fn as_str(&self) -> &'static str {
        match self {
            KemAlgorithm::MlKem512              => "ML-KEM-512",
            KemAlgorithm::MlKem768              => "ML-KEM-768",
            KemAlgorithm::MlKem1024             => "ML-KEM-1024",
            KemAlgorithm::HybridX25519MlKem768  => "X25519+ML-KEM-768",
            KemAlgorithm::XWing                 => "X-Wing",
            KemAlgorithm::Hqc128                => "HQC-128",
            KemAlgorithm::Hqc192                => "HQC-192",
            KemAlgorithm::Hqc256                => "HQC-256",
            KemAlgorithm::Bike                  => "BIKE",
            KemAlgorithm::ClassicMceliece       => "Classic-McEliece",
        }
    }

    /// Returns the expected public key size in bytes (0 = variable).
    #[allow(deprecated)] // Bike/ClassicMceliece arms — see variant docs (removed in 0.4.0)
    pub fn public_key_size(&self) -> usize {
        match self {
            KemAlgorithm::MlKem512              => 800,
            KemAlgorithm::MlKem768              => 1184,
            KemAlgorithm::MlKem1024             => 1568,
            KemAlgorithm::HybridX25519MlKem768  => 32 + 1184, // 1216
            KemAlgorithm::XWing                 => 1216, // pk_M(1184) ‖ pk_X(32)
            KemAlgorithm::Hqc128                => 2249,
            KemAlgorithm::Hqc192                => 4522,
            KemAlgorithm::Hqc256                => 7245,
            KemAlgorithm::Bike                  => 0, // variable by level
            KemAlgorithm::ClassicMceliece       => 0, // variable by parameter set
        }
    }

    /// Returns the expected ciphertext size in bytes (0 = variable).
    ///
    /// HQC-128/256 sizes were corrected from 4481/14469 to 4433/14421 bytes
    /// during the P2/alpha-001 HQC implementation pass — verified live
    /// against both `pqcrypto-hqc` 0.2.2 and `liboqs` 0.13.0 (two
    /// independent implementations of the same NIST submission, which
    /// agree). HQC-192's 8978-byte ciphertext was already correct. This
    /// reflects the HQC round-4/2023 parameter revision to the
    /// error-correcting code, which changed ciphertext size at the 128- and
    /// 256-bit levels but not the 192-bit level.
    #[allow(deprecated)] // Bike/ClassicMceliece arms — see variant docs (removed in 0.4.0)
    pub fn ciphertext_size(&self) -> usize {
        match self {
            KemAlgorithm::MlKem512              => 768,
            KemAlgorithm::MlKem768              => 1088,
            KemAlgorithm::MlKem1024             => 1568,
            KemAlgorithm::HybridX25519MlKem768  => 32 + 1088, // 1120
            KemAlgorithm::XWing                 => 1120, // ct_M(1088) ‖ ct_X(32)
            KemAlgorithm::Hqc128                => 4433,
            KemAlgorithm::Hqc192                => 8978,
            KemAlgorithm::Hqc256                => 14421,
            KemAlgorithm::Bike                  => 0,
            KemAlgorithm::ClassicMceliece       => 0,
        }
    }

    /// Returns the shared secret size in bytes (always 32 for all supported algorithms).
    pub fn shared_secret_size(&self) -> usize {
        32
    }
}

// ── Raw Byte Wrappers ─────────────────────────────────────────────────────────

/// A KEM public key (raw bytes).
///
/// Public keys are safe to distribute and do not require zeroization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemPublicKey {
    /// The algorithm this key belongs to.
    pub algorithm: KemAlgorithm,
    /// Raw public key bytes.
    #[serde(
        serialize_with   = "serialize_bytes_base64url",
        deserialize_with = "deserialize_bytes_base64url"
    )]
    pub bytes: Vec<u8>,
}

impl KemPublicKey {
    /// Create a new public key from raw bytes.
    pub fn new(algorithm: KemAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// Encode the public key as base64url (no padding).
    pub fn to_base64url(&self) -> String {
        Base64Url::encode_string(&self.bytes)
    }

    /// Encode the public key as multibase (base58btc, prefix 'z') for DID Documents.
    pub fn to_multibase(&self) -> String {
        let mut out = String::with_capacity(self.bytes.len() * 2);
        out.push('z');
        out.push_str(&bs58::encode(&self.bytes).into_string());
        out
    }

    /// Decode a public key from base64url.
    pub fn from_base64url(algorithm: KemAlgorithm, s: &str) -> KemResult<Self> {
        let bytes = Base64Url::decode_vec(s)
            .map_err(|e| KemError::Base64Decode(e.to_string()))?;
        Ok(Self { algorithm, bytes })
    }

    /// Decode a public key from multibase (base58btc, prefix 'z').
    pub fn from_multibase(algorithm: KemAlgorithm, s: &str) -> KemResult<Self> {
        let s = s.strip_prefix('z')
            .ok_or_else(|| KemError::InvalidKey("multibase prefix must be 'z' (base58btc)".into()))?;
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| KemError::InvalidKey(e.to_string()))?;
        Ok(Self { algorithm, bytes })
    }
}

/// A KEM secret key (raw bytes). Zeroized on drop.
///
/// # Secret handling
/// `bytes` is zeroized on drop (`#[derive(Zeroize, ZeroizeOnDrop)]`).
/// `algorithm` is `#[zeroize(skip)]`d — it is a plain enum tag with no
/// secret data. Cloning this type duplicates the secret bytes into a new,
/// independently-zeroizing allocation; the clone is zeroized on its own
/// drop just like the original.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct KemSecretKey {
    /// The algorithm this key belongs to.
    /// Skipped during zeroization — `KemAlgorithm` is a plain enum with no secret data.
    #[zeroize(skip)]
    pub algorithm: KemAlgorithm,
    /// Raw secret key bytes (zeroized on drop).
    pub bytes: Vec<u8>,
}

impl KemSecretKey {
    /// Create a new secret key from raw bytes.
    pub fn new(algorithm: KemAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }
}

/// A KEM ciphertext (raw bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemCiphertext {
    /// The algorithm used to produce this ciphertext.
    pub algorithm: KemAlgorithm,
    /// Raw ciphertext bytes.
    #[serde(
        serialize_with   = "serialize_bytes_base64url",
        deserialize_with = "deserialize_bytes_base64url"
    )]
    pub bytes: Vec<u8>,
}

impl KemCiphertext {
    /// Create a new ciphertext from raw bytes.
    pub fn new(algorithm: KemAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// Encode the ciphertext as base64url (no padding).
    pub fn to_base64url(&self) -> String {
        Base64Url::encode_string(&self.bytes)
    }

    /// Decode a ciphertext from base64url.
    pub fn from_base64url(algorithm: KemAlgorithm, s: &str) -> KemResult<Self> {
        let bytes = Base64Url::decode_vec(s)
            .map_err(|e| KemError::Base64Decode(e.to_string()))?;
        Ok(Self { algorithm, bytes })
    }
}

/// A shared secret produced by KEM encapsulation/decapsulation. Zeroized on drop.
///
/// # Secret handling
/// `bytes` is zeroized on drop (`#[derive(Zeroize, ZeroizeOnDrop)]`).
/// Cloning this type duplicates the secret bytes into a new,
/// independently-zeroizing allocation.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    /// Raw shared secret bytes (always 32 bytes for all supported algorithms).
    pub bytes: Vec<u8>,
}

impl SharedSecret {
    /// Create a new shared secret from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the shared secret as a fixed 32-byte array, if it is exactly 32 bytes.
    pub fn as_32_bytes(&self) -> KemResult<[u8; 32]> {
        self.bytes.as_slice().try_into()
            .map_err(|_| KemError::Internal(
                format!("shared secret is {} bytes, expected 32", self.bytes.len())
            ))
    }
}

// ── Hybrid KEM Wire Types ─────────────────────────────────────────────────────

/// Wire format for a Hybrid X25519 + ML-KEM-768 ciphertext.
///
/// This is this crate's primary hybrid KEM construction.
/// Breaking it requires breaking both X25519 AND ML-KEM-768 simultaneously.
///
/// # Construction
/// ```text
/// x25519_ss  = X25519(ephemeral_private, recipient_x25519_public)
/// mlkem_ss   = ML-KEM-768.Decaps(ciphertext, recipient_mlkem_secret)
/// combined   = x25519_ss ‖ mlkem_ss          (64 bytes)
/// shared_key = HKDF-SHA256(combined, info="pqc-kem-hybrid-v1", len=32)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridKemCiphertext {
    /// X25519 ephemeral public key (32 bytes, base64url-encoded).
    pub classical_ct: String,
    /// ML-KEM-768 ciphertext (1088 bytes, base64url-encoded).
    pub pqc_ct: String,
    /// Algorithm identifier: "X25519+ML-KEM-768"
    pub algorithm: String,
}

impl HybridKemCiphertext {
    /// Create a new hybrid ciphertext from raw byte components.
    pub fn new(x25519_ephemeral_pub: &[u8], mlkem_ciphertext: &[u8]) -> Self {
        Self {
            classical_ct: Base64Url::encode_string(x25519_ephemeral_pub),
            pqc_ct:       Base64Url::encode_string(mlkem_ciphertext),
            algorithm:    "X25519+ML-KEM-768".into(),
        }
    }

    /// Decode the X25519 ephemeral public key bytes.
    pub fn x25519_bytes(&self) -> KemResult<Vec<u8>> {
        Base64Url::decode_vec(&self.classical_ct)
            .map_err(|e| KemError::Base64Decode(e.to_string()))
    }

    /// Decode the ML-KEM-768 ciphertext bytes.
    pub fn mlkem_bytes(&self) -> KemResult<Vec<u8>> {
        Base64Url::decode_vec(&self.pqc_ct)
            .map_err(|e| KemError::Base64Decode(e.to_string()))
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> KemResult<String> {
        serde_json::to_string(self)
            .map_err(|e| KemError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON string.
    pub fn from_json(s: &str) -> KemResult<Self> {
        serde_json::from_str(s)
            .map_err(|e| KemError::Serialization(e.to_string()))
    }

    /// Canonical **profile v1** (`HYBRID_PROFILE_V1`) byte encoding:
    /// `x25519_eph_pk(32) ‖ mlkem_ct(1088)` = 1120 bytes. See
    /// `docs/hybrid-profiles.md`. This is additive — the JSON wire format
    /// above (`classical_ct`/`pqc_ct`/`algorithm`) is unchanged and remains
    /// the compatibility-critical shape SAGP consumes.
    pub const BYTES: usize = 1120;

    /// Encode this ciphertext as the canonical 1120-byte v1 profile layout.
    ///
    /// Fails with [`KemError::InvalidCiphertext`] if the decoded component
    /// lengths don't match the profile (32 / 1088 bytes) — never panics.
    pub fn to_bytes(&self) -> KemResult<Vec<u8>> {
        let x25519 = self.x25519_bytes()?;
        let mlkem = self.mlkem_bytes()?;
        if x25519.len() != 32 {
            return Err(KemError::InvalidCiphertext(
                format!("hybrid v1 profile: X25519 component must be 32 bytes, got {}", x25519.len())
            ));
        }
        if mlkem.len() != 1088 {
            return Err(KemError::InvalidCiphertext(
                format!("hybrid v1 profile: ML-KEM-768 component must be 1088 bytes, got {}", mlkem.len())
            ));
        }
        let mut out = Vec::with_capacity(Self::BYTES);
        out.extend_from_slice(&x25519);
        out.extend_from_slice(&mlkem);
        Ok(out)
    }

    /// Decode the canonical 1120-byte v1 profile layout produced by
    /// [`Self::to_bytes`]. Length-checked; returns [`KemError::InvalidCiphertext`]
    /// (never panics) on a mismatched length. Rebuilds the same JSON-facing
    /// fields [`Self::new`] would.
    pub fn from_bytes(bytes: &[u8]) -> KemResult<Self> {
        if bytes.len() != Self::BYTES {
            return Err(KemError::InvalidCiphertext(
                format!("hybrid v1 profile ciphertext must be {} bytes, got {}", Self::BYTES, bytes.len())
            ));
        }
        Ok(Self::new(&bytes[..32], &bytes[32..]))
    }
}

/// Wire format for a Hybrid X25519 + ML-KEM-768 public key.
///
/// Used in DID Documents under the `keyAgreement` verification method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridPublicKey {
    /// X25519 public key (32 bytes, base64url-encoded).
    pub x25519_key: String,
    /// ML-KEM-768 public key (1184 bytes, base64url-encoded).
    pub mlkem_key: String,
    /// Multibase-encoded X25519 key for DID keyAgreement (base58btc, prefix 'z').
    pub x25519_multibase: String,
    /// Multibase-encoded ML-KEM-768 key for DID keyAgreement (base58btc, prefix 'z').
    pub mlkem_multibase: String,
}

impl HybridPublicKey {
    /// Create a new hybrid public key from raw byte components.
    pub fn new(x25519_pub: &[u8], mlkem_pub: &[u8]) -> Self {
        let x25519_multibase = {
            let mut s = String::with_capacity(x25519_pub.len() * 2);
            s.push('z');
            s.push_str(&bs58::encode(x25519_pub).into_string());
            s
        };
        let mlkem_multibase = {
            let mut s = String::with_capacity(mlkem_pub.len() * 2);
            s.push('z');
            s.push_str(&bs58::encode(mlkem_pub).into_string());
            s
        };
        Self {
            x25519_key:      Base64Url::encode_string(x25519_pub),
            mlkem_key:       Base64Url::encode_string(mlkem_pub),
            x25519_multibase,
            mlkem_multibase,
        }
    }

    /// Decode the X25519 public key bytes.
    pub fn x25519_bytes(&self) -> KemResult<Vec<u8>> {
        Base64Url::decode_vec(&self.x25519_key)
            .map_err(|e| KemError::Base64Decode(e.to_string()))
    }

    /// Decode the ML-KEM-768 public key bytes.
    pub fn mlkem_bytes(&self) -> KemResult<Vec<u8>> {
        Base64Url::decode_vec(&self.mlkem_key)
            .map_err(|e| KemError::Base64Decode(e.to_string()))
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> KemResult<String> {
        serde_json::to_string(self)
            .map_err(|e| KemError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON string.
    pub fn from_json(s: &str) -> KemResult<Self> {
        serde_json::from_str(s)
            .map_err(|e| KemError::Serialization(e.to_string()))
    }

    /// Canonical **profile v1** (`HYBRID_PROFILE_V1`) byte encoding:
    /// `x25519_pk(32) ‖ mlkem_ek(1184)` = 1216 bytes. See
    /// `docs/hybrid-profiles.md`. Additive — the JSON wire format above
    /// (`x25519_key`/`mlkem_key`/`*_multibase`) is unchanged.
    pub const BYTES: usize = 1216;

    /// Encode this public key as the canonical 1216-byte v1 profile layout.
    ///
    /// Fails with [`KemError::InvalidKey`] if the decoded component lengths
    /// don't match the profile (32 / 1184 bytes) — never panics.
    pub fn to_bytes(&self) -> KemResult<Vec<u8>> {
        let x25519 = self.x25519_bytes()?;
        let mlkem = self.mlkem_bytes()?;
        if x25519.len() != 32 {
            return Err(KemError::InvalidKey(
                format!("hybrid v1 profile: X25519 component must be 32 bytes, got {}", x25519.len())
            ));
        }
        if mlkem.len() != 1184 {
            return Err(KemError::InvalidKey(
                format!("hybrid v1 profile: ML-KEM-768 component must be 1184 bytes, got {}", mlkem.len())
            ));
        }
        let mut out = Vec::with_capacity(Self::BYTES);
        out.extend_from_slice(&x25519);
        out.extend_from_slice(&mlkem);
        Ok(out)
    }

    /// Decode the canonical 1216-byte v1 profile layout produced by
    /// [`Self::to_bytes`]. Length-checked; returns [`KemError::InvalidKey`]
    /// (never panics) on a mismatched length. Rebuilds the same
    /// JSON-facing fields [`Self::new`] would (including the multibase
    /// fields).
    pub fn from_bytes(bytes: &[u8]) -> KemResult<Self> {
        if bytes.len() != Self::BYTES {
            return Err(KemError::InvalidKey(
                format!("hybrid v1 profile public key must be {} bytes, got {}", Self::BYTES, bytes.len())
            ));
        }
        Ok(Self::new(&bytes[..32], &bytes[32..]))
    }
}

// ── Named Hybrid KEM Profiles (K-5) ───────────────────────────────────────────

/// Identifies a named hybrid KEM profile (K-5, `docs/hybrid-profiles.md`).
///
/// Both profiles combine X25519 (RFC 7748) and ML-KEM-768 (FIPS 203) — they
/// differ only in combiner and canonical byte layout:
///
/// - [`HybridProfile::V1`] — this crate's original combiner
///   (`HKDF-SHA256(x25519_ss ‖ mlkem_ss, info="pqc-kem-hybrid-v1")`,
///   `HybridKemKeypair`), wire-compatible with every prior 0.x release.
///   Does **not** bind the ciphertext/public key into the KDF.
/// - [`HybridProfile::V2XWing`] — X-Wing (`draft-connolly-cfrg-xwing-kem`,
///   `XWingKeypair`), `SHA3-256`-based combiner that binds `ct_X`/`pk_X`.
///   **Recommended for new deployments.**
///
/// `PRIMARY_ALGORITHM`/`HYBRID_PROFILE_ID` still point at v1 for wire
/// compatibility with existing SAGP deployments; this may change in a
/// future major/minor version once v2 has had time to see adoption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridProfile {
    /// `HybridKem-X25519-MLKEM768-v1` — this crate's original combiner.
    V1,
    /// `HybridKem-X25519-MLKEM768-v2` — X-Wing.
    V2XWing,
}

impl HybridProfile {
    /// The profile's string identifier (`HYBRID_PROFILE_V1`/`HYBRID_PROFILE_V2`).
    pub fn id(&self) -> &'static str {
        match self {
            HybridProfile::V1 => crate::HYBRID_PROFILE_V1,
            HybridProfile::V2XWing => crate::HYBRID_PROFILE_V2,
        }
    }

    /// Public key size in bytes. Identical (1216) for both profiles — they
    /// differ in component *order*, not size (see `docs/hybrid-profiles.md`).
    pub fn pk_len(&self) -> usize {
        1216
    }

    /// Ciphertext size in bytes. Identical (1120) for both profiles.
    pub fn ct_len(&self) -> usize {
        1120
    }

    /// Secret-key storage size in bytes. v1: `x25519_sk(32) ‖ d(32) ‖ z(32)`
    /// = 96. X-Wing: a single 32-byte seed.
    pub fn sk_len(&self) -> usize {
        match self {
            HybridProfile::V1 => 96,
            HybridProfile::V2XWing => 32,
        }
    }
}

// ── Serde Helpers ─────────────────────────────────────────────────────────────

fn serialize_bytes_base64url<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&Base64Url::encode_string(bytes))
}

fn deserialize_bytes_base64url<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Base64Url::decode_vec(&s).map_err(serde::de::Error::custom)
}
