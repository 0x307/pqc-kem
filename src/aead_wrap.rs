//! `aead-wrap`: from a KEM shared secret to a sealed payload, in one audited
//! path.
//!
//! A KEM produces a 32-byte shared secret, not an encryption. Every consumer
//! that wants to send data to a public key has to turn that secret into an
//! AEAD key and seal with it, and each one that does so by hand invents its
//! own key derivation. This module is that step, done once:
//!
//! ```text
//! key = HKDF-SHA256(ikm  = shared_secret,
//!                   salt = none,
//!                   info = "pqc-kem-aead-wrap-v1" ‖ 0x00 ‖ kem_algorithm ‖ 0x00 ‖ context)
//! ```
//!
//! `kem_algorithm` is the KEM's stable name (`"ML-KEM-768"`,
//! `"X25519+ML-KEM-768"`), and `context` is chosen by the caller to separate
//! protocols from one another, e.g. `b"my-protocol-v1"`. The algorithm name
//! comes from a fixed set containing no NUL byte, so the encoding parses one
//! way only: a context can never be confused with a different algorithm.
//!
//! # Two ways to use it
//!
//! **Single-shot sealing** -- [`seal_ml_kem_768`](crate::aead_wrap::seal_ml_kem_768) / [`open_ml_kem_768`](crate::aead_wrap::open_ml_kem_768) and
//! [`seal_hybrid`](crate::aead_wrap::seal_hybrid) / [`open_hybrid`](crate::aead_wrap::open_hybrid). Each call encapsulates afresh, so every
//! sealed box has its own one-time AEAD key. XChaCha20-Poly1305 is the default
//! suite; the `_with_suite` variants choose ChaCha20-Poly1305 instead.
//!
//! **Your own framing** -- [`derive_aead_key`](crate::aead_wrap::derive_aead_key) alone, for a protocol that keeps
//! a session key and seals many messages under it (a tunnel, say). That
//! caller owns nonce management and must never reuse a nonce under one key;
//! ChaCha20-Poly1305's 12-byte nonce is meant to be a counter there.
//!
//! # Security properties
//!
//! - **The AEAD tag binds the encapsulation.** The authenticated data is
//!   `kem_ct ‖ aad`, so a sealed body cannot be moved onto another KEM
//!   ciphertext. `kem_ct` has a fixed length per algorithm, so the
//!   concatenation is unambiguous.
//! - **One key per sealed box.** Single-shot sealing derives a fresh key from
//!   a fresh encapsulation every time, which is why a random 12-byte nonce is
//!   safe for the ChaCha20 suite here even though it would not be for a
//!   long-lived key.
//! - **Uniform failure.** After the structural checks -- algorithm, lengths --
//!   every failure to open returns the same [`KemError::SymmetricCipher`]:
//!   wrong recipient, tampered KEM ciphertext, tampered body or tag, wrong
//!   nonce, wrong context, wrong `aad`. ML-KEM's implicit rejection turns a
//!   bad KEM ciphertext into a wrong key rather than an error, and reporting
//!   it the same way as a bad tag keeps the two indistinguishable.
//! - **No plaintext left behind.** Opened plaintext comes back as
//!   [`Zeroizing`](zeroize::Zeroizing); working buffers are zeroized; [`AeadKey`](crate::aead_wrap::AeadKey) zeroizes on drop.
//!
//! Not for identity or wallet secrets: this seals data *to* a KEM public key.
//! Anything whose security depends on purpose-separated keys belongs in a
//! construction built for that.

extern crate alloc;
use alloc::vec::Vec;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{KemError, KemResult};
use crate::fips203::{HybridKemKeypair, MlKem768Keypair};
use crate::types::{HybridKemCiphertext, HybridPublicKey, KemAlgorithm, KemCiphertext, KemPublicKey, SharedSecret};

/// Domain-separation label for the key derivation. Bump the suffix on any
/// change to the derivation; old and new keys must never coincide.
pub const AEAD_WRAP_INFO_V1: &[u8] = b"pqc-kem-aead-wrap-v1";

/// Poly1305 tag length, identical for both suites.
const TAG_LEN: usize = 16;

/// ML-KEM-768 ciphertext length (FIPS 203).
const ML_KEM_768_CT_LEN: usize = 1088;

/// The AEAD that seals the payload.
///
/// Wire names are given explicitly rather than by `rename_all = "kebab-case"`,
/// which splits on every capital and would serialize `XChaCha20Poly1305` as
/// `x-cha-cha20-poly1305`. A wire name is permanent once published, so it
/// should be the one people actually write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AeadSuite {
    /// The default. 24-byte nonce, large enough to generate at random for any
    /// number of messages under one key.
    #[serde(rename = "xchacha20-poly1305")]
    XChaCha20Poly1305,
    /// 12-byte nonce. Safe with a random nonce only because single-shot
    /// sealing never reuses a key; for a long-lived key, use a counter.
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
}

impl AeadSuite {
    /// Nonce length in bytes for this suite.
    pub const fn nonce_len(self) -> usize {
        match self {
            AeadSuite::XChaCha20Poly1305 => 24,
            AeadSuite::ChaCha20Poly1305 => 12,
        }
    }
}

/// A 32-byte AEAD key, zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AeadKey(pub [u8; 32]);

/// A payload sealed to a KEM public key.
///
/// Byte fields are base64url in JSON, as with every other wire type here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBox {
    /// Which KEM produced `kem_ct`.
    pub kem_algorithm: KemAlgorithm,
    /// Which AEAD sealed `ciphertext`.
    pub suite: AeadSuite,
    /// The KEM ciphertext: 1088 bytes for ML-KEM-768, 1120 for the hybrid's
    /// canonical encoding.
    #[serde(
        serialize_with = "crate::types::serialize_bytes_base64url",
        deserialize_with = "crate::types::deserialize_bytes_base64url"
    )]
    pub kem_ct: Vec<u8>,
    /// The AEAD nonce: 24 bytes for XChaCha20, 12 for ChaCha20.
    #[serde(
        serialize_with = "crate::types::serialize_bytes_base64url",
        deserialize_with = "crate::types::deserialize_bytes_base64url"
    )]
    pub nonce: Vec<u8>,
    /// Sealed payload followed by its 16-byte tag.
    #[serde(
        serialize_with = "crate::types::serialize_bytes_base64url",
        deserialize_with = "crate::types::deserialize_bytes_base64url"
    )]
    pub ciphertext: Vec<u8>,
}

impl SealedBox {
    /// Serialize to a JSON string, as the crate's other wire types do.
    pub fn to_json(&self) -> KemResult<alloc::string::String> {
        serde_json::to_string(self).map_err(|e| KemError::Serialization(alloc::string::ToString::to_string(&e)))
    }

    /// Deserialize from a JSON string. This checks shape only: lengths and
    /// algorithm are checked when the box is opened.
    pub fn from_json(s: &str) -> KemResult<Self> {
        serde_json::from_str(s).map_err(|e| KemError::Serialization(alloc::string::ToString::to_string(&e)))
    }
}

/// Derive the AEAD key for a KEM shared secret.
///
/// `HKDF-SHA256(ikm = ss, salt = none, info = AEAD_WRAP_INFO_V1 ‖ 0x00 ‖
/// kem_algorithm.as_str() ‖ 0x00 ‖ context)`, 32 bytes out.
///
/// Public so that a protocol with its own framing can derive session keys
/// (one per direction, say, by varying `context`) without re-implementing
/// the derivation.
pub fn derive_aead_key(ss: &SharedSecret, kem_algorithm: KemAlgorithm, context: &[u8]) -> KemResult<AeadKey> {
    let alg = kem_algorithm.as_str().as_bytes();
    let mut info = Vec::with_capacity(AEAD_WRAP_INFO_V1.len() + 2 + alg.len() + context.len());
    info.extend_from_slice(AEAD_WRAP_INFO_V1);
    info.push(0x00);
    info.extend_from_slice(alg);
    info.push(0x00);
    info.extend_from_slice(context);

    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(None, &ss.bytes)
        .expand(&info, &mut okm)
        .map_err(|_| KemError::KeyDerivation("HKDF-SHA256 expand failed".into()))?;
    let key = AeadKey(okm);
    okm.zeroize();
    Ok(key)
}

/// Seal to an ML-KEM-768 public key with the default suite, XChaCha20-Poly1305.
pub fn seal_ml_kem_768<R: CryptoRng + RngCore>(
    rng: &mut R,
    recipient: &KemPublicKey,
    context: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> KemResult<SealedBox> {
    seal_ml_kem_768_with_suite(rng, AeadSuite::XChaCha20Poly1305, recipient, context, aad, plaintext)
}

/// Seal to an ML-KEM-768 public key with a chosen suite.
pub fn seal_ml_kem_768_with_suite<R: CryptoRng + RngCore>(
    rng: &mut R,
    suite: AeadSuite,
    recipient: &KemPublicKey,
    context: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> KemResult<SealedBox> {
    // encapsulate() rejects a key of the wrong algorithm or length.
    let (ct, ss) = MlKem768Keypair::encapsulate(rng, recipient)?;
    let key = derive_aead_key(&ss, KemAlgorithm::MlKem768, context)?;
    seal_with_key(rng, suite, &key, KemAlgorithm::MlKem768, ct.bytes, aad, plaintext)
}

/// Open a box sealed to this ML-KEM-768 keypair.
pub fn open_ml_kem_768(
    keypair: &MlKem768Keypair,
    sealed: &SealedBox,
    context: &[u8],
    aad: &[u8],
) -> KemResult<Zeroizing<Vec<u8>>> {
    validate(sealed, KemAlgorithm::MlKem768, ML_KEM_768_CT_LEN)?;
    let ct = KemCiphertext::new(KemAlgorithm::MlKem768, sealed.kem_ct.clone());
    let ss = keypair.decapsulate(&ct).map_err(|_| auth_failed())?;
    let key = derive_aead_key(&ss, KemAlgorithm::MlKem768, context)?;
    open_with_key(&key, sealed, aad)
}

/// Seal to a hybrid (X25519 + ML-KEM-768, profile v1) public key with the
/// default suite, XChaCha20-Poly1305.
pub fn seal_hybrid<R: CryptoRng + RngCore>(
    rng: &mut R,
    recipient: &HybridPublicKey,
    context: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> KemResult<SealedBox> {
    seal_hybrid_with_suite(rng, AeadSuite::XChaCha20Poly1305, recipient, context, aad, plaintext)
}

/// Seal to a hybrid public key with a chosen suite.
pub fn seal_hybrid_with_suite<R: CryptoRng + RngCore>(
    rng: &mut R,
    suite: AeadSuite,
    recipient: &HybridPublicKey,
    context: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> KemResult<SealedBox> {
    let (ct, ss) = HybridKemKeypair::encapsulate_to(rng, recipient)?;
    let kem_ct = ct.to_bytes()?;
    let key = derive_aead_key(&ss, KemAlgorithm::HybridX25519MlKem768, context)?;
    seal_with_key(rng, suite, &key, KemAlgorithm::HybridX25519MlKem768, kem_ct, aad, plaintext)
}

/// Open a box sealed to this hybrid keypair.
pub fn open_hybrid(
    keypair: &HybridKemKeypair,
    sealed: &SealedBox,
    context: &[u8],
    aad: &[u8],
) -> KemResult<Zeroizing<Vec<u8>>> {
    validate(sealed, KemAlgorithm::HybridX25519MlKem768, HybridKemCiphertext::BYTES)?;
    let ct = HybridKemCiphertext::from_bytes(&sealed.kem_ct).map_err(|_| auth_failed())?;
    let ss = keypair.decapsulate(&ct).map_err(|_| auth_failed())?;
    let key = derive_aead_key(&ss, KemAlgorithm::HybridX25519MlKem768, context)?;
    open_with_key(&key, sealed, aad)
}

// ── internals ────────────────────────────────────────────────────────────────

/// The single error every post-validation failure maps to. See the module
/// docs: distinguishing "the KEM ciphertext was bad" from "the tag was bad"
/// would hand an attacker an oracle that implicit rejection exists to deny.
fn auth_failed() -> KemError {
    KemError::SymmetricCipher("sealed box failed to open".into())
}

/// Structural checks, done before any cryptography. These reveal nothing
/// secret -- a length or an algorithm tag is public -- so they may say
/// precisely what is wrong.
fn validate(sealed: &SealedBox, expected: KemAlgorithm, kem_ct_len: usize) -> KemResult<()> {
    if sealed.kem_algorithm != expected {
        return Err(KemError::InvalidCiphertext(alloc::format!(
            "sealed box is for {:?}, expected {:?}",
            sealed.kem_algorithm, expected
        )));
    }
    if sealed.kem_ct.len() != kem_ct_len {
        return Err(KemError::InvalidCiphertext(alloc::format!(
            "KEM ciphertext is {} bytes, expected {}",
            sealed.kem_ct.len(),
            kem_ct_len
        )));
    }
    if sealed.nonce.len() != sealed.suite.nonce_len() {
        return Err(KemError::InvalidCiphertext(alloc::format!(
            "nonce is {} bytes, {:?} needs {}",
            sealed.nonce.len(),
            sealed.suite,
            sealed.suite.nonce_len()
        )));
    }
    if sealed.ciphertext.len() < TAG_LEN {
        return Err(KemError::InvalidCiphertext(alloc::format!(
            "ciphertext is {} bytes, shorter than the {}-byte tag",
            sealed.ciphertext.len(),
            TAG_LEN
        )));
    }
    Ok(())
}

/// `kem_ct ‖ aad`: what the tag authenticates besides the body.
fn internal_aad(kem_ct: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(kem_ct.len() + aad.len());
    v.extend_from_slice(kem_ct);
    v.extend_from_slice(aad);
    v
}

fn seal_with_key<R: CryptoRng + RngCore>(
    rng: &mut R,
    suite: AeadSuite,
    key: &AeadKey,
    kem_algorithm: KemAlgorithm,
    kem_ct: Vec<u8>,
    aad: &[u8],
    plaintext: &[u8],
) -> KemResult<SealedBox> {
    let mut nonce = alloc::vec![0u8; suite.nonce_len()];
    rng.fill_bytes(&mut nonce);
    let aad_internal = internal_aad(&kem_ct, aad);

    // Zeroizing, because until encryption succeeds this holds the plaintext;
    // if it fails, the copy must not outlive the call.
    let mut buf = Zeroizing::new(plaintext.to_vec());
    let tag: Tag = match suite {
        AeadSuite::XChaCha20Poly1305 => XChaCha20Poly1305::new(Key::from_slice(&key.0))
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), &aad_internal, &mut buf),
        AeadSuite::ChaCha20Poly1305 => ChaCha20Poly1305::new(Key::from_slice(&key.0))
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad_internal, &mut buf),
    }
    .map_err(|_| KemError::SymmetricCipher("sealing failed".into()))?;

    // buf now holds ciphertext, not plaintext; taking it leaves an empty
    // Vec behind for Zeroizing to clear.
    let mut ciphertext = core::mem::take(&mut *buf);
    ciphertext.extend_from_slice(&tag);
    Ok(SealedBox { kem_algorithm, suite, kem_ct, nonce, ciphertext })
}

fn open_with_key(key: &AeadKey, sealed: &SealedBox, aad: &[u8]) -> KemResult<Zeroizing<Vec<u8>>> {
    let split = sealed.ciphertext.len() - TAG_LEN; // validate() guaranteed >= TAG_LEN
    let (body, tag) = sealed.ciphertext.split_at(split);
    let aad_internal = internal_aad(&sealed.kem_ct, aad);

    let mut buf = Zeroizing::new(body.to_vec());
    match sealed.suite {
        AeadSuite::XChaCha20Poly1305 => XChaCha20Poly1305::new(Key::from_slice(&key.0))
            .decrypt_in_place_detached(XNonce::from_slice(&sealed.nonce), &aad_internal, &mut buf, Tag::from_slice(tag)),
        AeadSuite::ChaCha20Poly1305 => ChaCha20Poly1305::new(Key::from_slice(&key.0))
            .decrypt_in_place_detached(Nonce::from_slice(&sealed.nonce), &aad_internal, &mut buf, Tag::from_slice(tag)),
    }
    .map_err(|_| auth_failed())?;
    Ok(buf)
}
