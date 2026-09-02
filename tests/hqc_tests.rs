//! Integration tests for HQC-128, HQC-192, and HQC-256 (`hqc` feature).
//!
//! Tests cover:
//! - Keygen → encapsulate → decapsulate roundtrip, per parameter set
//! - Shared secret equality between encapsulator and decapsulator
//! - Shared secret is truncated to this crate's uniform 32 bytes
//! - Two encapsulations to the same key produce different ciphertexts/secrets
//! - Decapsulating with the wrong secret key returns `Err`, never panics
//!   (this is the property that ruled out `pqcrypto-hqc` as the dependency —
//!   see `src/hqc/mod.rs` module docs and `CHANGELOG.md` for why)
//! - Malformed (wrong-length) ciphertext/key bytes return `Err`, never panic
//!
//! No bit-flip-of-a-valid-ciphertext test is included on purpose: that
//! exercises the exact same underlying "ciphertext doesn't match this secret
//! key" path as the wrong-secret-key test below (both fail the KEM's
//! internal re-encryption check), so it would not add coverage — and this
//! crate's own `[profile.dev]`/`[profile.release]` set `panic = "abort"`
//! (required by the no_std/WASM build path), under which a `#[should_panic]`
//! test would abort the whole test binary rather than being caught, per the
//! same rationale already documented in `Cargo.toml`.

#![cfg(feature = "hqc")]

use pqc_kem::hqc::{Hqc128Keypair, Hqc192Keypair, Hqc256Keypair};
use pqc_kem::types::KemAlgorithm;
use rand::rngs::OsRng;

// ── HQC-128 ───────────────────────────────────────────────────────────────────

#[test]
fn hqc_128_roundtrip() {
    let keypair = Hqc128Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let (ct, sender_ss) = Hqc128Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    let recipient_ss = keypair.decapsulate(&ct).expect("decapsulate failed");

    assert_eq!(sender_ss.bytes, recipient_ss.bytes, "HQC-128: shared secrets must match");
}

#[test]
fn hqc_128_shared_secret_is_32_bytes() {
    let keypair = Hqc128Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let (ct, ss) = Hqc128Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    let recovered = keypair.decapsulate(&ct).expect("decapsulate failed");

    assert_eq!(ss.bytes.len(), 32, "shared secret must be truncated to 32 bytes");
    assert_eq!(recovered.bytes.len(), 32, "recovered shared secret must be 32 bytes");
}

#[test]
fn hqc_128_public_key_size() {
    let keypair = Hqc128Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    assert_eq!(pk.bytes.len(), 2249, "HQC-128 public key must be 2249 bytes");
    assert_eq!(pk.bytes.len(), KemAlgorithm::Hqc128.public_key_size());
}

#[test]
fn hqc_128_ciphertext_size() {
    let keypair = Hqc128Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let (ct, _ss) = Hqc128Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    assert_eq!(ct.bytes.len(), 4433, "HQC-128 ciphertext must be 4433 bytes (corrected from 4481)");
    assert_eq!(ct.bytes.len(), KemAlgorithm::Hqc128.ciphertext_size());
}

#[test]
fn hqc_128_two_encapsulations_differ() {
    let keypair = Hqc128Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let (ct1, ss1) = Hqc128Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    let (ct2, ss2) = Hqc128Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");

    assert_ne!(ct1.bytes, ct2.bytes, "two encapsulations must produce different ciphertexts");
    assert_ne!(ss1.bytes, ss2.bytes, "two encapsulations must produce different shared secrets");

    let recovered1 = keypair.decapsulate(&ct1).expect("decapsulate ct1 failed");
    let recovered2 = keypair.decapsulate(&ct2).expect("decapsulate ct2 failed");
    assert_eq!(ss1.bytes, recovered1.bytes);
    assert_eq!(ss2.bytes, recovered2.bytes);
}

#[test]
fn hqc_128_wrong_secret_key_errors_not_panics() {
    // Verified live during implementation: this is exactly the case that
    // panics/aborts the process via `pqcrypto-hqc` 0.2.2's decapsulate(), and
    // is the reason this crate uses `liboqs` (`oqs` crate) instead. A
    // ciphertext encapsulated to keypair A's public key, decapsulated with
    // keypair B's unrelated secret key, must return `Err`, never panic.
    let recipient = Hqc128Keypair::generate(&mut OsRng).expect("keygen (recipient) failed");
    let attacker = Hqc128Keypair::generate(&mut OsRng).expect("keygen (attacker) failed");

    let pk = recipient.public_key();
    let (ct, _ss) = Hqc128Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");

    let result = attacker.decapsulate(&ct);
    assert!(result.is_err(), "decapsulating with the wrong secret key must return Err, not panic");
}

#[test]
fn hqc_128_malformed_ciphertext_bytes_errors_not_panics() {
    let keypair = Hqc128Keypair::generate(&mut OsRng).expect("keygen failed");
    let bad_ct = pqc_kem::types::KemCiphertext::new(KemAlgorithm::Hqc128, vec![0u8; 10]);
    let result = keypair.decapsulate(&bad_ct);
    assert!(result.is_err(), "wrong-length ciphertext must return Err, not panic");
}

#[test]
fn hqc_128_wrong_algorithm_tag_rejected() {
    // No keypair needed: encapsulate() is an associated function that only
    // inspects the recipient public key's algorithm tag before ever
    // touching liboqs.
    let wrong_pk = pqc_kem::types::KemPublicKey::new(KemAlgorithm::Hqc192, vec![0u8; 4522]);
    let result = Hqc128Keypair::encapsulate(&mut OsRng, &wrong_pk);
    assert!(result.is_err(), "encapsulating to a mislabeled algorithm tag must be rejected");
}

// ── HQC-192 ───────────────────────────────────────────────────────────────────

#[test]
fn hqc_192_roundtrip() {
    let keypair = Hqc192Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let (ct, sender_ss) = Hqc192Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    let recipient_ss = keypair.decapsulate(&ct).expect("decapsulate failed");

    assert_eq!(sender_ss.bytes, recipient_ss.bytes, "HQC-192: shared secrets must match");
}

#[test]
fn hqc_192_shared_secret_is_32_bytes() {
    let keypair = Hqc192Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let (ct, ss) = Hqc192Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    let recovered = keypair.decapsulate(&ct).expect("decapsulate failed");

    assert_eq!(ss.bytes.len(), 32);
    assert_eq!(recovered.bytes.len(), 32);
}

#[test]
fn hqc_192_public_key_and_ciphertext_size() {
    let keypair = Hqc192Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    assert_eq!(pk.bytes.len(), 4522, "HQC-192 public key must be 4522 bytes");
    assert_eq!(pk.bytes.len(), KemAlgorithm::Hqc192.public_key_size());

    let (ct, _ss) = Hqc192Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    assert_eq!(ct.bytes.len(), 8978, "HQC-192 ciphertext must be 8978 bytes (unchanged)");
    assert_eq!(ct.bytes.len(), KemAlgorithm::Hqc192.ciphertext_size());
}

#[test]
fn hqc_192_wrong_secret_key_errors_not_panics() {
    let recipient = Hqc192Keypair::generate(&mut OsRng).expect("keygen (recipient) failed");
    let attacker = Hqc192Keypair::generate(&mut OsRng).expect("keygen (attacker) failed");

    let pk = recipient.public_key();
    let (ct, _ss) = Hqc192Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");

    let result = attacker.decapsulate(&ct);
    assert!(result.is_err(), "decapsulating with the wrong secret key must return Err, not panic");
}

// ── HQC-256 ───────────────────────────────────────────────────────────────────

#[test]
fn hqc_256_roundtrip() {
    let keypair = Hqc256Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let (ct, sender_ss) = Hqc256Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    let recipient_ss = keypair.decapsulate(&ct).expect("decapsulate failed");

    assert_eq!(sender_ss.bytes, recipient_ss.bytes, "HQC-256: shared secrets must match");
}

#[test]
fn hqc_256_shared_secret_is_32_bytes() {
    let keypair = Hqc256Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let (ct, ss) = Hqc256Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    let recovered = keypair.decapsulate(&ct).expect("decapsulate failed");

    assert_eq!(ss.bytes.len(), 32);
    assert_eq!(recovered.bytes.len(), 32);
}

#[test]
fn hqc_256_public_key_and_ciphertext_size() {
    let keypair = Hqc256Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    assert_eq!(pk.bytes.len(), 7245, "HQC-256 public key must be 7245 bytes");
    assert_eq!(pk.bytes.len(), KemAlgorithm::Hqc256.public_key_size());

    let (ct, _ss) = Hqc256Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    assert_eq!(ct.bytes.len(), 14421, "HQC-256 ciphertext must be 14421 bytes (corrected from 14469)");
    assert_eq!(ct.bytes.len(), KemAlgorithm::Hqc256.ciphertext_size());
}

#[test]
fn hqc_256_wrong_secret_key_errors_not_panics() {
    let recipient = Hqc256Keypair::generate(&mut OsRng).expect("keygen (recipient) failed");
    let attacker = Hqc256Keypair::generate(&mut OsRng).expect("keygen (attacker) failed");

    let pk = recipient.public_key();
    let (ct, _ss) = Hqc256Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");

    let result = attacker.decapsulate(&ct);
    assert!(result.is_err(), "decapsulating with the wrong secret key must return Err, not panic");
}
