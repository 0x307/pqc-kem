//! Integration tests for ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
//!
//! Tests cover:
//! - Keygen → encapsulate → decapsulate roundtrip
//! - Shared secret equality between encapsulator and decapsulator
//! - Implicit rejection: wrong ciphertext produces different shared secret
//! - Public key base64url serialization roundtrip
//! - Public key multibase encoding roundtrip
//! - Secret key serialization roundtrip (from_secret_key_bytes)

use pqc_kem::fips203::{MlKem512Keypair, MlKem768Keypair, MlKem1024Keypair};
use pqc_kem::types::KemAlgorithm;
use rand::rngs::OsRng;

// ── ML-KEM-512 ────────────────────────────────────────────────────────────────

#[test]
fn ml_kem_512_roundtrip() {
    let keypair = MlKem512Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let (ct, sender_ss) = MlKem512Keypair::encapsulate(&mut OsRng, &pk)
        .expect("encapsulate failed");
    let recipient_ss = keypair.decapsulate(&ct).expect("decapsulate failed");

    assert_eq!(
        sender_ss.bytes, recipient_ss.bytes,
        "ML-KEM-512: shared secrets must match"
    );
}

#[test]
fn ml_kem_512_shared_secret_is_32_bytes() {
    let keypair = MlKem512Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let (ct, ss) = MlKem512Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    let recovered = keypair.decapsulate(&ct).expect("decapsulate failed");

    assert_eq!(ss.bytes.len(), 32, "shared secret must be 32 bytes");
    assert_eq!(recovered.bytes.len(), 32, "recovered shared secret must be 32 bytes");
}

#[test]
fn ml_kem_512_wrong_ciphertext_implicit_rejection() {
    // ML-KEM uses implicit rejection: decapsulating a wrong ciphertext returns
    // a deterministic but different shared secret (not an error).
    let keypair = MlKem512Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let (ct1, ss1) = MlKem512Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    let (ct2, _ss2) = MlKem512Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");

    // Decapsulate ct2 with the keypair that was used for ct1 — same keypair, different ct
    let recovered_from_ct1 = keypair.decapsulate(&ct1).expect("decapsulate ct1 failed");
    let recovered_from_ct2 = keypair.decapsulate(&ct2).expect("decapsulate ct2 failed");

    // The two ciphertexts should produce different shared secrets
    assert_ne!(
        recovered_from_ct1.bytes, recovered_from_ct2.bytes,
        "different ciphertexts must produce different shared secrets"
    );
    assert_eq!(
        ss1.bytes, recovered_from_ct1.bytes,
        "ct1 shared secret must match"
    );
}

#[test]
fn ml_kem_512_public_key_base64url_roundtrip() {
    let keypair = MlKem512Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let encoded = pk.to_base64url();
    let decoded = pqc_kem::types::KemPublicKey::from_base64url(KemAlgorithm::MlKem512, &encoded)
        .expect("base64url decode failed");

    assert_eq!(pk.bytes, decoded.bytes, "base64url roundtrip must preserve bytes");
    assert_eq!(pk.algorithm, decoded.algorithm, "base64url roundtrip must preserve algorithm");
}

#[test]
fn ml_kem_512_public_key_multibase_roundtrip() {
    let keypair = MlKem512Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let multibase = pk.to_multibase();
    assert!(multibase.starts_with('z'), "multibase must start with 'z' (base58btc)");

    let decoded = pqc_kem::types::KemPublicKey::from_multibase(KemAlgorithm::MlKem512, &multibase)
        .expect("multibase decode failed");

    assert_eq!(pk.bytes, decoded.bytes, "multibase roundtrip must preserve bytes");
}

#[test]
fn ml_kem_512_public_key_size() {
    let keypair = MlKem512Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    assert_eq!(pk.bytes.len(), 800, "ML-KEM-512 public key must be 800 bytes");
}

#[test]
fn ml_kem_512_secret_key_serialization_roundtrip() {
    let keypair = MlKem512Keypair::generate(&mut OsRng).expect("keygen failed");
    let sk = keypair.secret_key();

    // The seed is 64 bytes
    assert_eq!(sk.bytes.len(), 64, "ML-KEM-512 seed must be 64 bytes");

    // Restore keypair from seed
    let restored = MlKem512Keypair::from_secret_key_bytes(&sk.bytes)
        .expect("from_secret_key_bytes failed");

    // The restored keypair must produce the same public key
    assert_eq!(
        keypair.public_key().bytes,
        restored.public_key().bytes,
        "restored keypair must have same public key"
    );

    // And must be able to decapsulate ciphertexts from the original public key
    let pk = keypair.public_key();
    let (ct, sender_ss) = MlKem512Keypair::encapsulate(&mut OsRng, &pk)
        .expect("encapsulate failed");
    let recovered = restored.decapsulate(&ct).expect("decapsulate with restored keypair failed");
    assert_eq!(sender_ss.bytes, recovered.bytes, "restored keypair must recover same shared secret");
}

// ── ML-KEM-768 ────────────────────────────────────────────────────────────────

#[test]
fn ml_kem_768_roundtrip() {
    let keypair = MlKem768Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let (ct, sender_ss) = MlKem768Keypair::encapsulate(&mut OsRng, &pk)
        .expect("encapsulate failed");
    let recipient_ss = keypair.decapsulate(&ct).expect("decapsulate failed");

    assert_eq!(
        sender_ss.bytes, recipient_ss.bytes,
        "ML-KEM-768: shared secrets must match"
    );
}

#[test]
fn ml_kem_768_shared_secret_is_32_bytes() {
    let keypair = MlKem768Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let (ct, ss) = MlKem768Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    let recovered = keypair.decapsulate(&ct).expect("decapsulate failed");

    assert_eq!(ss.bytes.len(), 32, "shared secret must be 32 bytes");
    assert_eq!(recovered.bytes.len(), 32, "recovered shared secret must be 32 bytes");
}

#[test]
fn ml_kem_768_wrong_ciphertext_implicit_rejection() {
    let keypair = MlKem768Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let (ct1, ss1) = MlKem768Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    let (ct2, _ss2) = MlKem768Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");

    let recovered_from_ct1 = keypair.decapsulate(&ct1).expect("decapsulate ct1 failed");
    let recovered_from_ct2 = keypair.decapsulate(&ct2).expect("decapsulate ct2 failed");

    assert_ne!(
        recovered_from_ct1.bytes, recovered_from_ct2.bytes,
        "different ciphertexts must produce different shared secrets"
    );
    assert_eq!(ss1.bytes, recovered_from_ct1.bytes, "ct1 shared secret must match");
}

#[test]
fn ml_kem_768_public_key_base64url_roundtrip() {
    let keypair = MlKem768Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let encoded = pk.to_base64url();
    let decoded = pqc_kem::types::KemPublicKey::from_base64url(KemAlgorithm::MlKem768, &encoded)
        .expect("base64url decode failed");

    assert_eq!(pk.bytes, decoded.bytes, "base64url roundtrip must preserve bytes");
    assert_eq!(pk.algorithm, decoded.algorithm);
}

#[test]
fn ml_kem_768_public_key_multibase_roundtrip() {
    let keypair = MlKem768Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let multibase = pk.to_multibase();
    assert!(multibase.starts_with('z'), "multibase must start with 'z'");

    let decoded = pqc_kem::types::KemPublicKey::from_multibase(KemAlgorithm::MlKem768, &multibase)
        .expect("multibase decode failed");

    assert_eq!(pk.bytes, decoded.bytes, "multibase roundtrip must preserve bytes");
}

#[test]
fn ml_kem_768_public_key_size() {
    let keypair = MlKem768Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    assert_eq!(pk.bytes.len(), 1184, "ML-KEM-768 public key must be 1184 bytes");
}

#[test]
fn ml_kem_768_secret_key_serialization_roundtrip() {
    let keypair = MlKem768Keypair::generate(&mut OsRng).expect("keygen failed");
    let sk = keypair.secret_key();

    assert_eq!(sk.bytes.len(), 64, "ML-KEM-768 seed must be 64 bytes");

    let restored = MlKem768Keypair::from_secret_key_bytes(&sk.bytes)
        .expect("from_secret_key_bytes failed");

    assert_eq!(
        keypair.public_key().bytes,
        restored.public_key().bytes,
        "restored keypair must have same public key"
    );

    let pk = keypair.public_key();
    let (ct, sender_ss) = MlKem768Keypair::encapsulate(&mut OsRng, &pk)
        .expect("encapsulate failed");
    let recovered = restored.decapsulate(&ct).expect("decapsulate with restored keypair failed");
    assert_eq!(sender_ss.bytes, recovered.bytes, "restored keypair must recover same shared secret");
}

// ── ML-KEM-1024 ───────────────────────────────────────────────────────────────

#[test]
fn ml_kem_1024_roundtrip() {
    let keypair = MlKem1024Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let (ct, sender_ss) = MlKem1024Keypair::encapsulate(&mut OsRng, &pk)
        .expect("encapsulate failed");
    let recipient_ss = keypair.decapsulate(&ct).expect("decapsulate failed");

    assert_eq!(
        sender_ss.bytes, recipient_ss.bytes,
        "ML-KEM-1024: shared secrets must match"
    );
}

#[test]
fn ml_kem_1024_shared_secret_is_32_bytes() {
    let keypair = MlKem1024Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let (ct, ss) = MlKem1024Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    let recovered = keypair.decapsulate(&ct).expect("decapsulate failed");

    assert_eq!(ss.bytes.len(), 32, "shared secret must be 32 bytes");
    assert_eq!(recovered.bytes.len(), 32, "recovered shared secret must be 32 bytes");
}

#[test]
fn ml_kem_1024_wrong_ciphertext_implicit_rejection() {
    let keypair = MlKem1024Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let (ct1, ss1) = MlKem1024Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    let (ct2, _ss2) = MlKem1024Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");

    let recovered_from_ct1 = keypair.decapsulate(&ct1).expect("decapsulate ct1 failed");
    let recovered_from_ct2 = keypair.decapsulate(&ct2).expect("decapsulate ct2 failed");

    assert_ne!(
        recovered_from_ct1.bytes, recovered_from_ct2.bytes,
        "different ciphertexts must produce different shared secrets"
    );
    assert_eq!(ss1.bytes, recovered_from_ct1.bytes, "ct1 shared secret must match");
}

#[test]
fn ml_kem_1024_public_key_base64url_roundtrip() {
    let keypair = MlKem1024Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let encoded = pk.to_base64url();
    let decoded = pqc_kem::types::KemPublicKey::from_base64url(KemAlgorithm::MlKem1024, &encoded)
        .expect("base64url decode failed");

    assert_eq!(pk.bytes, decoded.bytes, "base64url roundtrip must preserve bytes");
    assert_eq!(pk.algorithm, decoded.algorithm);
}

#[test]
fn ml_kem_1024_public_key_multibase_roundtrip() {
    let keypair = MlKem1024Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let multibase = pk.to_multibase();
    assert!(multibase.starts_with('z'), "multibase must start with 'z'");

    let decoded = pqc_kem::types::KemPublicKey::from_multibase(KemAlgorithm::MlKem1024, &multibase)
        .expect("multibase decode failed");

    assert_eq!(pk.bytes, decoded.bytes, "multibase roundtrip must preserve bytes");
}

#[test]
fn ml_kem_1024_public_key_size() {
    let keypair = MlKem1024Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    assert_eq!(pk.bytes.len(), 1568, "ML-KEM-1024 public key must be 1568 bytes");
}

#[test]
fn ml_kem_1024_secret_key_serialization_roundtrip() {
    let keypair = MlKem1024Keypair::generate(&mut OsRng).expect("keygen failed");
    let sk = keypair.secret_key();

    assert_eq!(sk.bytes.len(), 64, "ML-KEM-1024 seed must be 64 bytes");

    let restored = MlKem1024Keypair::from_secret_key_bytes(&sk.bytes)
        .expect("from_secret_key_bytes failed");

    assert_eq!(
        keypair.public_key().bytes,
        restored.public_key().bytes,
        "restored keypair must have same public key"
    );

    let pk = keypair.public_key();
    let (ct, sender_ss) = MlKem1024Keypair::encapsulate(&mut OsRng, &pk)
        .expect("encapsulate failed");
    let recovered = restored.decapsulate(&ct).expect("decapsulate with restored keypair failed");
    assert_eq!(sender_ss.bytes, recovered.bytes, "restored keypair must recover same shared secret");
}

// ── Cross-algorithm rejection ─────────────────────────────────────────────────

#[test]
fn ml_kem_512_rejects_768_public_key() {
    let keypair768 = MlKem768Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk768 = keypair768.public_key();

    // Attempt to encapsulate with ML-KEM-512 using a ML-KEM-768 public key
    let result = MlKem512Keypair::encapsulate(&mut OsRng, &pk768);
    assert!(result.is_err(), "ML-KEM-512 must reject a ML-KEM-768 public key");
}

#[test]
fn ml_kem_768_rejects_512_public_key() {
    let keypair512 = MlKem512Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk512 = keypair512.public_key();

    let result = MlKem768Keypair::encapsulate(&mut OsRng, &pk512);
    assert!(result.is_err(), "ML-KEM-768 must reject a ML-KEM-512 public key");
}
