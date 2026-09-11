//! Integration tests for the Hybrid X25519 + ML-KEM-768 KEM.
//!
//! Tests cover:
//! - Keygen → encapsulate → decapsulate roundtrip
//! - Shared secret equality between encapsulator and decapsulator
//! - HybridPublicKey JSON serialization roundtrip
//! - HybridKemCiphertext JSON serialization roundtrip
//! - encapsulate_to() convenience method
//! - Two different encapsulations produce different ciphertexts (randomness)
//! - Two different encapsulations produce different shared secrets

use pqc_kem::fips203::HybridKemKeypair;
use pqc_kem::types::{HybridKemCiphertext, HybridPublicKey};
use rand::rngs::OsRng;

// ── Roundtrip ─────────────────────────────────────────────────────────────────

#[test]
fn hybrid_kem_roundtrip() {
    let recipient = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");

    let x25519_pub = recipient.x25519_public_bytes();
    let mlkem_pub = recipient.mlkem_public_bytes();

    let (ct, sender_ss) = HybridKemKeypair::encapsulate(&mut OsRng, &x25519_pub, &mlkem_pub)
        .expect("encapsulate failed");

    let recipient_ss = recipient.decapsulate(&ct).expect("decapsulate failed");

    assert_eq!(
        sender_ss.bytes, recipient_ss.bytes,
        "hybrid KEM: shared secrets must match"
    );
}

#[test]
fn hybrid_kem_shared_secret_is_32_bytes() {
    let recipient = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let x25519_pub = recipient.x25519_public_bytes();
    let mlkem_pub = recipient.mlkem_public_bytes();

    let (ct, ss) = HybridKemKeypair::encapsulate(&mut OsRng, &x25519_pub, &mlkem_pub)
        .expect("encapsulate failed");
    let recovered = recipient.decapsulate(&ct).expect("decapsulate failed");

    assert_eq!(ss.bytes.len(), 32, "shared secret must be 32 bytes");
    assert_eq!(recovered.bytes.len(), 32, "recovered shared secret must be 32 bytes");
}

// ── encapsulate_to() convenience method ──────────────────────────────────────

#[test]
fn hybrid_kem_encapsulate_to_roundtrip() {
    let recipient = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let pub_key = recipient.public_key();

    let (ct, sender_ss) = HybridKemKeypair::encapsulate_to(&mut OsRng, &pub_key)
        .expect("encapsulate_to failed");

    let recipient_ss = recipient.decapsulate(&ct).expect("decapsulate failed");

    assert_eq!(
        sender_ss.bytes, recipient_ss.bytes,
        "encapsulate_to: shared secrets must match"
    );
}

#[test]
fn hybrid_kem_encapsulate_to_matches_encapsulate() {
    // Both encapsulate() and encapsulate_to() should produce valid ciphertexts
    // that the same recipient can decapsulate.
    let recipient = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let pub_key = recipient.public_key();

    let (ct_via_to, ss_via_to) = HybridKemKeypair::encapsulate_to(&mut OsRng, &pub_key)
        .expect("encapsulate_to failed");

    let x25519_pub = recipient.x25519_public_bytes();
    let mlkem_pub = recipient.mlkem_public_bytes();
    let (ct_direct, ss_direct) = HybridKemKeypair::encapsulate(&mut OsRng, &x25519_pub, &mlkem_pub)
        .expect("encapsulate failed");

    // Both should decapsulate successfully
    let recovered_via_to = recipient.decapsulate(&ct_via_to).expect("decapsulate via_to failed");
    let recovered_direct = recipient.decapsulate(&ct_direct).expect("decapsulate direct failed");

    assert_eq!(ss_via_to.bytes, recovered_via_to.bytes, "encapsulate_to roundtrip");
    assert_eq!(ss_direct.bytes, recovered_direct.bytes, "encapsulate direct roundtrip");
}

// ── Randomness: different encapsulations produce different outputs ─────────────

#[test]
fn hybrid_kem_two_encapsulations_produce_different_ciphertexts() {
    let recipient = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let pub_key = recipient.public_key();

    let (ct1, _) = HybridKemKeypair::encapsulate_to(&mut OsRng, &pub_key)
        .expect("encapsulate 1 failed");
    let (ct2, _) = HybridKemKeypair::encapsulate_to(&mut OsRng, &pub_key)
        .expect("encapsulate 2 failed");

    // The X25519 ephemeral keys should differ (different random ephemeral each time)
    assert_ne!(
        ct1.classical_ct, ct2.classical_ct,
        "two encapsulations must produce different X25519 ephemeral keys"
    );
}

#[test]
fn hybrid_kem_two_encapsulations_produce_different_shared_secrets() {
    let recipient = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let pub_key = recipient.public_key();

    let (_, ss1) = HybridKemKeypair::encapsulate_to(&mut OsRng, &pub_key)
        .expect("encapsulate 1 failed");
    let (_, ss2) = HybridKemKeypair::encapsulate_to(&mut OsRng, &pub_key)
        .expect("encapsulate 2 failed");

    assert_ne!(
        ss1.bytes, ss2.bytes,
        "two encapsulations must produce different shared secrets"
    );
}

// ── HybridPublicKey JSON serialization ───────────────────────────────────────

#[test]
fn hybrid_public_key_json_roundtrip() {
    let keypair = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let pub_key = keypair.public_key();

    let json = pub_key.to_json().expect("to_json failed");
    assert!(!json.is_empty(), "JSON must not be empty");

    let restored = HybridPublicKey::from_json(&json).expect("from_json failed");

    assert_eq!(pub_key, restored, "JSON roundtrip must preserve HybridPublicKey");
}

#[test]
fn hybrid_public_key_json_contains_expected_fields() {
    let keypair = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let pub_key = keypair.public_key();
    let json = pub_key.to_json().expect("to_json failed");

    assert!(json.contains("x25519_key"), "JSON must contain x25519_key field");
    assert!(json.contains("mlkem_key"), "JSON must contain mlkem_key field");
    assert!(json.contains("x25519_multibase"), "JSON must contain x25519_multibase field");
    assert!(json.contains("mlkem_multibase"), "JSON must contain mlkem_multibase field");
}

#[test]
fn hybrid_public_key_multibase_prefix() {
    let keypair = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let pub_key = keypair.public_key();

    assert!(
        pub_key.x25519_multibase.starts_with('z'),
        "x25519_multibase must start with 'z' (base58btc)"
    );
    assert!(
        pub_key.mlkem_multibase.starts_with('z'),
        "mlkem_multibase must start with 'z' (base58btc)"
    );
}

#[test]
fn hybrid_public_key_bytes_roundtrip() {
    let keypair = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let pub_key = keypair.public_key();

    let x25519_bytes = pub_key.x25519_bytes().expect("x25519_bytes failed");
    let mlkem_bytes = pub_key.mlkem_bytes().expect("mlkem_bytes failed");

    assert_eq!(x25519_bytes.len(), 32, "X25519 public key must be 32 bytes");
    assert_eq!(mlkem_bytes.len(), 1184, "ML-KEM-768 public key must be 1184 bytes");

    // Verify they match the raw bytes from the keypair
    assert_eq!(
        x25519_bytes,
        keypair.x25519_public_bytes().to_vec(),
        "x25519_bytes must match keypair x25519_public_bytes"
    );
    assert_eq!(
        mlkem_bytes,
        keypair.mlkem_public_bytes(),
        "mlkem_bytes must match keypair mlkem_public_bytes"
    );
}

// ── HybridKemCiphertext JSON serialization ────────────────────────────────────

#[test]
fn hybrid_ciphertext_json_roundtrip() {
    let recipient = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let pub_key = recipient.public_key();

    let (ct, _) = HybridKemKeypair::encapsulate_to(&mut OsRng, &pub_key)
        .expect("encapsulate failed");

    let json = ct.to_json().expect("to_json failed");
    assert!(!json.is_empty(), "JSON must not be empty");

    let restored = HybridKemCiphertext::from_json(&json).expect("from_json failed");

    assert_eq!(ct, restored, "JSON roundtrip must preserve HybridKemCiphertext");
}

#[test]
fn hybrid_ciphertext_json_contains_expected_fields() {
    let recipient = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let pub_key = recipient.public_key();
    let (ct, _) = HybridKemKeypair::encapsulate_to(&mut OsRng, &pub_key)
        .expect("encapsulate failed");

    let json = ct.to_json().expect("to_json failed");

    assert!(json.contains("classical_ct"), "JSON must contain classical_ct field");
    assert!(json.contains("pqc_ct"), "JSON must contain pqc_ct field");
    assert!(json.contains("algorithm"), "JSON must contain algorithm field");
    assert!(json.contains("X25519+ML-KEM-768"), "JSON must contain algorithm value");
}

#[test]
fn hybrid_ciphertext_bytes_sizes() {
    let recipient = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let pub_key = recipient.public_key();
    let (ct, _) = HybridKemKeypair::encapsulate_to(&mut OsRng, &pub_key)
        .expect("encapsulate failed");

    let x25519_bytes = ct.x25519_bytes().expect("x25519_bytes failed");
    let mlkem_bytes = ct.mlkem_bytes().expect("mlkem_bytes failed");

    assert_eq!(x25519_bytes.len(), 32, "X25519 ephemeral key must be 32 bytes");
    assert_eq!(mlkem_bytes.len(), 1088, "ML-KEM-768 ciphertext must be 1088 bytes");
}

#[test]
fn hybrid_ciphertext_deserialized_still_decapsulates() {
    let recipient = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let pub_key = recipient.public_key();

    let (ct, sender_ss) = HybridKemKeypair::encapsulate_to(&mut OsRng, &pub_key)
        .expect("encapsulate failed");

    // Serialize and deserialize the ciphertext
    let json = ct.to_json().expect("to_json failed");
    let ct_restored = HybridKemCiphertext::from_json(&json).expect("from_json failed");

    // Decapsulate with the restored ciphertext
    let recipient_ss = recipient.decapsulate(&ct_restored).expect("decapsulate failed");

    assert_eq!(
        sender_ss.bytes, recipient_ss.bytes,
        "deserialized ciphertext must still decapsulate correctly"
    );
}

// ── Secret key serialization roundtrip ───────────────────────────────────────

#[test]
#[allow(deprecated)] // x25519_secret_bytes/mlkem_secret_bytes deprecated since 0.3.0 — see tests/zeroize_tests.rs for the replacement accessors
fn hybrid_kem_secret_key_serialization_roundtrip() {
    let keypair = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");

    let x25519_secret = keypair.x25519_secret_bytes();
    let mlkem_secret = keypair.mlkem_secret_bytes();

    assert_eq!(x25519_secret.len(), 32, "X25519 secret must be 32 bytes");
    assert_eq!(mlkem_secret.len(), 64, "ML-KEM-768 seed must be 64 bytes");

    let restored = HybridKemKeypair::from_secret_key_bytes(&x25519_secret, &mlkem_secret)
        .expect("from_secret_key_bytes failed");

    // Restored keypair must have the same public key
    assert_eq!(
        keypair.public_key(),
        restored.public_key(),
        "restored keypair must have same public key"
    );

    // And must be able to decapsulate ciphertexts
    let pub_key = keypair.public_key();
    let (ct, sender_ss) = HybridKemKeypair::encapsulate_to(&mut OsRng, &pub_key)
        .expect("encapsulate failed");
    let recovered = restored.decapsulate(&ct).expect("decapsulate with restored keypair failed");

    assert_eq!(
        sender_ss.bytes, recovered.bytes,
        "restored keypair must recover same shared secret"
    );
}
