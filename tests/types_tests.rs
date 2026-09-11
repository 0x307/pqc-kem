//! Integration tests for wire types: KemAlgorithm, KemPublicKey, KemCiphertext,
//! SharedSecret, HybridKemCiphertext, HybridPublicKey.
//!
//! Tests cover:
//! - KemAlgorithm::as_str() for all variants
//! - KemAlgorithm size methods (public_key_size, ciphertext_size, shared_secret_size)
//! - KemPublicKey base64url encode/decode roundtrip
//! - KemPublicKey multibase encode/decode roundtrip
//! - HybridKemCiphertext JSON roundtrip
//! - HybridPublicKey JSON roundtrip
//! - SharedSecret zeroize (ZeroizeOnDrop is derived — compile-time guarantee)

use pqc_kem::types::{
    HybridKemCiphertext, HybridPublicKey, KemAlgorithm, KemCiphertext, KemPublicKey,
    KemSecretKey, SharedSecret,
};

// ── KemAlgorithm::as_str() ────────────────────────────────────────────────────

#[test]
fn kem_algorithm_as_str_ml_kem_512() {
    assert_eq!(KemAlgorithm::MlKem512.as_str(), "ML-KEM-512");
}

#[test]
fn kem_algorithm_as_str_ml_kem_768() {
    assert_eq!(KemAlgorithm::MlKem768.as_str(), "ML-KEM-768");
}

#[test]
fn kem_algorithm_as_str_ml_kem_1024() {
    assert_eq!(KemAlgorithm::MlKem1024.as_str(), "ML-KEM-1024");
}

#[test]
fn kem_algorithm_as_str_hybrid() {
    assert_eq!(KemAlgorithm::HybridX25519MlKem768.as_str(), "X25519+ML-KEM-768");
}

#[test]
fn kem_algorithm_as_str_hqc128() {
    assert_eq!(KemAlgorithm::Hqc128.as_str(), "HQC-128");
}

#[test]
fn kem_algorithm_as_str_hqc192() {
    assert_eq!(KemAlgorithm::Hqc192.as_str(), "HQC-192");
}

#[test]
fn kem_algorithm_as_str_hqc256() {
    assert_eq!(KemAlgorithm::Hqc256.as_str(), "HQC-256");
}

#[test]
#[allow(deprecated)] // KemAlgorithm::Bike deprecated since 0.3.0, removed in 0.4.0
fn kem_algorithm_as_str_bike() {
    assert_eq!(KemAlgorithm::Bike.as_str(), "BIKE");
}

#[test]
#[allow(deprecated)] // KemAlgorithm::ClassicMceliece deprecated since 0.3.0, removed in 0.4.0
fn kem_algorithm_as_str_classic_mceliece() {
    assert_eq!(KemAlgorithm::ClassicMceliece.as_str(), "Classic-McEliece");
}

// ── KemAlgorithm size methods ─────────────────────────────────────────────────

#[test]
#[allow(deprecated)] // KemAlgorithm::{Bike,ClassicMceliece} deprecated since 0.3.0, removed in 0.4.0
fn kem_algorithm_public_key_sizes() {
    assert_eq!(KemAlgorithm::MlKem512.public_key_size(), 800);
    assert_eq!(KemAlgorithm::MlKem768.public_key_size(), 1184);
    assert_eq!(KemAlgorithm::MlKem1024.public_key_size(), 1568);
    assert_eq!(KemAlgorithm::HybridX25519MlKem768.public_key_size(), 32 + 1184); // 1216
    assert_eq!(KemAlgorithm::Hqc128.public_key_size(), 2249);
    assert_eq!(KemAlgorithm::Hqc192.public_key_size(), 4522);
    assert_eq!(KemAlgorithm::Hqc256.public_key_size(), 7245);
    // BIKE and McEliece are variable (0). Both variants are deprecated since
    // 0.3.0 (never implemented; removed in 0.4.0) but still round-trip.
    assert_eq!(KemAlgorithm::Bike.public_key_size(), 0);
    assert_eq!(KemAlgorithm::ClassicMceliece.public_key_size(), 0);
}

#[test]
#[allow(deprecated)] // KemAlgorithm::{Bike,ClassicMceliece} deprecated since 0.3.0, removed in 0.4.0
fn kem_algorithm_ciphertext_sizes() {
    assert_eq!(KemAlgorithm::MlKem512.ciphertext_size(), 768);
    assert_eq!(KemAlgorithm::MlKem768.ciphertext_size(), 1088);
    assert_eq!(KemAlgorithm::MlKem1024.ciphertext_size(), 1568);
    assert_eq!(KemAlgorithm::HybridX25519MlKem768.ciphertext_size(), 32 + 1088); // 1120
    // HQC-128/256 corrected from 4481/14469 to 4433/14421 during the real
    // HQC implementation pass (P2/alpha-001) -- verified live against both
    // `pqcrypto-hqc` 0.2.2 and `liboqs` 0.13.0 (independent implementations
    // of the same NIST submission, which agree). HQC-192 was already
    // correct. See src/hqc/mod.rs module docs for the full explanation.
    assert_eq!(KemAlgorithm::Hqc128.ciphertext_size(), 4433);
    assert_eq!(KemAlgorithm::Hqc192.ciphertext_size(), 8978);
    assert_eq!(KemAlgorithm::Hqc256.ciphertext_size(), 14421);
    assert_eq!(KemAlgorithm::Bike.ciphertext_size(), 0);
    assert_eq!(KemAlgorithm::ClassicMceliece.ciphertext_size(), 0);
}

#[test]
#[allow(deprecated)] // KemAlgorithm::{Bike,ClassicMceliece} deprecated since 0.3.0, removed in 0.4.0
fn kem_algorithm_shared_secret_size_always_32() {
    // All algorithms return 32 bytes for the shared secret
    let algos = [
        KemAlgorithm::MlKem512,
        KemAlgorithm::MlKem768,
        KemAlgorithm::MlKem1024,
        KemAlgorithm::HybridX25519MlKem768,
        KemAlgorithm::Hqc128,
        KemAlgorithm::Hqc192,
        KemAlgorithm::Hqc256,
        KemAlgorithm::Bike,
        KemAlgorithm::ClassicMceliece,
    ];
    for algo in &algos {
        assert_eq!(algo.shared_secret_size(), 32, "{} shared secret must be 32 bytes", algo.as_str());
    }
}

// ── KemPublicKey base64url roundtrip ──────────────────────────────────────────

#[test]
fn kem_public_key_base64url_roundtrip() {
    let raw_bytes = vec![0xAB_u8; 800]; // 800 bytes for ML-KEM-512
    let pk = KemPublicKey::new(KemAlgorithm::MlKem512, raw_bytes.clone());

    let encoded = pk.to_base64url();
    assert!(!encoded.is_empty(), "base64url must not be empty");

    let decoded = KemPublicKey::from_base64url(KemAlgorithm::MlKem512, &encoded)
        .expect("from_base64url failed");

    assert_eq!(decoded.bytes, raw_bytes, "base64url roundtrip must preserve bytes");
    assert_eq!(decoded.algorithm, KemAlgorithm::MlKem512);
}

#[test]
fn kem_public_key_base64url_invalid_input() {
    let result = KemPublicKey::from_base64url(KemAlgorithm::MlKem512, "not!valid!base64url!!!");
    assert!(result.is_err(), "invalid base64url must return error");
}

// ── KemPublicKey multibase roundtrip ─────────────────────────────────────────

#[test]
fn kem_public_key_multibase_roundtrip() {
    let raw_bytes = vec![0xCD_u8; 1184]; // 1184 bytes for ML-KEM-768
    let pk = KemPublicKey::new(KemAlgorithm::MlKem768, raw_bytes.clone());

    let multibase = pk.to_multibase();
    assert!(multibase.starts_with('z'), "multibase must start with 'z' (base58btc)");
    assert!(multibase.len() > 1, "multibase must have content after prefix");

    let decoded = KemPublicKey::from_multibase(KemAlgorithm::MlKem768, &multibase)
        .expect("from_multibase failed");

    assert_eq!(decoded.bytes, raw_bytes, "multibase roundtrip must preserve bytes");
    assert_eq!(decoded.algorithm, KemAlgorithm::MlKem768);
}

#[test]
fn kem_public_key_multibase_wrong_prefix() {
    // Multibase without 'z' prefix must fail
    let result = KemPublicKey::from_multibase(KemAlgorithm::MlKem512, "mSomeBase64");
    assert!(result.is_err(), "multibase without 'z' prefix must return error");
}

#[test]
fn kem_public_key_multibase_empty_prefix_only() {
    // Just 'z' with no content — bs58 decode of empty string should succeed (empty bytes)
    // but let's verify it doesn't panic
    let result = KemPublicKey::from_multibase(KemAlgorithm::MlKem512, "z");
    // This may succeed with empty bytes or fail — either is acceptable, just no panic
    let _ = result;
}

// ── KemPublicKey JSON serialization (via serde) ───────────────────────────────

#[test]
fn kem_public_key_json_roundtrip() {
    let raw_bytes = vec![0x42_u8; 800];
    let pk = KemPublicKey::new(KemAlgorithm::MlKem512, raw_bytes.clone());

    let json = serde_json::to_string(&pk).expect("serde_json::to_string failed");
    assert!(!json.is_empty());

    let restored: KemPublicKey = serde_json::from_str(&json).expect("serde_json::from_str failed");
    assert_eq!(restored.bytes, raw_bytes);
    assert_eq!(restored.algorithm, KemAlgorithm::MlKem512);
}

// ── KemCiphertext ─────────────────────────────────────────────────────────────

#[test]
fn kem_ciphertext_base64url_roundtrip() {
    let raw_bytes = vec![0x77_u8; 768]; // 768 bytes for ML-KEM-512 ciphertext
    let ct = KemCiphertext::new(KemAlgorithm::MlKem512, raw_bytes.clone());

    let encoded = ct.to_base64url();
    assert!(!encoded.is_empty(), "base64url must not be empty");

    let decoded = KemCiphertext::from_base64url(KemAlgorithm::MlKem512, &encoded)
        .expect("from_base64url failed");

    assert_eq!(decoded.bytes, raw_bytes, "base64url roundtrip must preserve bytes");
    assert_eq!(decoded.algorithm, KemAlgorithm::MlKem512);
}

#[test]
fn kem_ciphertext_json_roundtrip() {
    let raw_bytes = vec![0x55_u8; 1088];
    let ct = KemCiphertext::new(KemAlgorithm::MlKem768, raw_bytes.clone());

    let json = serde_json::to_string(&ct).expect("serde_json::to_string failed");
    let restored: KemCiphertext = serde_json::from_str(&json).expect("serde_json::from_str failed");

    assert_eq!(restored.bytes, raw_bytes);
    assert_eq!(restored.algorithm, KemAlgorithm::MlKem768);
}

// ── SharedSecret ──────────────────────────────────────────────────────────────

#[test]
fn shared_secret_as_32_bytes() {
    let ss = SharedSecret::new(vec![0xAA_u8; 32]);
    let arr = ss.as_32_bytes().expect("as_32_bytes failed");
    assert_eq!(arr, [0xAA_u8; 32]);
}

#[test]
fn shared_secret_as_32_bytes_wrong_size() {
    let ss = SharedSecret::new(vec![0x01_u8; 16]); // wrong size
    let result = ss.as_32_bytes();
    assert!(result.is_err(), "as_32_bytes must fail for non-32-byte secret");
}

#[test]
fn shared_secret_zeroize_on_drop() {
    // ZeroizeOnDrop is a compile-time derive — we verify the type implements it
    // by checking that SharedSecret: zeroize::ZeroizeOnDrop (trait bound).
    // This is a compile-time test: if SharedSecret doesn't derive ZeroizeOnDrop,
    // this function won't compile.
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<SharedSecret>();
}

#[test]
fn kem_secret_key_zeroize_on_drop() {
    // Same compile-time check for KemSecretKey
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<KemSecretKey>();
}

// ── HybridKemCiphertext JSON roundtrip ───────────────────────────────────────

#[test]
fn hybrid_kem_ciphertext_json_roundtrip() {
    let ct = HybridKemCiphertext::new(
        &[0x11_u8; 32],   // X25519 ephemeral public key (32 bytes)
        &[0x22_u8; 1088], // ML-KEM-768 ciphertext (1088 bytes)
    );

    let json = ct.to_json().expect("to_json failed");
    assert!(!json.is_empty());
    assert!(json.contains("X25519+ML-KEM-768"), "JSON must contain algorithm");

    let restored = HybridKemCiphertext::from_json(&json).expect("from_json failed");
    assert_eq!(ct, restored, "JSON roundtrip must preserve HybridKemCiphertext");
}

#[test]
fn hybrid_kem_ciphertext_bytes_decode() {
    let x25519_raw = [0xAB_u8; 32];
    let mlkem_raw = vec![0xCD_u8; 1088];

    let ct = HybridKemCiphertext::new(&x25519_raw, &mlkem_raw);

    let x25519_decoded = ct.x25519_bytes().expect("x25519_bytes failed");
    let mlkem_decoded = ct.mlkem_bytes().expect("mlkem_bytes failed");

    assert_eq!(x25519_decoded, x25519_raw.to_vec());
    assert_eq!(mlkem_decoded, mlkem_raw);
}

#[test]
fn hybrid_kem_ciphertext_algorithm_field() {
    let ct = HybridKemCiphertext::new(&[0u8; 32], &[0u8; 1088]);
    assert_eq!(ct.algorithm, "X25519+ML-KEM-768");
}

// ── HybridPublicKey JSON roundtrip ────────────────────────────────────────────

#[test]
fn hybrid_public_key_json_roundtrip() {
    let pk = HybridPublicKey::new(
        &[0x33_u8; 32],   // X25519 public key (32 bytes)
        &[0x44_u8; 1184], // ML-KEM-768 public key (1184 bytes)
    );

    let json = pk.to_json().expect("to_json failed");
    assert!(!json.is_empty());

    let restored = HybridPublicKey::from_json(&json).expect("from_json failed");
    assert_eq!(pk, restored, "JSON roundtrip must preserve HybridPublicKey");
}

#[test]
fn hybrid_public_key_bytes_decode() {
    let x25519_raw = [0xEF_u8; 32];
    let mlkem_raw = vec![0x12_u8; 1184];

    let pk = HybridPublicKey::new(&x25519_raw, &mlkem_raw);

    let x25519_decoded = pk.x25519_bytes().expect("x25519_bytes failed");
    let mlkem_decoded = pk.mlkem_bytes().expect("mlkem_bytes failed");

    assert_eq!(x25519_decoded, x25519_raw.to_vec());
    assert_eq!(mlkem_decoded, mlkem_raw);
}

#[test]
fn hybrid_public_key_multibase_fields() {
    let pk = HybridPublicKey::new(&[0x55_u8; 32], &[0x66_u8; 1184]);

    assert!(pk.x25519_multibase.starts_with('z'), "x25519_multibase must start with 'z'");
    assert!(pk.mlkem_multibase.starts_with('z'), "mlkem_multibase must start with 'z'");
}

#[test]
fn hybrid_public_key_invalid_json() {
    let result = HybridPublicKey::from_json("not valid json {{{");
    assert!(result.is_err(), "invalid JSON must return error");
}

#[test]
fn hybrid_kem_ciphertext_invalid_json() {
    let result = HybridKemCiphertext::from_json("not valid json {{{");
    assert!(result.is_err(), "invalid JSON must return error");
}

// ── KemAlgorithm serde roundtrip ──────────────────────────────────────────────

#[test]
fn kem_algorithm_serde_roundtrip() {
    let algos = [
        KemAlgorithm::MlKem512,
        KemAlgorithm::MlKem768,
        KemAlgorithm::MlKem1024,
        KemAlgorithm::HybridX25519MlKem768,
    ];

    for algo in &algos {
        let json = serde_json::to_string(algo).expect("serialize failed");
        let restored: KemAlgorithm = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(*algo, restored, "serde roundtrip must preserve KemAlgorithm");
    }
}
