//! Tests for the `aead-wrap` feature: KEM shared secret -> HKDF-SHA256 -> AEAD.
//!
//! Declared in Cargo.toml with `required-features = ["aead-wrap"]`, so cargo
//! does not build this file at all without the feature, rather than building
//! an empty binary that reports success.

use pqc_kem::aead_wrap::{
    derive_aead_key, open_hybrid, open_ml_kem_768, seal_hybrid, seal_hybrid_with_suite, seal_ml_kem_768,
    seal_ml_kem_768_with_suite, AeadSuite, SealedBox, AEAD_WRAP_INFO_V1,
};
use pqc_kem::types::{KemAlgorithm, KemPublicKey, SharedSecret};
use pqc_kem::{HybridKemKeypair, KemError, MlKem768Keypair};
use rand::rngs::OsRng;

const CTX: &[u8] = b"test-protocol-v1";
const AAD: &[u8] = b"header: v1";
const MSG: &[u8] = b"a payload that only the recipient can read";

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd-length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn alg_from_name(name: &str) -> KemAlgorithm {
    match name {
        "ML-KEM-768" => KemAlgorithm::MlKem768,
        "X25519+ML-KEM-768" => KemAlgorithm::HybridX25519MlKem768,
        other => panic!("vector names an algorithm this test does not map: {other}"),
    }
}

fn is_auth_failure(e: &KemError) -> bool {
    matches!(e, KemError::SymmetricCipher(_))
}

fn is_structural(e: &KemError) -> bool {
    matches!(e, KemError::InvalidCiphertext(_))
}

// ── key derivation ──────────────────────────────────────────────────────────

/// Frozen vectors computed by an independent HKDF-SHA256 implementation
/// (Python standard library, RFC 5869), not by this crate. See the file's
/// `provenance` field.
#[test]
fn derive_aead_key_matches_independent_vectors() {
    let doc: serde_json::Value =
        serde_json::from_str(include_str!("vectors/aead_wrap_v1.json")).expect("vector file parses");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(vectors.len() >= 5, "expected at least 5 vectors, found {}", vectors.len());

    for (i, v) in vectors.iter().enumerate() {
        let ss = SharedSecret::new(hex(v["ss"].as_str().unwrap()));
        let alg = alg_from_name(v["kem_algorithm"].as_str().unwrap());
        let ctx = hex(v["context"].as_str().unwrap());
        let want = hex(v["key"].as_str().unwrap());
        let got = derive_aead_key(&ss, alg, &ctx).expect("derive");
        assert_eq!(got.0.to_vec(), want, "vector {i} ({}): key mismatch", v["description"]);
    }
}

/// The derivation, recomputed from its documented formula with the `hkdf`
/// crate directly, so the formula in the docs and the code cannot drift.
#[test]
fn derive_aead_key_matches_its_documented_formula() {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let ss = SharedSecret::new((0u8..32).collect());
    let mut info = AEAD_WRAP_INFO_V1.to_vec();
    info.push(0);
    info.extend_from_slice(b"ML-KEM-768");
    info.push(0);
    info.extend_from_slice(CTX);
    let mut want = [0u8; 32];
    Hkdf::<Sha256>::new(None, &ss.bytes).expand(&info, &mut want).unwrap();

    assert_eq!(derive_aead_key(&ss, KemAlgorithm::MlKem768, CTX).unwrap().0, want);
}

/// RFC 5869 Appendix A.1, through the same `hkdf` crate the module uses.
#[test]
fn hkdf_sha256_passes_rfc5869_test_case_1() {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut okm = [0u8; 42];
    Hkdf::<Sha256>::new(Some(&hex("000102030405060708090a0b0c")), &hex(&"0b".repeat(22)))
        .expand(&hex("f0f1f2f3f4f5f6f7f8f9"), &mut okm)
        .unwrap();
    assert_eq!(
        okm.to_vec(),
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );
}

#[test]
fn suite_wire_names_are_the_ones_people_write() {
    assert_eq!(serde_json::to_string(&AeadSuite::XChaCha20Poly1305).unwrap(), "\"xchacha20-poly1305\"");
    assert_eq!(serde_json::to_string(&AeadSuite::ChaCha20Poly1305).unwrap(), "\"chacha20-poly1305\"");
}

#[test]
fn keys_are_separated_by_context_and_by_algorithm() {
    let ss = SharedSecret::new((0u8..32).collect());
    let a = derive_aead_key(&ss, KemAlgorithm::MlKem768, b"protocol-a").unwrap().0;
    let b = derive_aead_key(&ss, KemAlgorithm::MlKem768, b"protocol-b").unwrap().0;
    let h = derive_aead_key(&ss, KemAlgorithm::HybridX25519MlKem768, b"protocol-a").unwrap().0;
    assert_ne!(a, b, "different contexts must give different keys");
    assert_ne!(a, h, "different KEMs must give different keys for the same secret");
}

// ── round trips ─────────────────────────────────────────────────────────────

#[test]
fn ml_kem_768_round_trips_under_both_suites() {
    let kp = MlKem768Keypair::generate(&mut OsRng).unwrap();
    for suite in [AeadSuite::XChaCha20Poly1305, AeadSuite::ChaCha20Poly1305] {
        let sealed = seal_ml_kem_768_with_suite(&mut OsRng, suite, &kp.public_key(), CTX, AAD, MSG).unwrap();
        assert_eq!(sealed.suite, suite);
        assert_eq!(sealed.kem_algorithm, KemAlgorithm::MlKem768);
        assert_eq!(sealed.kem_ct.len(), 1088);
        assert_eq!(sealed.nonce.len(), suite.nonce_len());
        assert_eq!(sealed.ciphertext.len(), MSG.len() + 16);
        let opened = open_ml_kem_768(&kp, &sealed, CTX, AAD).unwrap();
        assert_eq!(opened.as_slice(), MSG, "{suite:?}");
    }
}

#[test]
fn hybrid_round_trips_under_both_suites() {
    let kp = HybridKemKeypair::generate(&mut OsRng).unwrap();
    for suite in [AeadSuite::XChaCha20Poly1305, AeadSuite::ChaCha20Poly1305] {
        let sealed = seal_hybrid_with_suite(&mut OsRng, suite, &kp.public_key(), CTX, AAD, MSG).unwrap();
        assert_eq!(sealed.kem_algorithm, KemAlgorithm::HybridX25519MlKem768);
        assert_eq!(sealed.kem_ct.len(), 1120);
        let opened = open_hybrid(&kp, &sealed, CTX, AAD).unwrap();
        assert_eq!(opened.as_slice(), MSG, "{suite:?}");
    }
}

#[test]
fn the_default_suite_is_xchacha20() {
    let kp = MlKem768Keypair::generate(&mut OsRng).unwrap();
    let hk = HybridKemKeypair::generate(&mut OsRng).unwrap();
    assert_eq!(seal_ml_kem_768(&mut OsRng, &kp.public_key(), CTX, AAD, MSG).unwrap().suite, AeadSuite::XChaCha20Poly1305);
    assert_eq!(seal_hybrid(&mut OsRng, &hk.public_key(), CTX, AAD, MSG).unwrap().suite, AeadSuite::XChaCha20Poly1305);
}

#[test]
fn empty_plaintext_round_trips() {
    let kp = MlKem768Keypair::generate(&mut OsRng).unwrap();
    let sealed = seal_ml_kem_768(&mut OsRng, &kp.public_key(), CTX, AAD, b"").unwrap();
    assert_eq!(sealed.ciphertext.len(), 16, "an empty payload is just the tag");
    assert!(open_ml_kem_768(&kp, &sealed, CTX, AAD).unwrap().is_empty());
}

#[test]
fn two_seals_of_the_same_message_differ() {
    let kp = MlKem768Keypair::generate(&mut OsRng).unwrap();
    let a = seal_ml_kem_768(&mut OsRng, &kp.public_key(), CTX, AAD, MSG).unwrap();
    let b = seal_ml_kem_768(&mut OsRng, &kp.public_key(), CTX, AAD, MSG).unwrap();
    assert_ne!(a.kem_ct, b.kem_ct, "each seal must encapsulate afresh");
    assert_ne!(a.ciphertext, b.ciphertext);
}

#[test]
fn sealed_box_survives_a_json_round_trip() {
    let kp = HybridKemKeypair::generate(&mut OsRng).unwrap();
    let sealed = seal_hybrid(&mut OsRng, &kp.public_key(), CTX, AAD, MSG).unwrap();
    let json = serde_json::to_string(&sealed).unwrap();
    assert!(json.contains("\"suite\":\"xchacha20-poly1305\""), "wire name for the default suite: {json}");
    let back: SealedBox = serde_json::from_str(&json).unwrap();
    assert_eq!(back, sealed);
    assert_eq!(open_hybrid(&kp, &back, CTX, AAD).unwrap().as_slice(), MSG);
}

// ── tampering: every one must fail, and fail as an authentication failure ──

/// One way of corrupting a sealed box.
type Tamper = fn(&mut SealedBox);

fn sealed_768() -> (MlKem768Keypair, SealedBox) {
    let kp = MlKem768Keypair::generate(&mut OsRng).unwrap();
    let sealed = seal_ml_kem_768(&mut OsRng, &kp.public_key(), CTX, AAD, MSG).unwrap();
    (kp, sealed)
}

#[test]
fn tampering_with_any_part_fails_to_open() {
    let (kp, sealed) = sealed_768();
    let cases: [(&str, Tamper); 4] = [
        ("body", |s| s.ciphertext[0] ^= 1),
        ("tag", |s| {
            let n = s.ciphertext.len();
            s.ciphertext[n - 1] ^= 1
        }),
        ("nonce", |s| s.nonce[0] ^= 1),
        ("kem ciphertext", |s| s.kem_ct[0] ^= 1),
    ];
    for (what, tamper) in cases {
        let mut bad = sealed.clone();
        tamper(&mut bad);
        let err = open_ml_kem_768(&kp, &bad, CTX, AAD).expect_err(what);
        assert!(is_auth_failure(&err), "{what}: expected SymmetricCipher, got {err:?}");
    }
    // The untouched box still opens, so the failures above are the tampering.
    assert_eq!(open_ml_kem_768(&kp, &sealed, CTX, AAD).unwrap().as_slice(), MSG);
}

#[test]
fn wrong_context_or_aad_fails_to_open() {
    let (kp, sealed) = sealed_768();
    assert!(is_auth_failure(&open_ml_kem_768(&kp, &sealed, b"other-protocol-v1", AAD).unwrap_err()));
    assert!(is_auth_failure(&open_ml_kem_768(&kp, &sealed, CTX, b"header: v2").unwrap_err()));
}

#[test]
fn the_wrong_recipient_cannot_open() {
    let (_, sealed) = sealed_768();
    let stranger = MlKem768Keypair::generate(&mut OsRng).unwrap();
    assert!(is_auth_failure(&open_ml_kem_768(&stranger, &sealed, CTX, AAD).unwrap_err()));

    let hk = HybridKemKeypair::generate(&mut OsRng).unwrap();
    let hsealed = seal_hybrid(&mut OsRng, &hk.public_key(), CTX, AAD, MSG).unwrap();
    let hstranger = HybridKemKeypair::generate(&mut OsRng).unwrap();
    assert!(is_auth_failure(&open_hybrid(&hstranger, &hsealed, CTX, AAD).unwrap_err()));
}

/// The no-oracle property. A tampered KEM ciphertext goes through ML-KEM's
/// implicit rejection and becomes a wrong key; a tampered tag is a failed
/// AEAD check. An attacker must not be able to tell those apart, so they
/// must fail identically -- same variant *and* same message.
#[test]
fn a_bad_kem_ciphertext_and_a_bad_tag_are_indistinguishable() {
    let (kp, sealed) = sealed_768();
    let mut bad_kem = sealed.clone();
    bad_kem.kem_ct[100] ^= 1;
    let mut bad_tag = sealed.clone();
    let n = bad_tag.ciphertext.len();
    bad_tag.ciphertext[n - 1] ^= 1;

    let e1 = open_ml_kem_768(&kp, &bad_kem, CTX, AAD).unwrap_err();
    let e2 = open_ml_kem_768(&kp, &bad_tag, CTX, AAD).unwrap_err();
    assert_eq!(e1.to_string(), e2.to_string(), "the two failures must be indistinguishable");
}

// ── structural checks: public facts, reported precisely, before any crypto ──

#[test]
fn malformed_boxes_are_rejected_before_any_cryptography() {
    let (kp, sealed) = sealed_768();

    let mut wrong_alg = sealed.clone();
    wrong_alg.kem_algorithm = KemAlgorithm::HybridX25519MlKem768;
    assert!(is_structural(&open_ml_kem_768(&kp, &wrong_alg, CTX, AAD).unwrap_err()));

    let mut short_kem = sealed.clone();
    short_kem.kem_ct.pop();
    assert!(is_structural(&open_ml_kem_768(&kp, &short_kem, CTX, AAD).unwrap_err()));

    let mut wrong_nonce_len = sealed.clone();
    wrong_nonce_len.suite = AeadSuite::ChaCha20Poly1305; // 12-byte suite, 24-byte nonce
    assert!(is_structural(&open_ml_kem_768(&kp, &wrong_nonce_len, CTX, AAD).unwrap_err()));

    let mut no_tag = sealed.clone();
    no_tag.ciphertext.truncate(15);
    assert!(is_structural(&open_ml_kem_768(&kp, &no_tag, CTX, AAD).unwrap_err()));
}

#[test]
fn sealing_to_a_key_of_the_wrong_algorithm_is_refused() {
    let kp = MlKem768Keypair::generate(&mut OsRng).unwrap();
    let mut pk: KemPublicKey = kp.public_key();
    pk.algorithm = KemAlgorithm::MlKem512;
    let err = seal_ml_kem_768(&mut OsRng, &pk, CTX, AAD, MSG).unwrap_err();
    assert!(matches!(err, KemError::InvalidKey(_)), "got {err:?}");
}
