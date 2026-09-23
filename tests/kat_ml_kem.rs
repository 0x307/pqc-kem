//! Known-Answer Tests (KATs) for ML-KEM-512/768/1024 against NIST ACVP
//! vectors, exercised through this crate's `kat`-gated deterministic entry
//! points (`from_seed_halves`, `encapsulate_deterministic`,
//! `from_expanded_decapsulation_key_bytes`,
//! `to_expanded_decapsulation_key_bytes`).
//!
//! Vector provenance: `tests/vectors/README.md`.
//!
//! This whole file is a no-op when the `kat` feature is disabled — `cargo
//! test` (without `--features kat`) still passes, since nothing here is
//! compiled at all in that configuration.


use pqc_kem::fips203::{MlKem1024Keypair, MlKem512Keypair, MlKem768Keypair};
use pqc_kem::types::{KemAlgorithm, KemCiphertext, KemPublicKey};
use serde::Deserialize;

// ── Hex helpers ────────────────────────────────────────────────────────────────

fn hex_to_bytes(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "hex string must have an even number of digits: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|e| panic!("invalid hex byte in vector file at offset {i}: {e}")))
        .collect()
}

fn hex_to_array32(s: &str) -> [u8; 32] {
    let v = hex_to_bytes(s);
    v.try_into().unwrap_or_else(|v: Vec<u8>| panic!("expected 32-byte hex value, got {} bytes", v.len()))
}

// ── Vector file schemas ────────────────────────────────────────────────────────
//
// These mirror the compact JSON format documented in
// `tests/vectors/README.md`. Unknown/extra JSON fields (e.g. `source`,
// `note`, `algorithm`) are intentionally not modeled here — serde ignores
// them by default.

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeygenFile {
    cases: Vec<KeygenCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeygenCase {
    tc_id: u32,
    d: String,
    z: String,
    ek: String,
    dk: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncapFile {
    cases: Vec<EncapCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncapCase {
    tc_id: u32,
    ek: String,
    m: String,
    c: String,
    k: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecapFile {
    dk: String,
    cases: Vec<DecapCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecapCase {
    tc_id: u32,
    c: String,
    k: String,
    reason: String,
}

// ── ML-KEM-512 ───────────────────────────────────────────────────────────────

mod ml_kem_512 {
    use super::*;

    const KEYGEN_JSON: &str = include_str!("vectors/ml-kem/512/keygen.json");
    const ENCAP_JSON: &str = include_str!("vectors/ml-kem/512/encap.json");
    const DECAP_JSON: &str = include_str!("vectors/ml-kem/512/decap.json");

    #[test]
    fn keygen_kat() {
        let file: KeygenFile = serde_json::from_str(KEYGEN_JSON).expect("parse keygen.json");
        assert!(!file.cases.is_empty());
        for case in &file.cases {
            let d = hex_to_array32(&case.d);
            let z = hex_to_array32(&case.z);
            let expected_ek = hex_to_bytes(&case.ek);
            let expected_dk = hex_to_bytes(&case.dk);

            let kp = MlKem512Keypair::from_seed_halves(&d, &z);
            assert_eq!(kp.public_key().bytes, expected_ek, "ML-KEM-512 keyGen tcId={}: ek mismatch", case.tc_id);
            assert_eq!(kp.to_expanded_decapsulation_key_bytes(), expected_dk, "ML-KEM-512 keyGen tcId={}: dk mismatch", case.tc_id);
        }
        println!("ML-KEM-512 keyGen KAT: {} cases checked", file.cases.len());
    }

    #[test]
    fn encap_kat() {
        let file: EncapFile = serde_json::from_str(ENCAP_JSON).expect("parse encap.json");
        assert!(!file.cases.is_empty());
        for case in &file.cases {
            let pk = KemPublicKey::new(KemAlgorithm::MlKem512, hex_to_bytes(&case.ek));
            let m = hex_to_array32(&case.m);
            let expected_c = hex_to_bytes(&case.c);
            let expected_k = hex_to_bytes(&case.k);

            let (ct, ss) = MlKem512Keypair::encapsulate_deterministic(&pk, &m)
                .unwrap_or_else(|e| panic!("ML-KEM-512 encap tcId={}: encapsulate_deterministic failed: {e}", case.tc_id));
            assert_eq!(ct.bytes, expected_c, "ML-KEM-512 encap tcId={}: ciphertext mismatch", case.tc_id);
            assert_eq!(ss.bytes, expected_k, "ML-KEM-512 encap tcId={}: shared secret mismatch", case.tc_id);
        }
        println!("ML-KEM-512 encap KAT: {} cases checked", file.cases.len());
    }

    #[test]
    fn decap_kat_including_implicit_rejection() {
        let file: DecapFile = serde_json::from_str(DECAP_JSON).expect("parse decap.json");
        assert!(!file.cases.is_empty());
        let dk_bytes = hex_to_bytes(&file.dk);
        let kp = MlKem512Keypair::from_expanded_decapsulation_key_bytes(&dk_bytes)
            .expect("ML-KEM-512 decap: failed to load expanded decapsulation key");

        let mut valid = 0;
        let mut rejected = 0;
        for case in &file.cases {
            let ct = KemCiphertext::new(KemAlgorithm::MlKem512, hex_to_bytes(&case.c));
            let expected_k = hex_to_bytes(&case.k);
            let ss = kp.decapsulate(&ct)
                .unwrap_or_else(|e| panic!("ML-KEM-512 decap tcId={}: decapsulate() returned Err (must never error on a length-correct ciphertext, even a malformed one — implicit rejection): {e}", case.tc_id));
            assert_eq!(ss.bytes, expected_k, "ML-KEM-512 decap tcId={} (reason: {}): shared secret mismatch", case.tc_id, case.reason);
            if case.reason == "modified ciphertext" { rejected += 1; } else { valid += 1; }
        }
        assert!(rejected > 0, "ML-KEM-512 decap KAT: expected at least one implicit-rejection ('modified ciphertext') case");
        println!("ML-KEM-512 decap KAT: {valid} valid + {rejected} implicit-rejection cases checked");
    }

    #[test]
    fn malformed_inputs_are_rejected_not_panicked() {
        // Wrong-length public key: encapsulate_deterministic must return Err.
        let bad_pk = KemPublicKey::new(KemAlgorithm::MlKem512, vec![0u8; 10]);
        let m = [0u8; 32];
        assert!(MlKem512Keypair::encapsulate_deterministic(&bad_pk, &m).is_err());

        // Wrong-length expanded decapsulation key: must return Err, not panic.
        assert!(MlKem512Keypair::from_expanded_decapsulation_key_bytes(&[0u8; 10]).is_err());

        // Wrong-algorithm public key tag: must be rejected before any crypto.
        let wrong_alg_pk = KemPublicKey::new(KemAlgorithm::MlKem768, vec![0u8; 800]);
        assert!(MlKem512Keypair::encapsulate_deterministic(&wrong_alg_pk, &m).is_err());
    }
}

// ── ML-KEM-768 ───────────────────────────────────────────────────────────────

mod ml_kem_768 {
    use super::*;

    const KEYGEN_JSON: &str = include_str!("vectors/ml-kem/768/keygen.json");
    const ENCAP_JSON: &str = include_str!("vectors/ml-kem/768/encap.json");
    const DECAP_JSON: &str = include_str!("vectors/ml-kem/768/decap.json");

    #[test]
    fn keygen_kat() {
        let file: KeygenFile = serde_json::from_str(KEYGEN_JSON).expect("parse keygen.json");
        assert!(!file.cases.is_empty());
        for case in &file.cases {
            let d = hex_to_array32(&case.d);
            let z = hex_to_array32(&case.z);
            let expected_ek = hex_to_bytes(&case.ek);
            let expected_dk = hex_to_bytes(&case.dk);

            let kp = MlKem768Keypair::from_seed_halves(&d, &z);
            assert_eq!(kp.public_key().bytes, expected_ek, "ML-KEM-768 keyGen tcId={}: ek mismatch", case.tc_id);
            assert_eq!(kp.to_expanded_decapsulation_key_bytes(), expected_dk, "ML-KEM-768 keyGen tcId={}: dk mismatch", case.tc_id);
        }
        println!("ML-KEM-768 keyGen KAT: {} cases checked", file.cases.len());
    }

    #[test]
    fn encap_kat() {
        let file: EncapFile = serde_json::from_str(ENCAP_JSON).expect("parse encap.json");
        assert!(!file.cases.is_empty());
        for case in &file.cases {
            let pk = KemPublicKey::new(KemAlgorithm::MlKem768, hex_to_bytes(&case.ek));
            let m = hex_to_array32(&case.m);
            let expected_c = hex_to_bytes(&case.c);
            let expected_k = hex_to_bytes(&case.k);

            let (ct, ss) = MlKem768Keypair::encapsulate_deterministic(&pk, &m)
                .unwrap_or_else(|e| panic!("ML-KEM-768 encap tcId={}: encapsulate_deterministic failed: {e}", case.tc_id));
            assert_eq!(ct.bytes, expected_c, "ML-KEM-768 encap tcId={}: ciphertext mismatch", case.tc_id);
            assert_eq!(ss.bytes, expected_k, "ML-KEM-768 encap tcId={}: shared secret mismatch", case.tc_id);
        }
        println!("ML-KEM-768 encap KAT: {} cases checked", file.cases.len());
    }

    #[test]
    fn decap_kat_including_implicit_rejection() {
        let file: DecapFile = serde_json::from_str(DECAP_JSON).expect("parse decap.json");
        assert!(!file.cases.is_empty());
        let dk_bytes = hex_to_bytes(&file.dk);
        let kp = MlKem768Keypair::from_expanded_decapsulation_key_bytes(&dk_bytes)
            .expect("ML-KEM-768 decap: failed to load expanded decapsulation key");

        let mut valid = 0;
        let mut rejected = 0;
        for case in &file.cases {
            let ct = KemCiphertext::new(KemAlgorithm::MlKem768, hex_to_bytes(&case.c));
            let expected_k = hex_to_bytes(&case.k);
            let ss = kp.decapsulate(&ct)
                .unwrap_or_else(|e| panic!("ML-KEM-768 decap tcId={}: decapsulate() returned Err (must never error on a length-correct ciphertext, even a malformed one — implicit rejection): {e}", case.tc_id));
            assert_eq!(ss.bytes, expected_k, "ML-KEM-768 decap tcId={} (reason: {}): shared secret mismatch", case.tc_id, case.reason);
            if case.reason == "modified ciphertext" { rejected += 1; } else { valid += 1; }
        }
        assert!(rejected > 0, "ML-KEM-768 decap KAT: expected at least one implicit-rejection ('modified ciphertext') case");
        println!("ML-KEM-768 decap KAT: {valid} valid + {rejected} implicit-rejection cases checked");
    }

    #[test]
    fn malformed_inputs_are_rejected_not_panicked() {
        let bad_pk = KemPublicKey::new(KemAlgorithm::MlKem768, vec![0u8; 10]);
        let m = [0u8; 32];
        assert!(MlKem768Keypair::encapsulate_deterministic(&bad_pk, &m).is_err());
        assert!(MlKem768Keypair::from_expanded_decapsulation_key_bytes(&[0u8; 10]).is_err());
        let wrong_alg_pk = KemPublicKey::new(KemAlgorithm::MlKem512, vec![0u8; 1184]);
        assert!(MlKem768Keypair::encapsulate_deterministic(&wrong_alg_pk, &m).is_err());
    }
}

// ── ML-KEM-1024 ──────────────────────────────────────────────────────────────

mod ml_kem_1024 {
    use super::*;

    const KEYGEN_JSON: &str = include_str!("vectors/ml-kem/1024/keygen.json");
    const ENCAP_JSON: &str = include_str!("vectors/ml-kem/1024/encap.json");
    const DECAP_JSON: &str = include_str!("vectors/ml-kem/1024/decap.json");

    #[test]
    fn keygen_kat() {
        let file: KeygenFile = serde_json::from_str(KEYGEN_JSON).expect("parse keygen.json");
        assert!(!file.cases.is_empty());
        for case in &file.cases {
            let d = hex_to_array32(&case.d);
            let z = hex_to_array32(&case.z);
            let expected_ek = hex_to_bytes(&case.ek);
            let expected_dk = hex_to_bytes(&case.dk);

            let kp = MlKem1024Keypair::from_seed_halves(&d, &z);
            assert_eq!(kp.public_key().bytes, expected_ek, "ML-KEM-1024 keyGen tcId={}: ek mismatch", case.tc_id);
            assert_eq!(kp.to_expanded_decapsulation_key_bytes(), expected_dk, "ML-KEM-1024 keyGen tcId={}: dk mismatch", case.tc_id);
        }
        println!("ML-KEM-1024 keyGen KAT: {} cases checked", file.cases.len());
    }

    #[test]
    fn encap_kat() {
        let file: EncapFile = serde_json::from_str(ENCAP_JSON).expect("parse encap.json");
        assert!(!file.cases.is_empty());
        for case in &file.cases {
            let pk = KemPublicKey::new(KemAlgorithm::MlKem1024, hex_to_bytes(&case.ek));
            let m = hex_to_array32(&case.m);
            let expected_c = hex_to_bytes(&case.c);
            let expected_k = hex_to_bytes(&case.k);

            let (ct, ss) = MlKem1024Keypair::encapsulate_deterministic(&pk, &m)
                .unwrap_or_else(|e| panic!("ML-KEM-1024 encap tcId={}: encapsulate_deterministic failed: {e}", case.tc_id));
            assert_eq!(ct.bytes, expected_c, "ML-KEM-1024 encap tcId={}: ciphertext mismatch", case.tc_id);
            assert_eq!(ss.bytes, expected_k, "ML-KEM-1024 encap tcId={}: shared secret mismatch", case.tc_id);
        }
        println!("ML-KEM-1024 encap KAT: {} cases checked", file.cases.len());
    }

    #[test]
    fn decap_kat_including_implicit_rejection() {
        let file: DecapFile = serde_json::from_str(DECAP_JSON).expect("parse decap.json");
        assert!(!file.cases.is_empty());
        let dk_bytes = hex_to_bytes(&file.dk);
        let kp = MlKem1024Keypair::from_expanded_decapsulation_key_bytes(&dk_bytes)
            .expect("ML-KEM-1024 decap: failed to load expanded decapsulation key");

        let mut valid = 0;
        let mut rejected = 0;
        for case in &file.cases {
            let ct = KemCiphertext::new(KemAlgorithm::MlKem1024, hex_to_bytes(&case.c));
            let expected_k = hex_to_bytes(&case.k);
            let ss = kp.decapsulate(&ct)
                .unwrap_or_else(|e| panic!("ML-KEM-1024 decap tcId={}: decapsulate() returned Err (must never error on a length-correct ciphertext, even a malformed one — implicit rejection): {e}", case.tc_id));
            assert_eq!(ss.bytes, expected_k, "ML-KEM-1024 decap tcId={} (reason: {}): shared secret mismatch", case.tc_id, case.reason);
            if case.reason == "modified ciphertext" { rejected += 1; } else { valid += 1; }
        }
        assert!(rejected > 0, "ML-KEM-1024 decap KAT: expected at least one implicit-rejection ('modified ciphertext') case");
        println!("ML-KEM-1024 decap KAT: {valid} valid + {rejected} implicit-rejection cases checked");
    }

    #[test]
    fn malformed_inputs_are_rejected_not_panicked() {
        let bad_pk = KemPublicKey::new(KemAlgorithm::MlKem1024, vec![0u8; 10]);
        let m = [0u8; 32];
        assert!(MlKem1024Keypair::encapsulate_deterministic(&bad_pk, &m).is_err());
        assert!(MlKem1024Keypair::from_expanded_decapsulation_key_bytes(&[0u8; 10]).is_err());
        let wrong_alg_pk = KemPublicKey::new(KemAlgorithm::MlKem512, vec![0u8; 1568]);
        assert!(MlKem1024Keypair::encapsulate_deterministic(&wrong_alg_pk, &m).is_err());
    }
}
