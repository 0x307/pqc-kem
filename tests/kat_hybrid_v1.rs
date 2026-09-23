//! Known-Answer Tests for hybrid profile v1
//! (`HybridKem-X25519-MLKEM768-v1`, `fips203::HybridKemKeypair`).
//!
//! These vectors are generated *by this crate itself* (there is no
//! independent second implementation of the v1 combiner — see
//! `tests/vectors/README.md`) via the `kat`-gated deterministic entry
//! points (`HybridKemKeypair::from_secrets`/`encapsulate_deterministic`),
//! then frozen here so future refactors of `hybrid.rs` can't silently
//! change the v1 wire/KDF behavior without this test noticing.
//!
//! To partially satisfy K-5's "cross-check against a second
//! implementation" ask despite there being no external implementation of
//! this exact combiner, [`independent_recomputation_of_first_vector`]
//! reimplements the v1 combiner from scratch using `x25519_dalek`,
//! `ml_kem`, and `hkdf`/`sha2` directly — never calling
//! `HybridKemKeypair::{encapsulate, encapsulate_deterministic, decapsulate}`
//! — for the first vector, and checks the result against the same frozen
//! `pk`/`ct`/`ss` fields the main KAT loop below checks via the crate's own
//! API.
//!
//! This whole file is a no-op when the `kat` feature is disabled.

#![cfg(feature = "kat")]

use pqc_kem::fips203::HybridKemKeypair;
use serde::Deserialize;

fn hex_to_bytes(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "hex string must have an even number of digits: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|e| panic!("invalid hex byte at offset {i}: {e}")))
        .collect()
}

fn hex_to_array32(s: &str) -> [u8; 32] {
    let v = hex_to_bytes(s);
    v.try_into().unwrap_or_else(|v: Vec<u8>| panic!("expected 32-byte hex value, got {} bytes", v.len()))
}

#[derive(Deserialize)]
struct Vector {
    x25519_sk: String,
    d: String,
    z: String,
    eph_x25519_sk: String,
    m: String,
    pk: String,
    ct: String,
    ss: String,
}

const VECTORS_JSON: &str = include_str!("vectors/hybrid-v1/vectors.json");

fn load_vectors() -> Vec<Vector> {
    let vectors: Vec<Vector> = serde_json::from_str(VECTORS_JSON).expect("parse hybrid-v1/vectors.json");
    assert!(!vectors.is_empty(), "vector file must not be empty");
    vectors
}

/// Main KAT loop: exercises this crate's own `kat`-gated API
/// (`from_secrets`, `encapsulate_deterministic`, `decapsulate`) against
/// every frozen vector.
#[test]
fn hybrid_v1_keygen_encaps_decaps_kat() {
    let vectors = load_vectors();

    for (i, v) in vectors.iter().enumerate() {
        let x25519_sk = hex_to_array32(&v.x25519_sk);
        let d = hex_to_array32(&v.d);
        let z = hex_to_array32(&v.z);
        let eph_x25519_sk = hex_to_array32(&v.eph_x25519_sk);
        let m = hex_to_array32(&v.m);
        let expected_pk = hex_to_bytes(&v.pk);
        let expected_ct = hex_to_bytes(&v.ct);
        let expected_ss = hex_to_bytes(&v.ss);

        let keypair = HybridKemKeypair::from_secrets(&x25519_sk, &d, &z);
        let pk = keypair.public_key();
        assert_eq!(pk.to_bytes().unwrap(), expected_pk, "vector {i}: public key mismatch");

        let (ct, ss) = HybridKemKeypair::encapsulate_deterministic(&pk, &eph_x25519_sk, &m)
            .unwrap_or_else(|e| panic!("vector {i}: encapsulate_deterministic failed: {e}"));
        assert_eq!(ct.to_bytes().unwrap(), expected_ct, "vector {i}: ciphertext mismatch");
        assert_eq!(ss.bytes, expected_ss, "vector {i}: encaps shared secret mismatch");

        let ss_dec = keypair.decapsulate(&ct)
            .unwrap_or_else(|e| panic!("vector {i}: decapsulate failed: {e}"));
        assert_eq!(ss_dec.bytes, expected_ss, "vector {i}: decaps shared secret mismatch");

        // Secret-key byte round-trip (to_secret_bytes/from_secret_bytes, §2 API).
        let sk_bytes = keypair.to_secret_bytes().expect("to_secret_bytes").bytes.clone();
        assert_eq!(sk_bytes.len(), 96, "vector {i}: v1 secret key must be 96 bytes");
        let restored = HybridKemKeypair::from_secret_bytes(&sk_bytes).expect("from_secret_bytes");
        assert_eq!(restored.public_key(), pk, "vector {i}: from_secret_bytes round-trip must preserve public key");
    }

    println!("hybrid v1 KAT: {} vectors checked", vectors.len());
}

/// Independent, low-level recomputation of the **first** vector's
/// pk/ct/ss, using `x25519_dalek`, `ml_kem`, and `hkdf`/`sha2` directly —
/// never `HybridKemKeypair`. See `tests/vectors/README.md` for why this
/// exists (no second external implementation of the v1 combiner is
/// available).
#[test]
fn independent_recomputation_of_first_vector() {
    use hkdf::Hkdf;
    use ml_kem::{
        kem::KeyExport,
        EncapsulationKey, MlKem768, Seed,
    };
    use sha2::Sha256;

    let vectors = load_vectors();
    let v = &vectors[0];

    let x25519_sk = hex_to_array32(&v.x25519_sk);
    let d = hex_to_array32(&v.d);
    let z = hex_to_array32(&v.z);
    let eph_x25519_sk = hex_to_array32(&v.eph_x25519_sk);
    let m = hex_to_array32(&v.m);
    let expected_pk = hex_to_bytes(&v.pk);
    let expected_ct = hex_to_bytes(&v.ct);
    let expected_ss = hex_to_bytes(&v.ss);

    // ── Recompute the ML-KEM-768 public key from (d ‖ z) ──────────────────
    let mut seed_bytes = [0u8; 64];
    seed_bytes[..32].copy_from_slice(&d);
    seed_bytes[32..].copy_from_slice(&z);
    let seed: Seed = seed_bytes.into();
    let mlkem_dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed);
    let mlkem_ek = mlkem_dk.encapsulation_key().clone();
    let mlkem_pk_bytes = mlkem_ek.to_bytes();

    // ── Recompute the X25519 public key: x25519_dalek::x25519(sk, BASE) ──
    // RFC 7748 §5: X25519(k, u) with the standard base point u = 9.
    const X25519_BASE: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 9;
        b
    };
    let x25519_pk_bytes = x25519_dalek::x25519(x25519_sk, X25519_BASE);

    // ── Canonical v1 pk layout: x25519_pk(32) ‖ mlkem_ek(1184) ────────────
    let mut pk_bytes = Vec::with_capacity(1216);
    pk_bytes.extend_from_slice(&x25519_pk_bytes);
    pk_bytes.extend_from_slice(mlkem_pk_bytes.as_slice());
    assert_eq!(pk_bytes, expected_pk, "independent recomputation: public key mismatch");

    // ── Encapsulation, fully independent of HybridKemKeypair ─────────────
    // X25519: ephemeral public key + shared secret, via the raw
    // x25519_dalek::x25519() free function (not StaticSecret/EphemeralSecret).
    let ct_x_bytes = x25519_dalek::x25519(eph_x25519_sk, X25519_BASE);
    let x25519_ss_bytes = x25519_dalek::x25519(eph_x25519_sk, x25519_pk_bytes);

    // ML-KEM-768: deterministic encapsulation using ml_kem's own public API.
    let ek_key: ml_kem::kem::Key<EncapsulationKey<MlKem768>> = mlkem_pk_bytes.as_slice().try_into()
        .expect("ML-KEM-768 public key must be 1184 bytes");
    let ek = EncapsulationKey::<MlKem768>::new(&ek_key).expect("ML-KEM-768 key check");
    let m_arr: ml_kem::B32 = m.into();
    let (mlkem_ct, mlkem_ss) = ek.encapsulate_deterministic(&m_arr);

    let mut ct_bytes = Vec::with_capacity(1120);
    ct_bytes.extend_from_slice(&ct_x_bytes);
    ct_bytes.extend_from_slice(mlkem_ct.as_slice());
    assert_eq!(ct_bytes, expected_ct, "independent recomputation: ciphertext mismatch");

    // HKDF-SHA256(ikm = x25519_ss ‖ mlkem_ss, salt = None, info = "pqc-kem-hybrid-v1", L = 32)
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&x25519_ss_bytes);
    combined[32..].copy_from_slice(mlkem_ss.as_slice());

    let hkdf = Hkdf::<Sha256>::new(None, &combined);
    let mut shared_key = [0u8; 32];
    hkdf.expand(b"pqc-kem-hybrid-v1", &mut shared_key)
        .expect("HKDF expand failed");

    assert_eq!(shared_key.to_vec(), expected_ss, "independent recomputation: shared secret mismatch");
}
