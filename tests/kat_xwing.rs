//! Known-Answer Tests for X-Wing (hybrid profile v2) against the official
//! draft test vectors.
//!
//! Vector provenance: `tests/vectors/xwing/xwing.json` (see
//! `tests/vectors/README.md` and `docs/hybrid-profiles.md` for full
//! provenance — draft version, upstream URL, commit).
//!
//! This whole file is a no-op when the `kat` feature is disabled.


use pqc_kem::fips203::{XWingKeypair, XWingPublicKey};
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

fn hex_to_array64(s: &str) -> [u8; 64] {
    let v = hex_to_bytes(s);
    v.try_into().unwrap_or_else(|v: Vec<u8>| panic!("expected 64-byte hex value, got {} bytes", v.len()))
}

#[derive(Deserialize)]
struct Vector {
    seed: String,
    eseed: String,
    ss: String,
    sk: String,
    pk: String,
    ct: String,
}

#[test]
fn xwing_keygen_encaps_decaps_kat() {
    const VECTORS_JSON: &str = include_str!("vectors/xwing/xwing.json");
    let vectors: Vec<Vector> = serde_json::from_str(VECTORS_JSON).expect("parse xwing.json");
    assert!(!vectors.is_empty(), "vector file must not be empty");

    for (i, v) in vectors.iter().enumerate() {
        let seed = hex_to_array32(&v.seed);
        let eseed = hex_to_array64(&v.eseed);
        let expected_ss = hex_to_bytes(&v.ss);
        let expected_sk = hex_to_bytes(&v.sk);
        let expected_pk = hex_to_bytes(&v.pk);
        let expected_ct = hex_to_bytes(&v.ct);

        // sk is just the 32-byte seed for X-Wing.
        assert_eq!(seed.to_vec(), expected_sk, "vector {i}: sk must equal seed");

        let keypair = XWingKeypair::from_seed(&seed);

        // keygen: seed -> pk
        let pk = keypair.public_key();
        assert_eq!(pk.to_bytes(), expected_pk, "vector {i}: public key mismatch");

        // encaps: eseed -> ct, ss
        let (ct, ss) = XWingKeypair::encapsulate_deterministic(&pk, &eseed)
            .unwrap_or_else(|e| panic!("vector {i}: encapsulate_deterministic failed: {e}"));
        assert_eq!(ct.to_bytes(), expected_ct, "vector {i}: ciphertext mismatch");
        assert_eq!(ss.bytes, expected_ss, "vector {i}: encaps shared secret mismatch");

        // decaps: ct -> ss (must match the encaps-side shared secret)
        let ss_dec = keypair.decapsulate(&ct)
            .unwrap_or_else(|e| panic!("vector {i}: decapsulate failed: {e}"));
        assert_eq!(ss_dec.bytes, expected_ss, "vector {i}: decaps shared secret mismatch");

        // Also confirm from_bytes/to_bytes round-trip on the wire types.
        let pk_restored = XWingPublicKey::from_bytes(&expected_pk).expect("pk from_bytes");
        assert_eq!(pk_restored, pk, "vector {i}: pk from_bytes/to_bytes round-trip");
    }

    println!("X-Wing KAT: {} vectors checked", vectors.len());
}
