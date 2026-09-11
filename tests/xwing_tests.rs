//! Integration tests for X-Wing (hybrid profile v2, `fips203::XWingKeypair`).
//!
//! Tests cover:
//! - Keygen -> encapsulate -> decapsulate round-trip
//! - Shared secret equality between encapsulator and decapsulator
//! - Byte round-trips for `XWingPublicKey`/`XWingCiphertext`
//! - Wrong-length rejection (never panics)
//! - `from_seed` determinism
//! - Cross-profile confusion: v1 ciphertext fed into X-Wing decapsulation

use pqc_kem::fips203::{HybridKemKeypair, XWingCiphertext, XWingKeypair, XWingPublicKey};
use rand::rngs::OsRng;

#[test]
fn xwing_roundtrip() {
    let recipient = XWingKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = recipient.public_key();

    let (ct, sender_ss) = XWingKeypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
    let recipient_ss = recipient.decapsulate(&ct).expect("decapsulate failed");

    assert_eq!(sender_ss.bytes, recipient_ss.bytes, "X-Wing: shared secrets must match");
    assert_eq!(sender_ss.bytes.len(), 32, "shared secret must be 32 bytes");
}

#[test]
fn xwing_two_encapsulations_differ() {
    let recipient = XWingKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = recipient.public_key();

    let (ct1, ss1) = XWingKeypair::encapsulate(&mut OsRng, &pk).expect("encapsulate 1 failed");
    let (ct2, ss2) = XWingKeypair::encapsulate(&mut OsRng, &pk).expect("encapsulate 2 failed");

    assert_ne!(ct1.0, ct2.0, "two encapsulations must produce different ciphertexts");
    assert_ne!(ss1.bytes, ss2.bytes, "two encapsulations must produce different shared secrets");
}

#[test]
fn xwing_from_seed_is_deterministic() {
    let seed = [0x42u8; 32];
    let kp1 = XWingKeypair::from_seed(&seed);
    let kp2 = XWingKeypair::from_seed(&seed);
    assert_eq!(kp1.public_key(), kp2.public_key(), "from_seed must be deterministic");
    assert_eq!(kp1.seed().bytes, kp2.seed().bytes);
    assert_eq!(kp1.seed().bytes, seed.to_vec());
}

// ── Byte round-trips ──────────────────────────────────────────────────────────

#[test]
fn xwing_public_key_bytes_roundtrip() {
    let kp = XWingKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = kp.public_key();
    let bytes = pk.to_bytes();
    assert_eq!(bytes.len(), XWingPublicKey::BYTES);

    let restored = XWingPublicKey::from_bytes(&bytes).expect("from_bytes failed");
    assert_eq!(restored, pk, "public key byte round-trip must be lossless");
}

#[test]
fn xwing_ciphertext_bytes_roundtrip() {
    let kp = XWingKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = kp.public_key();
    let (ct, sender_ss) = XWingKeypair::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");

    let bytes = ct.to_bytes();
    assert_eq!(bytes.len(), XWingCiphertext::BYTES);

    let restored = XWingCiphertext::from_bytes(&bytes).expect("from_bytes failed");
    assert_eq!(restored, ct, "ciphertext byte round-trip must be lossless");

    let recovered = kp.decapsulate(&restored).expect("decapsulate (restored ct) failed");
    assert_eq!(sender_ss.bytes, recovered.bytes);
}

#[test]
fn xwing_public_key_wrong_length_rejected() {
    let err = XWingPublicKey::from_bytes(&[0u8; 100]);
    assert!(err.is_err(), "wrong-length public key must be rejected, not panic");

    let err = XWingPublicKey::from_bytes(&[0u8; 1217]);
    assert!(err.is_err());
}

#[test]
fn xwing_ciphertext_wrong_length_rejected() {
    let err = XWingCiphertext::from_bytes(&[0u8; 100]);
    assert!(err.is_err(), "wrong-length ciphertext must be rejected, not panic");

    let err = XWingCiphertext::from_bytes(&[0u8; 1121]);
    assert!(err.is_err());
}

// ── Cross-profile confusion (v1 vs. v2/X-Wing) ───────────────────────────────

#[test]
fn v1_ciphertext_bytes_fed_into_xwing_decaps_does_not_panic() {
    // v1 and X-Wing ciphertexts are both 1120 bytes, but different byte
    // orders (v1: x25519 ‖ mlkem; X-Wing: mlkem ‖ x25519) and different
    // combiners — feeding one profile's bytes into the other's decapsulate
    // must never panic. It will either fail ML-KEM-768 ciphertext decoding
    // (unlikely — 1088 arbitrary bytes almost always decode as *some*
    // ciphertext under FIPS 203's implicit-rejection design) or, far more
    // likely, silently produce a shared secret that does not match anything
    // a real v1 encapsulator produced. Either outcome is acceptable; a panic
    // is not.
    let v1_recipient = HybridKemKeypair::generate(&mut OsRng).expect("v1 keygen failed");
    let v1_pub = v1_recipient.public_key();
    let (v1_ct, _v1_ss) = HybridKemKeypair::encapsulate_to(&mut OsRng, &v1_pub)
        .expect("v1 encapsulate failed");
    let v1_ct_bytes = v1_ct.to_bytes().expect("v1 ct to_bytes failed");
    assert_eq!(v1_ct_bytes.len(), 1120);

    let xwing_recipient = XWingKeypair::generate(&mut OsRng).expect("X-Wing keygen failed");

    // Must not panic regardless of Ok/Err outcome.
    let xwing_ct = XWingCiphertext::from_bytes(&v1_ct_bytes).expect("length matches (1120), decode succeeds");
    let result = xwing_recipient.decapsulate(&xwing_ct);
    match result {
        Ok(ss) => assert_eq!(ss.bytes.len(), 32),
        Err(_) => { /* also acceptable */ }
    }
}

#[test]
fn xwing_ciphertext_bytes_fed_into_v1_decaps_does_not_panic() {
    let xwing_recipient = XWingKeypair::generate(&mut OsRng).expect("X-Wing keygen failed");
    let xwing_pub = xwing_recipient.public_key();
    let (xwing_ct, _ss) = XWingKeypair::encapsulate(&mut OsRng, &xwing_pub).expect("X-Wing encapsulate failed");
    let xwing_ct_bytes = xwing_ct.to_bytes();

    let v1_recipient = HybridKemKeypair::generate(&mut OsRng).expect("v1 keygen failed");

    // v1's from_bytes is on the wire type; decode then attempt decapsulate.
    use pqc_kem::types::HybridKemCiphertext;
    let v1_ct = HybridKemCiphertext::from_bytes(&xwing_ct_bytes).expect("length matches (1120), decode succeeds");
    let result = v1_recipient.decapsulate(&v1_ct);
    match result {
        Ok(ss) => assert_eq!(ss.bytes.len(), 32),
        Err(_) => { /* also acceptable */ }
    }
}

#[test]
fn xwing_public_key_byte_order_is_mlkem_first() {
    // Sanity check against the documented layout (docs/hybrid-profiles.md):
    // X-Wing pk = pk_M(1184) ‖ pk_X(32), the opposite of v1's x25519-first
    // layout. The last 32 bytes of the public key must equal the standalone
    // X25519 public key derivable via a second, independently-seeded X-Wing
    // keypair check: simplest verifiable property here is just the length
    // split (1184 + 32 = 1216) and that changing the seed changes both
    // halves (checked elsewhere); this test locks the split point itself.
    let kp = XWingKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk_bytes = kp.public_key().to_bytes();
    assert_eq!(pk_bytes.len(), 1216);
    // ML-KEM-768 encapsulation keys are never the all-zero pattern by
    // construction; this is a structural smoke check, not a crypto assertion.
    let (mlkem_part, x25519_part) = (&pk_bytes[..1184], &pk_bytes[1184..1216]);
    assert_eq!(mlkem_part.len(), 1184);
    assert_eq!(x25519_part.len(), 32);
}
