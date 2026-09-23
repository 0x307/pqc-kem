//! A-Z1 (secret-material hardening) verification tests.
//!
//! Tests cover:
//! - (a) deprecated raw-byte accessors still work (behavior-compatible with 0.2.x)
//! - (b) new zeroizing accessors return the same bytes as the deprecated ones
//! - (c) round-trip encapsulate/decapsulate still works after keypair
//!   reconstruction from the new accessors' output (seed/secret)
//! - (d) compile-time assertions that the keypair/secret types implement
//!   `zeroize::ZeroizeOnDrop`
//!
//! Zeroization of memory itself cannot be reliably tested without `unsafe`
//! (reading freed/dropped memory) — this crate is `#![forbid(unsafe_code)]`
//! and that stays true here too. These tests instead verify: the types
//! carry the `ZeroizeOnDrop` marker (compile-time, via a generic bound
//! function that only compiles if the bound is satisfied), and the new
//! fallible/zeroizing accessors are behaviorally equivalent to the old
//! raw-byte ones they replace.

use pqc_kem::fips203::{HybridKemKeypair, MlKem512Keypair, MlKem768Keypair, MlKem1024Keypair};
use pqc_kem::types::{KemSecretKey, SharedSecret};
use rand::rngs::OsRng;

// ── (d) Compile-time ZeroizeOnDrop assertions ────────────────────────────────

/// Generic helper: only compiles if `T: zeroize::ZeroizeOnDrop`. Calling it
/// for a type is itself the test — if the bound isn't satisfied, this file
/// fails to compile, not just a single test to fail at runtime.
fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

#[test]
fn hybrid_kem_keypair_is_zeroize_on_drop() {
    assert_zeroize_on_drop::<HybridKemKeypair>();
}

#[test]
fn ml_kem_512_keypair_is_zeroize_on_drop() {
    assert_zeroize_on_drop::<MlKem512Keypair>();
}

#[test]
fn ml_kem_768_keypair_is_zeroize_on_drop() {
    assert_zeroize_on_drop::<MlKem768Keypair>();
}

#[test]
fn ml_kem_1024_keypair_is_zeroize_on_drop() {
    assert_zeroize_on_drop::<MlKem1024Keypair>();
}

#[test]
fn kem_secret_key_is_zeroize_on_drop() {
    assert_zeroize_on_drop::<KemSecretKey>();
}

#[test]
fn shared_secret_is_zeroize_on_drop() {
    assert_zeroize_on_drop::<SharedSecret>();
}

#[cfg(feature = "hqc")]
mod hqc_zeroize {
    use super::assert_zeroize_on_drop;
    use pqc_kem::hqc::{Hqc128Keypair, Hqc192Keypair, Hqc256Keypair};

    #[test]
    fn hqc_128_keypair_is_zeroize_on_drop() {
        assert_zeroize_on_drop::<Hqc128Keypair>();
    }

    #[test]
    fn hqc_192_keypair_is_zeroize_on_drop() {
        assert_zeroize_on_drop::<Hqc192Keypair>();
    }

    #[test]
    fn hqc_256_keypair_is_zeroize_on_drop() {
        assert_zeroize_on_drop::<Hqc256Keypair>();
    }
}

// ── (a) + (b) Hybrid: deprecated accessors vs. new zeroizing accessors ──────

#[test]
#[allow(deprecated)] // exercising the deprecated accessors is the point of this test
fn hybrid_deprecated_x25519_secret_bytes_still_works() {
    let keypair = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let raw = keypair.x25519_secret_bytes();
    assert_eq!(raw.len(), 32, "X25519 secret must be 32 bytes");
}

#[test]
#[allow(deprecated)] // exercising the deprecated accessors is the point of this test
fn hybrid_deprecated_mlkem_secret_bytes_still_works() {
    let keypair = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let raw = keypair.mlkem_secret_bytes();
    assert_eq!(raw.len(), 64, "ML-KEM-768 seed must be 64 bytes");
}

#[test]
#[allow(deprecated)]
fn hybrid_x25519_secret_matches_deprecated_x25519_secret_bytes() {
    let keypair = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");

    let new_accessor = keypair.x25519_secret();
    let old_accessor = keypair.x25519_secret_bytes();

    assert_eq!(
        new_accessor.bytes,
        old_accessor.to_vec(),
        "x25519_secret() must return the same bytes as the deprecated x25519_secret_bytes()"
    );
}

#[test]
#[allow(deprecated)]
fn hybrid_mlkem_seed_matches_deprecated_mlkem_secret_bytes() {
    let keypair = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");

    let new_accessor = keypair.mlkem_seed().expect("mlkem_seed failed");
    let old_accessor = keypair.mlkem_secret_bytes();

    assert_eq!(
        new_accessor.bytes,
        old_accessor,
        "mlkem_seed() must return the same bytes as the deprecated mlkem_secret_bytes()"
    );
}

#[test]
fn hybrid_x25519_secret_algorithm_tag() {
    use pqc_kem::types::KemAlgorithm;

    let keypair = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let secret = keypair.x25519_secret();
    assert_eq!(secret.algorithm, KemAlgorithm::HybridX25519MlKem768);
}

#[test]
fn hybrid_mlkem_seed_algorithm_tag() {
    use pqc_kem::types::KemAlgorithm;

    let keypair = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
    let secret = keypair.mlkem_seed().expect("mlkem_seed failed");
    assert_eq!(secret.algorithm, KemAlgorithm::MlKem768);
}

// ── (c) Round-trip after reconstruction from the new accessors ──────────────

#[test]
fn hybrid_roundtrip_after_reconstruction_from_new_accessors() {
    let keypair = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");

    let x25519_secret = keypair.x25519_secret();
    let mlkem_seed = keypair.mlkem_seed().expect("mlkem_seed failed");

    let restored = HybridKemKeypair::from_secret_key_bytes(&x25519_secret.bytes, &mlkem_seed.bytes)
        .expect("from_secret_key_bytes failed");

    assert_eq!(
        keypair.public_key(),
        restored.public_key(),
        "restored keypair must have the same public key"
    );

    let pub_key = keypair.public_key();
    let (ct, sender_ss) = HybridKemKeypair::encapsulate_to(&mut OsRng, &pub_key)
        .expect("encapsulate_to failed");
    let recovered = restored
        .decapsulate(&ct)
        .expect("decapsulate with restored keypair failed");

    assert_eq!(
        sender_ss.bytes, recovered.bytes,
        "restored keypair (from zeroizing accessors) must recover the same shared secret"
    );
}

// ── (a) + (b) + (c) ML-KEM-{512,768,1024}: secret_key() vs. try_secret_key() ─

macro_rules! ml_kem_try_secret_key_tests {
    ($mod_name:ident, $keypair:ty, $level_name:literal) => {
        mod $mod_name {
            use super::*;

            #[test]
            fn try_secret_key_matches_secret_key() {
                let keypair = <$keypair>::generate(&mut OsRng).expect("keygen failed");

                let via_secret_key = keypair.secret_key();
                let via_try_secret_key = keypair
                    .try_secret_key()
                    .expect(concat!($level_name, ": try_secret_key must succeed for a freshly generated key"));

                assert_eq!(
                    via_secret_key.bytes, via_try_secret_key.bytes,
                    "{}: secret_key() and try_secret_key() must return identical bytes",
                    $level_name
                );
                assert_eq!(via_secret_key.algorithm, via_try_secret_key.algorithm);
            }

            #[test]
            fn try_secret_key_is_64_bytes() {
                let keypair = <$keypair>::generate(&mut OsRng).expect("keygen failed");
                let sk = keypair.try_secret_key().expect("try_secret_key failed");
                assert_eq!(sk.bytes.len(), 64, "{}: seed must be 64 bytes", $level_name);
            }

            #[test]
            fn roundtrip_after_reconstruction_from_try_secret_key() {
                let keypair = <$keypair>::generate(&mut OsRng).expect("keygen failed");
                let sk = keypair.try_secret_key().expect("try_secret_key failed");

                let restored = <$keypair>::from_secret_key_bytes(&sk.bytes)
                    .expect("from_secret_key_bytes failed");

                assert_eq!(
                    keypair.public_key().bytes,
                    restored.public_key().bytes,
                    "{}: restored keypair must have the same public key",
                    $level_name
                );

                let pk = keypair.public_key();
                let (ct, sender_ss) = <$keypair>::encapsulate(&mut OsRng, &pk).expect("encapsulate failed");
                let recovered = restored
                    .decapsulate(&ct)
                    .expect("decapsulate with restored keypair failed");

                assert_eq!(
                    sender_ss.bytes, recovered.bytes,
                    "{}: restored keypair (from try_secret_key) must recover the same shared secret",
                    $level_name
                );
            }
        }
    };
}

ml_kem_try_secret_key_tests!(ml_kem_512_try_secret_key, MlKem512Keypair, "ML-KEM-512");
ml_kem_try_secret_key_tests!(ml_kem_768_try_secret_key, MlKem768Keypair, "ML-KEM-768");
ml_kem_try_secret_key_tests!(ml_kem_1024_try_secret_key, MlKem1024Keypair, "ML-KEM-1024");
