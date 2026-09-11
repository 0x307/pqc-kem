//! Known-Answer Tests (KATs) for X25519 against RFC 7748 §5.2/§6.1 vectors,
//! exercised through this crate's `kat`-gated
//! `pqc_kem::fips203::hybrid::x25519_kat` helper (a thin wrapper over
//! `x25519_dalek::x25519`, exposed only for this test — see its rustdoc for
//! why this crate has no general-purpose public X25519 API).
//!
//! Vector provenance: `tests/vectors/README.md`.
//!
//! This whole file is a no-op when the `kat` feature is disabled — `cargo
//! test` (without `--features kat`) still passes, since nothing here is
//! compiled at all in that configuration.

#![cfg(feature = "kat")]

use pqc_kem::fips203::hybrid::x25519_kat;
use serde::Deserialize;

const RFC7748_JSON: &str = include_str!("vectors/x25519/rfc7748.json");

fn hex_to_array32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "expected 32-byte (64 hex char) value, got {} chars", s.len());
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|e| panic!("invalid hex byte at offset {i}: {e}"));
    }
    out
}

#[derive(Deserialize)]
struct Rfc7748File {
    x25519_scalar_mult: Vec<ScalarMultCase>,
    x25519_iterated: IteratedBlock,
    x25519_diffie_hellman: DhCase,
}

#[derive(Deserialize)]
struct ScalarMultCase {
    id: String,
    scalar: String,
    u: String,
    output: String,
}

#[derive(Deserialize)]
struct IteratedBlock {
    initial_k_and_u: String,
    cases: Vec<IteratedCase>,
}

#[derive(Deserialize)]
struct IteratedCase {
    iterations: u64,
    output: String,
    #[serde(default)]
    skip_by_default: bool,
}

#[derive(Deserialize)]
struct DhCase {
    alice_private_key: String,
    alice_public_key: String,
    bob_private_key: String,
    bob_public_key: String,
    shared_secret: String,
}

fn load() -> Rfc7748File {
    serde_json::from_str(RFC7748_JSON).expect("parse tests/vectors/x25519/rfc7748.json")
}

/// RFC 7748 §5.2 — the two `X25519(scalar, u) = output` scalar-multiplication vectors.
#[test]
fn scalar_mult_vectors() {
    let file = load();
    assert_eq!(file.x25519_scalar_mult.len(), 2, "expected exactly 2 RFC 7748 §5.2 scalar-mult vectors");
    for case in &file.x25519_scalar_mult {
        let scalar = hex_to_array32(&case.scalar);
        let u = hex_to_array32(&case.u);
        let expected = hex_to_array32(&case.output);
        let got = x25519_kat(scalar, u);
        assert_eq!(got, expected, "RFC 7748 §5.2 vector {}: X25519(scalar, u) mismatch", case.id);
    }
}

/// RFC 7748 §5.2 — the iterated self-composition vectors (k = u = 9, apply
/// X25519 repeatedly). Runs the 1 and 1,000 iteration cases; the
/// 1,000,000-iteration case is `skip_by_default` in the vector file and is
/// only run by [`iterated_vectors_million_ignored`] under `--ignored`.
#[test]
fn iterated_vectors() {
    let file = load();
    let initial = hex_to_array32(&file.x25519_iterated.initial_k_and_u);

    for case in &file.x25519_iterated.cases {
        if case.skip_by_default {
            continue;
        }
        let expected = hex_to_array32(&case.output);
        let got = run_iterations(initial, case.iterations);
        assert_eq!(got, expected, "RFC 7748 §5.2 iterated vector ({} iterations) mismatch", case.iterations);
    }
}

/// The optional 1,000,000-iteration RFC 7748 §5.2 vector. Excluded from the
/// default `cargo test --features kat` run (1,000,000 sequential X25519
/// scalar multiplications is slow); run explicitly with
/// `cargo test --features kat -- --ignored iterated_vectors_million_ignored`.
/// Matches `x25519-dalek`'s own convention of gating this vector behind
/// `#[ignore]` in its `tests/x25519_tests.rs`.
#[test]
#[ignore]
fn iterated_vectors_million_ignored() {
    let file = load();
    let initial = hex_to_array32(&file.x25519_iterated.initial_k_and_u);
    let million = file.x25519_iterated.cases.iter()
        .find(|c| c.iterations == 1_000_000)
        .expect("expected a 1,000,000-iteration case in the vector file");
    let expected = hex_to_array32(&million.output);
    let got = run_iterations(initial, million.iterations);
    assert_eq!(got, expected, "RFC 7748 §5.2 iterated vector (1,000,000 iterations) mismatch");
}

fn run_iterations(initial: [u8; 32], iterations: u64) -> [u8; 32] {
    let mut k = initial;
    let mut u = initial;
    for _ in 0..iterations {
        let next_k = x25519_kat(k, u);
        u = k;
        k = next_k;
    }
    k
}

/// RFC 7748 §6.1 — the worked Curve25519 Diffie-Hellman example (Alice/Bob).
#[test]
fn diffie_hellman_vector() {
    let file = load();
    let dh = &file.x25519_diffie_hellman;

    let mut basepoint = [0u8; 32];
    basepoint[0] = 9;

    let alice_priv = hex_to_array32(&dh.alice_private_key);
    let bob_priv = hex_to_array32(&dh.bob_private_key);
    let expected_alice_pub = hex_to_array32(&dh.alice_public_key);
    let expected_bob_pub = hex_to_array32(&dh.bob_public_key);
    let expected_shared = hex_to_array32(&dh.shared_secret);

    let alice_pub = x25519_kat(alice_priv, basepoint);
    let bob_pub = x25519_kat(bob_priv, basepoint);
    assert_eq!(alice_pub, expected_alice_pub, "RFC 7748 §6.1: Alice's public key mismatch");
    assert_eq!(bob_pub, expected_bob_pub, "RFC 7748 §6.1: Bob's public key mismatch");

    let shared_from_alice = x25519_kat(alice_priv, bob_pub);
    let shared_from_bob = x25519_kat(bob_priv, alice_pub);
    assert_eq!(shared_from_alice, expected_shared, "RFC 7748 §6.1: Alice-computed shared secret mismatch");
    assert_eq!(shared_from_bob, expected_shared, "RFC 7748 §6.1: Bob-computed shared secret mismatch");
    assert_eq!(shared_from_alice, shared_from_bob, "RFC 7748 §6.1: Alice and Bob must derive the same shared secret");
}
